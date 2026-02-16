#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Universal Proxy Pro v4.2 - FIXED Tunnel (Empty Reply & Reset by Peer)
- SOCKS5 + HTTP/HTTPS on same port
- Tunnel dùng select synchronous (fix thread dead/empty reply)
- Fix curl (52) & (35) errors
- Tested in Codespaces-like env
"""

import logging
import select
import socket
import struct
import argparse
import atexit
import signal
import sys
import time
import base64
import threading
import subprocess
from socketserver import ThreadingMixIn, TCPServer, StreamRequestHandler
from urllib.parse import urlparse

# ====================== CONFIG ======================
SOCKS5_VER = 5
HTTP_FIRST_BYTES = {b'CONNECT'[0], b'GET'[0], b'POST'[0], b'PUT'[0], b'DELETE'[0],
                    b'HEAD'[0], b'OPTIONS'[0], b'TRACE'[0], b'PATCH'[0]}

MAX_CONNECTIONS      = 4000
CONNECTION_TIMEOUT   = 25
IDLE_TIMEOUT         = 180      # giây
RETRY_ATTEMPTS       = 5
BUFFER_SIZE          = 65536

GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
BLUE   = "\033[94m"
CYAN   = "\033[96m"
RESET  = "\033[0m"

logging.basicConfig(
    level=logging.INFO,
    format=f'{BLUE}%(asctime)s{RESET} │ %(message)s',
    datefmt='%H:%M:%S'
)

stats = {
    "start": time.time(),
    "total": 0,
    "current": 0,
    "socks5": 0,
    "http": 0,
    "auth_fail": 0,
    "bytes_up": 0,
    "bytes_down": 0
}

active_conns = set()           # {(ip, port, type), ...}
stats_lock   = threading.Lock()
active_lock  = threading.Lock()

# ====================== SERVER ======================
class ThreadedProxyServer(ThreadingMixIn, TCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, server_address, RequestHandlerClass, username="", password=""):
        self.username = username or ""
        self.password = password or ""
        self.auth_required = bool(username and password)
        super().__init__(server_address, RequestHandlerClass)

# ====================== HANDLER ======================
class ProxyHandler(StreamRequestHandler):

    def handle(self):
        client_ip, client_port = self.client_address
        conn_key = (client_ip, client_port)

        with stats_lock:
            if stats["current"] >= MAX_CONNECTIONS:
                logging.warning(f"{RED}Max connections reached from {client_ip}{RESET}")
                return
            stats["total"] += 1
            stats["current"] += 1

        try:
            peek = self.connection.recv(1, socket.MSG_PEEK)
            if not peek:
                return

            first_byte = peek[0]

            if first_byte == SOCKS5_VER:
                conn_type = "SOCKS5"
                with stats_lock: stats["socks5"] += 1
                with active_lock:
                    active_conns.add((client_ip, client_port, conn_type))
                logging.info(f"{GREEN}SOCKS5 → {client_ip}:{client_port}{RESET}")
                self.handle_socks5()

            elif first_byte in HTTP_FIRST_BYTES:
                conn_type = "HTTP"
                with stats_lock: stats["http"] += 1
                with active_lock:
                    active_conns.add((client_ip, client_port, conn_type))
                logging.info(f"{GREEN}HTTP   → {client_ip}:{client_port}{RESET}")
                self.handle_http()

            else:
                logging.warning(f"{YELLOW}Unknown protocol from {client_ip}:{client_port} (byte: {first_byte}){RESET}")

        except Exception as e:
            logging.error(f"Handler error {client_ip}:{client_port} → {e}")
        finally:
            with stats_lock:
                stats["current"] -= 1
            with active_lock:
                active_conns.discard((client_ip, client_port, "SOCKS5"))
                active_conns.discard((client_ip, client_port, "HTTP"))

    # ─── SOCKS5 ────────────────────────────────────────────────
    def handle_socks5(self):
        try:
            ver, nmethods = struct.unpack("!BB", self.connection.recv(2))
            if ver != SOCKS5_VER:
                return

            methods = self.connection.recv(nmethods)
            auth_method = 0x02 if self.server.auth_required else 0x00

            if auth_method not in methods:
                self.connection.sendall(b'\x05\xff')
                return

            self.connection.sendall(struct.pack("!BB", 5, auth_method))

            if self.server.auth_required and not self.socks5_auth():
                return

            ver, cmd, _, atyp = struct.unpack("!BBBB", self.connection.recv(4))
            if cmd != 0x01:  # chỉ hỗ trợ CONNECT
                self.socks5_reply(0x07)  # Command not supported
                return

            host, port = self.read_socks5_addr(atyp)
            if not host:
                self.socks5_reply(0x04)  # Host unreachable
                return

            remote = self.connect_remote(host, port)
            if not remote:
                self.socks5_reply(0x05)  # Connection refused
                return

            bind_ip, bind_port = remote.getsockname()[:2]
            self.socks5_reply(0x00, bind_ip, bind_port)

            self.tunnel(self.connection, remote)

        except Exception as e:
            logging.error(f"SOCKS5 error: {e}")

    def socks5_auth(self):
        try:
            ver = self.connection.recv(1)[0]
            if ver != 1:
                self.connection.sendall(b'\x01\xff')
                return False

            ulen = self.connection.recv(1)[0]
            user = self.connection.recv(ulen)
            plen = self.connection.recv(1)[0]
            pwd  = self.connection.recv(plen)

            ok = (user == self.server.username.encode()) and (pwd == self.server.password.encode())

            self.connection.sendall(b'\x01\x00' if ok else b'\x01\xff')

            if not ok:
                logging.warning(f"{RED}SOCKS5 auth fail from {self.client_address[0]} user={user!r}{RESET}")
                with stats_lock: stats["auth_fail"] += 1
            else:
                logging.info(f"{GREEN}SOCKS5 auth OK user={user.decode(errors='ignore')}{RESET}")

            return ok
        except:
            self.connection.sendall(b'\x01\xff')
            return False

    def read_socks5_addr(self, atyp):
        try:
            if atyp == 1:    # IPv4
                addr = socket.inet_ntop(socket.AF_INET, self.connection.recv(4))
            elif atyp == 3:  # Domain
                length = self.connection.recv(1)[0]
                addr = self.connection.recv(length).decode(errors='ignore')
            elif atyp == 4:  # IPv6
                addr = socket.inet_ntop(socket.AF_INET6, self.connection.recv(16))
            else:
                return None, 0

            port = struct.unpack("!H", self.connection.recv(2))[0]
            return addr, port
        except:
            return None, 0

    def socks5_reply(self, rep, addr="0.0.0.0", port=0):
        try:
            if ':' in addr and '.' not in addr:  # IPv6
                atyp = 4
                bin_addr = socket.inet_pton(socket.AF_INET6, addr)
            else:
                atyp = 1
                bin_addr = socket.inet_pton(socket.AF_INET, addr)

            reply = struct.pack("!BBBB", 5, rep, 0, atyp) + bin_addr + struct.pack("!H", port)
            self.connection.sendall(reply)
        except:
            pass

    # ─── HTTP / HTTPS ──────────────────────────────────────────
    def handle_http(self):
        try:
            line = self.rfile.readline(BUFFER_SIZE).decode(errors='ignore').strip()
            if not line:
                return

            method, url, _ = line.split(maxsplit=2)
            method = method.upper()

            headers = self.read_headers()

            if self.server.auth_required and not self.http_auth(headers):
                self.wfile.write(b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                                 b"Proxy-Authenticate: Basic realm=\"Proxy\"\r\n\r\n")
                self.wfile.flush()
                with stats_lock: stats["auth_fail"] += 1
                return

            if method == "CONNECT":
                host_port = url.split(':', 1)
                host = host_port[0]
                port = int(host_port[1]) if len(host_port) > 1 else 443
            else:
                parsed = urlparse(url if url.startswith(('http://', 'https://')) else 'http://' + url)
                host = parsed.hostname
                port = parsed.port or (443 if parsed.scheme == 'https' else 80)

            remote = self.connect_remote(host, port)
            if not remote:
                self.wfile.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                self.wfile.flush()
                return

            if method == "CONNECT":
                self.wfile.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                self.wfile.flush()
                self.tunnel(self.connection, remote)
            else:
                self.forward_http_request(method, url, headers, remote)
                self.forward_response(remote, self.connection)  # Cập nhật forward_response dùng select tương tự

        except Exception as e:
            logging.error(f"HTTP error: {e}")

    def read_headers(self):
        headers = {}
        while True:
            line = self.rfile.readline(BUFFER_SIZE).decode(errors='ignore').rstrip('\r\n')
            if not line:
                break
            if ':' in line:
                k, v = line.split(':', 1)
                headers[k.strip().lower()] = v.strip()
        return headers

    def http_auth(self, headers):
        auth = headers.get('proxy-authorization', '')
        if not auth.lower().startswith('basic '):
            return False
        try:
            cred = base64.b64decode(auth[6:]).decode('utf-8', errors='ignore')
            u, p = cred.split(':', 1)
            return u == self.server.username and p == self.server.password
        except:
            return False

    def forward_http_request(self, method, url, headers, remote):
        parsed = urlparse(url if url.startswith(('http://', 'https://')) else 'http://' + url)
        path = parsed.path
        if parsed.query:
            path += '?' + parsed.query
        if not path:
            path = '/'

        req_line = f"{method} {path} HTTP/1.1\r\n"
        for k, v in headers.items():
            if k not in ('proxy-authorization', 'proxy-connection', 'connection'):
                req_line += f"{k.title()}: {v}\r\n"

        req_line += "Connection: close\r\n\r\n"
        remote.sendall(req_line.encode())

    def forward_response(self, src, dst):
        # Sử dụng select tương tự tunnel cho non-CONNECT
        while True:
            r, _, e = select.select([src], [], [src], IDLE_TIMEOUT)
            if e or not r:
                break
            data = src.recv(BUFFER_SIZE)
            if not data:
                break
            dst.sendall(data)
            with stats_lock:
                stats["bytes_down"] += len(data)

    # ─── COMMON ────────────────────────────────────────────────
    def connect_remote(self, host, port):
        family = socket.AF_INET6 if ':' in host else socket.AF_INET
        for attempt in range(RETRY_ATTEMPTS):
            try:
                sock = socket.socket(family)
                sock.settimeout(CONNECTION_TIMEOUT)
                sock.connect((host, port))
                logging.info(f"{CYAN}→ {host}:{port} (try {attempt+1}){RESET}")
                return sock
            except Exception as e:
                if attempt == RETRY_ATTEMPTS - 1:
                    logging.warning(f"Connect failed {host}:{port} after {RETRY_ATTEMPTS} tries → {e}")
                time.sleep(min(0.5 * (attempt + 1), 4.0))  # backoff
        return None

    def tunnel(self, client, remote):
        socks = [client, remote]
        while True:
            r, _, e = select.select(socks, [], socks, IDLE_TIMEOUT)
            if e or not r:
                logging.debug("Tunnel break: error or idle timeout")
                break

            for s in r:
                data = s.recv(BUFFER_SIZE)
                if not data:
                    logging.debug("Tunnel EOF")
                    return

                if s == client:
                    remote.sendall(data)
                    with stats_lock:
                        stats["bytes_up"] += len(data)
                else:
                    client.sendall(data)
                    with stats_lock:
                        stats["bytes_down"] += len(data)

        try: client.close()
        except: pass
        try: remote.close()
        except: pass

# ====================== MONITOR & UTILS ======================
def format_bytes(b):
    for unit in ['B','KiB','MiB','GiB','TiB']:
        if b < 1024: return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} PiB"

def realtime_stats():
    while True:
        time.sleep(10)
        uptime = time.time() - stats["start"]
        h = int(uptime // 3600)
        m = int((uptime % 3600) // 60)
        s = int(uptime % 60)

        with active_lock:
            cur = len(active_conns)
            s5  = sum(1 for _,_,t in active_conns if t == "SOCKS5")
            http = cur - s5

        logging.info(
            f"{YELLOW}↑ {format_bytes(stats['bytes_up']):>9} ↓ {format_bytes(stats['bytes_down']):>9} │ "
            f"Active {cur:>4} (S5:{s5:>3} HTTP:{http:>3}) │ "
            f"Uptime {h:02d}:{m:02d}:{s:02d}{RESET}"
        )

def kill_port(port):
    try:
        subprocess.run(['fuser', '-k', f'{port}/tcp'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.8)
    except:
        pass

def shutdown():
    uptime = time.time() - stats["start"]
    h = int(uptime // 3600)
    m = int((uptime % 3600) // 60)
    s = int(uptime % 60)
    logging.info(
        f"{RED}Proxy STOPPED │ Uptime {h:02d}:{m:02d}:{s:02d} │ "
        f"Total conn {stats['total']} │ ↑ {format_bytes(stats['bytes_up'])} ↓ {format_bytes(stats['bytes_down'])}{RESET}"
    )
    sys.exit(0)

# ====================== MAIN ======================
def main():
    parser = argparse.ArgumentParser(description="Universal Proxy (SOCKS5 + HTTP) v4.2")
    parser.add_argument("-l", "--listen", default="0.0.0.0", help="Bind address")
    parser.add_argument("-p", "--port", type=int, default=1080)
    parser.add_argument("-u", "--username", help="Username for auth")
    parser.add_argument("-P", "--password", help="Password for auth")
    parser.add_argument("--force-kill", action="store_true", help="Kill port before start")
    args = parser.parse_args()

    if args.force_kill:
        kill_port(args.port)

    signal.signal(signal.SIGINT,  lambda sig, frame: shutdown())
    signal.signal(signal.SIGTERM, lambda sig, frame: shutdown())
    atexit.register(shutdown)

    server = ThreadedProxyServer(
        (args.listen, args.port),
        ProxyHandler,
        username=args.username,
        password=args.password
    )

    auth_str = f" (auth: {args.username}:{args.password})" if args.username else ""
    logging.info(f"{GREEN}Proxy v4.2 STARTED → {args.listen}:{args.port}{auth_str}{RESET}")

    threading.Thread(target=realtime_stats, daemon=True).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        shutdown()

if __name__ == "__main__":
    main()
