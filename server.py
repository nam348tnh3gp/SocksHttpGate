#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Universal Proxy Pro v3.5 - FIXED VERSION
SOCKS5 + HTTP/S trên cùng 1 port
Fixed: HTTP method detection, memory leaks, security issues
"""

import logging, select, socket, struct, argparse, atexit, signal, sys, time, base64, os, threading, subprocess
from socketserver import ThreadingMixIn, TCPServer, StreamRequestHandler
from urllib.parse import urlparse

# ====================== CONFIG ======================
SOCKS5_VER = 5
# FIX: Đầy đủ HTTP methods
HTTP_START = {b'CONNECT'[0], b'GET'[0], b'POST'[0], b'DELETE'[0], 
              b'HEAD'[0], b'OPTIONS'[0], b'TRACE'[0], b'PUT'[0], b'PATCH'[0]}
MAX_CONN = 3000
TIMEOUT = 20
RETRY = 5
BUFFER_SIZE = 65536

GREEN  = "\033[92m"; YELLOW = "\033[93m"; RED = "\033[91m"; BLUE = "\033[94m"; CYAN = "\033[96m"; RESET = "\033[0m"

logging.basicConfig(level=logging.INFO, format=f'{BLUE}%(asctime)s{RESET} │ %(message)s', datefmt='%H:%M:%S')
socket.setdefaulttimeout(TIMEOUT)

# Thống kê toàn cục
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

# Danh sách kết nối đang hoạt động
active_conns = []
stats_lock = threading.Lock()
active_lock = threading.Lock()

# ====================== SERVER ======================
class ThreadedServer(ThreadingMixIn, TCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, addr, handler, user="", pwd=""):
        self.username = user or ""
        self.password = pwd or ""
        self.auth_required = bool(user and pwd)
        super().__init__(addr, handler)

# ====================== HANDLER ======================
class ProxyHandler(StreamRequestHandler):
    def handle(self):
        client_ip, client_port = self.client_address
        conn_type = "UNKNOWN"

        with stats_lock:
            if stats["current"] >= MAX_CONN:
                logging.warning(f"{RED}Connection limit reached from {client_ip}:{client_port}{RESET}")
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
                    active_conns.append({
                        "ip": client_ip,
                        "port": client_port,
                        "type": conn_type,
                        "time": time.time()
                    })
                logging.info(f"{GREEN}New → {client_ip}:{client_port} [{conn_type}]{RESET}")
                self.handle_socks5()
            elif first_byte in HTTP_START:
                conn_type = "HTTP"
                with stats_lock: stats["http"] += 1
                with active_lock:
                    active_conns.append({
                        "ip": client_ip,
                        "port": client_port,
                        "type": conn_type,
                        "time": time.time()
                    })
                logging.info(f"{GREEN}New → {client_ip}:{client_port} [{conn_type}]{RESET}")
                self.handle_http()
            else:
                logging.warning(f"{YELLOW}Unknown protocol from {client_ip}:{client_port} - first byte: {first_byte}{RESET}")
                return

        except Exception as e:
            logging.error(f"Handle error: {e}")
        finally:
            with stats_lock:
                stats["current"] -= 1
            # Cleanup active connections
            with active_lock:
                current_time = time.time()
                active_conns[:] = [c for c in active_conns 
                                 if not (c["ip"] == client_ip and c["port"] == client_port) and 
                                    current_time - c["time"] < 3600]

    # ==================== SOCKS5 ====================
    def handle_socks5(self):
        try:
            data = self.connection.recv(2)
            ver, nmethods = struct.unpack("!BB", data)
            if ver != SOCKS5_VER:
                return

            methods = [self.connection.recv(1)[0] for _ in range(nmethods)]
            auth_method = 2 if self.server.auth_required else 0
            if auth_method not in methods:
                self.connection.sendall(struct.pack("!BB", SOCKS5_VER, 0xFF))
                return

            self.connection.sendall(struct.pack("!BB", SOCKS5_VER, auth_method))

            if self.server.auth_required and not self.auth_socks5():
                return

            data = self.connection.recv(4)
            _, cmd, _, atyp = struct.unpack("!BBBB", data)
            if cmd != 1:
                return

            host, port = self.read_addr(atyp)
            if not host:
                return

            remote = self.connect_to(host, port)
            if not remote:
                self.s5_reply(1, "0.0.0.0", 0)
                return

            bind_ip, bind_port = remote.getsockname()[:2]
            self.s5_reply(0, bind_ip, bind_port)
            self.tunnel(self.connection, remote)

        except Exception as e:
            logging.error(f"SOCKS5 error: {e}")

    def auth_socks5(self):
        try:
            ver = self.connection.recv(1)[0]
            if ver != 1:
                self.connection.sendall(b'\x01\xFF')
                return False
            ulen = self.connection.recv(1)[0]
            user = self.connection.recv(ulen)
            plen = self.connection.recv(1)[0]
            pwd = self.connection.recv(plen)
            expected_user = self.server.username.encode('utf-8')
            expected_pwd = self.server.password.encode('utf-8')
            ok = (user == expected_user and pwd == expected_pwd)
            self.connection.sendall(b'\x01\x00' if ok else b'\x01\xFF')
            if not ok:
                # FIX: Không log password
                logging.warning(f"{RED}Auth fail from {self.client_address[0]}: user={user!r}{RESET}")
                with stats_lock: stats["auth_fail"] += 1
            else:
                logging.info(f"{GREEN}Auth OK from {self.client_address[0]}: user={user!r}{RESET}")
            return ok
        except Exception as e:
            logging.error(f"Auth error: {e}")
            self.connection.sendall(b'\x01\xFF')
            return False

    def read_addr(self, atyp):
        try:
            if atyp == 1:
                addr = socket.inet_ntop(socket.AF_INET, self.connection.recv(4))
            elif atyp == 3:
                l = self.connection.recv(1)[0]
                addr = self.connection.recv(l).decode()
            elif atyp == 4:
                addr = socket.inet_ntop(socket.AF_INET6, self.connection.recv(16))
            else:
                return None, 0
            port = struct.unpack("!H", self.connection.recv(2))[0]
            return addr, port
        except:
            return None, 0

    def s5_reply(self, rep, addr, port):
        try:
            atyp = 4 if ':' in str(addr) and '.' not in str(addr) else 1
            bin_addr = socket.inet_pton(socket.AF_INET6 if atyp == 4 else socket.AF_INET, str(addr))
            self.connection.sendall(struct.pack("!BBBB", 5, rep, 0, atyp) + bin_addr + struct.pack("!H", port))
        except:
            pass

    # ==================== HTTP ====================
    def handle_http(self):
        try:
            line = self.rfile.readline(BUFFER_SIZE).decode(errors="ignore").strip()
            if not line: return
            parts = line.split()
            if len(parts) < 2: return
            method, url = parts[0].upper(), parts[1]

            headers = self.read_headers()
            if self.server.auth_required and not self.auth_http(headers):
                self.wfile.write(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Proxy\"\r\n\r\n")
                self.wfile.flush()
                with stats_lock: stats["auth_fail"] += 1
                return

            if method == "CONNECT":
                hp = url.split(':')
                host = hp[0]
                port = int(hp[1]) if len(hp) > 1 else 443
            else:
                parsed = urlparse(url if url.startswith('http') else 'http://' + url)
                host = parsed.hostname or headers.get('host', '').split(':')[0]
                port = parsed.port or (443 if parsed.scheme == 'https' else 80)

            remote = self.connect_to(host, port)
            if not remote:
                self.wfile.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                self.wfile.flush()
                return

            if method == "CONNECT":
                self.wfile.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                self.wfile.flush()
                self.tunnel(self.connection, remote)
            else:
                self.forward_http(method, url, headers, remote)
                self.forward_response(self.connection, remote)

        except Exception as e:
            logging.error(f"HTTP error: {e}")

    def read_headers(self):
        h = {}
        while True:
            line = self.rfile.readline(BUFFER_SIZE).decode(errors="ignore").strip()
            if not line: break
            if ':' in line:
                k, v = line.split(':', 1)
                h[k.strip().lower()] = v.strip()
        return h

    def auth_http(self, headers):
        auth = headers.get('proxy-authorization', '')
        if auth.lower().startswith('basic '):
            try:
                cred = base64.b64decode(auth[6:]).decode('utf-8')
                u, p = cred.split(':', 1)
                return u == self.server.username and p == self.server.password
            except:
                pass
        return False

    def forward_http(self, method, url, headers, remote):
        parsed = urlparse(url if url.startswith('http') else 'http://' + url)
        path = parsed.path + ('?' + parsed.query if parsed.query else '') or '/'
        req = f"{method} {path} HTTP/1.1\r\n"
        for k, v in headers.items():
            if k not in ['proxy-authorization', 'proxy-connection']:
                req += f"{k.capitalize()}: {v}\r\n"
        req += "Connection: close\r\n\r\n"
        self.send_with_retry(remote, req.encode())

    def forward_response(self, client, remote):
        try:
            while True:
                data = self.recv_with_retry(remote)
                if not data: 
                    break
                self.send_with_retry(client, data)
                with stats_lock: 
                    stats["bytes_down"] += len(data)
        except Exception as e:
            logging.error(f"Forward response error: {e}")
        finally:
            # FIX: Đảm bảo đóng socket
            try:
                remote.close()
            except:
                pass

    # ==================== COMMON ====================
    def connect_to(self, host, port):
        for attempt in range(RETRY):
            try:
                s = socket.create_connection((host, port), timeout=TIMEOUT)
                logging.info(f"{CYAN}Connected → {host}:{port} (attempt {attempt+1}){RESET}")
                return s
            except Exception as e:
                if attempt == RETRY - 1:  # Chỉ log lần cuối
                    logging.warning(f"Connect fail {host}:{port}: {e}")
                time.sleep(1)
        return None

    def tunnel(self, a, b):
        try:
            while True:
                r, _, _ = select.select([a, b], [], [], TIMEOUT)
                if not r: break
                for src in r:
                    data = self.recv_with_retry(src)
                    if not data: return
                    dst = b if src is a else a
                    self.send_with_retry(dst, data)
                    with stats_lock:
                        if src is a:
                            stats["bytes_up"] += len(data)
                        else:
                            stats["bytes_down"] += len(data)
        except Exception as e:
            logging.error(f"Tunnel error: {e}")

    def send_with_retry(self, sock, data):
        for attempt in range(RETRY):
            try:
                sock.sendall(data)
                return
            except Exception as e:
                logging.warning(f"Send fail: {e} (retry {attempt+1}/{RETRY})")
                time.sleep(0.5)
        raise Exception("Send failed after retries")

    def recv_with_retry(self, sock):
        for attempt in range(RETRY):
            try:
                return sock.recv(BUFFER_SIZE)
            except Exception as e:
                logging.warning(f"Recv fail: {e} (retry {attempt+1}/{RETRY})")
                time.sleep(0.5)
        raise Exception("Recv failed after retries")

# ====================== STATS LOG ======================
def format_bytes(b):
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if b < 1024: return f"{b:.1f}{unit}"
        b /= 1024
    return f"{b:.1f}PB"

def realtime_log():
    while True:
        time.sleep(8)
        uptime = int(time.time() - stats["start"])
        h, r = divmod(uptime, 3600)
        m, s = divmod(r, 60)

        # Đếm chính xác từ danh sách active
        with active_lock:
            current_s5 = sum(1 for c in active_conns if c["type"] == "SOCKS5")
            current_http = len(active_conns) - current_s5

        logging.info(
            f"{YELLOW}Uptime {h:02d}:{m:02d}:{s:02d} │ "
            f"Active {stats['current']:>4}/{stats['total']:<6} │ "
            f"S5:{current_s5:>3}  HTTP:{current_http:>3} │ "
            f"↑ {format_bytes(stats['bytes_up']):>8} ↓ {format_bytes(stats['bytes_down']):>8}{RESET}"
        )

def kill_port(port):
    subprocess.run(f"fuser -k {port}/tcp", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)

def goodbye():
    uptime = int(time.time() - stats["start"])
    h, r = divmod(uptime, 3600)
    m, s = divmod(r, 60)
    logging.info(f"{RED}Proxy STOPPED │ Uptime {h:02d}:{m:02d}:{s:02d} │ Total {stats['total']} connections │ ↑ {format_bytes(stats['bytes_up'])} ↓ {format_bytes(stats['bytes_down'])}{RESET}")
    sys.exit(0)

# ====================== MAIN ======================
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-l", "--listen", default="0.0.0.0")
    parser.add_argument("-p", "--port", type=int, default=2160)
    parser.add_argument("-u", "--username")
    parser.add_argument("-P", "--password")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    if args.force:
        kill_port(args.port)

    signal.signal(signal.SIGINT, lambda *_: goodbye())
    signal.signal(signal.SIGTERM, lambda *_: goodbye())
    atexit.register(goodbye)

    server = ThreadedServer(
        (args.listen, args.port),
        ProxyHandler,
        args.username,
        args.password
    )

    auth_info = f" (Auth: {args.username}:{args.password})" if args.username else ""
    logging.info(f"{GREEN}Proxy STARTED → {args.listen}:{args.port}{auth_info}{RESET}")

    threading.Thread(target=realtime_log, daemon=True).start()
    server.serve_forever()

if __name__ == "__main__":
    main()
