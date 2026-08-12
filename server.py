#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Universal Proxy Pro v5.2 - Fully Fixed
- SOCKS5 + HTTP/HTTPS on same port
- Full UDP ASSOCIATE (cross‑platform, select based)
- HTTP body forwarding (POST, PUT, PATCH, chunked)
- Fixed connection leaks and stats locks
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
import errno
import socketserver
from urllib.parse import urlparse

# ====================== CONFIG ======================
SOCKS5_VER = 5
SOCKS5_CMD_CONNECT = 0x01
SOCKS5_CMD_UDP = 0x03
HTTP_FIRST_BYTES = {b'CONNECT'[0], b'GET'[0], b'POST'[0], b'PUT'[0], b'DELETE'[0],
                    b'HEAD'[0], b'OPTIONS'[0], b'TRACE'[0], b'PATCH'[0]}

MAX_CONNECTIONS      = 4000
CONNECTION_TIMEOUT   = 25
IDLE_TIMEOUT         = 180
RETRY_ATTEMPTS       = 5
BUFFER_SIZE          = 65536
UDP_BUFFER_SIZE      = 65535
UDP_IDLE_TIMEOUT     = 120

GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
BLUE   = "\033[94m"
CYAN   = "\033[96m"
PURPLE = "\033[95m"
WHITE  = "\033[97m"
RESET  = "\033[0m"

# Custom formatter for connection logs
class ConnectionFilter(logging.Filter):
    def filter(self, record):
        # Only show connection logs, hide debug/warning/info noise
        return hasattr(record, 'connection') and record.connection

# Setup logging with connection filter
logging.basicConfig(
    level=logging.INFO,
    format=f'{BLUE}%(asctime)s{RESET} │ %(message)s',
    datefmt='%H:%M:%S'
)

# Create a separate logger for connection logs
connection_logger = logging.getLogger('connection')
connection_logger.setLevel(logging.INFO)
connection_logger.addFilter(ConnectionFilter())

stats = {
    "start": time.time(),
    "total": 0,
    "current": 0,
    "socks5_tcp": 0,
    "socks5_udp": 0,
    "http": 0,
    "auth_fail": 0,
    "bytes_up": 0,
    "bytes_down": 0,
    "udp_up": 0,
    "udp_down": 0
}

active_conns = set()           # {(ip, port, type, target), ...}
udp_assocs = {}                 # {assoc_id: UDPAssociation}
stats_lock   = threading.Lock()
active_lock  = threading.Lock()
udp_lock     = threading.Lock()

# ====================== UDP ASSOCIATION ======================
class UDPAssociation:
    def __init__(self, client_addr, relay_port):
        self.client_addr = client_addr      # (ip, tcp_port)
        self.client_udp = None              # (ip, udp_port) - learned from first packet
        self.relay_port = relay_port
        self.relay_sock = None
        self.dest_map = {}
        self.last_activity = time.time()
        self.active = True
        self.lock = threading.Lock()

    def create_relay(self):
        try:
            self.relay_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.relay_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.relay_sock.bind(('0.0.0.0', self.relay_port))
            self.relay_sock.setblocking(False)
            logging.info(f"{PURPLE}UDP relay on port {self.relay_port} for {self.client_addr}{RESET}")
            return True
        except Exception as e:
            logging.error(f"{RED}UDP relay creation failed: {e}{RESET}")
            return False

    def close(self):
        with self.lock:
            self.active = False
            if self.relay_sock:
                try:
                    self.relay_sock.close()
                except:
                    pass
                self.relay_sock = None
            self.dest_map.clear()
            logging.info(f"{PURPLE}UDP association closed for {self.client_addr}{RESET}")

    def is_expired(self):
        return time.time() - self.last_activity > UDP_IDLE_TIMEOUT

# ====================== UDP RELAY THREAD (select based) ======================
class UDPRelayThread(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.running = True

    def run(self):
        while self.running:
            try:
                self._process_udp()
                time.sleep(0.01)
            except Exception as e:
                logging.error(f"UDP relay error: {e}")

    def _process_udp(self):
        # Lấy snapshot các socket relay đang hoạt động
        socks = []
        assoc_map = {}
        with udp_lock:
            for assoc in udp_assocs.values():
                if assoc.active and assoc.relay_sock:
                    socks.append(assoc.relay_sock)
                    assoc_map[assoc.relay_sock.fileno()] = assoc
        if not socks:
            time.sleep(0.1)
            return

        try:
            rlist, _, _ = select.select(socks, [], [], 0.5)
        except (ValueError, OSError):
            return

        for sock in rlist:
            assoc = assoc_map.get(sock.fileno())
            if not assoc:
                continue
            try:
                data, addr = sock.recvfrom(UDP_BUFFER_SIZE)
                assoc.last_activity = time.time()

                # Lần đầu tiên nhận packet → đó là client UDP
                if assoc.client_udp is None:
                    assoc.client_udp = addr
                    logging.info(f"{PURPLE}UDP client registered: {addr[0]}:{addr[1]}{RESET}")
                    self._forward_client_to_remote(assoc, data, addr)
                elif addr == assoc.client_udp:
                    self._forward_client_to_remote(assoc, data, addr)
                else:
                    self._forward_remote_to_client(assoc, data, addr)
            except Exception as e:
                logging.debug(f"UDP recv error: {e}")

    def _forward_client_to_remote(self, assoc, data, client_addr):
        # Parse SOCKS5 UDP request header
        if len(data) < 4:
            return
        rsv = data[0:2]          # unused
        frag = data[2]
        if frag != 0:
            logging.warning(f"UDP fragmentation not supported (frag={frag})")
            return
        atyp = data[3]
        pos = 4
        if atyp == 1:            # IPv4
            if len(data) < pos + 6:
                return
            host = socket.inet_ntoa(data[pos:pos+4])
            pos += 4
        elif atyp == 3:          # domain
            if len(data) < pos + 1:
                return
            domlen = data[pos]
            pos += 1
            if len(data) < pos + domlen + 2:
                return
            host = data[pos:pos+domlen].decode('idna', errors='ignore')
            pos += domlen
        elif atyp == 4:          # IPv6
            if len(data) < pos + 18:
                return
            host = socket.inet_ntop(socket.AF_INET6, data[pos:pos+16])
            pos += 16
        else:
            return
        port = struct.unpack('!H', data[pos:pos+2])[0]
        payload = data[pos+2:]

        # Forward to real destination
        try:
            dest = (host, port)
            assoc.relay_sock.sendto(payload, dest)
            assoc.dest_map[dest] = time.time()
            with stats_lock:
                stats["udp_up"] += len(payload)
        except Exception as e:
            logging.debug(f"UDP forward error: {e}")

    def _forward_remote_to_client(self, assoc, data, remote_addr):
        if not assoc.client_udp:
            return
        # Build SOCKS5 UDP response header
        if ':' in remote_addr[0]:   # IPv6
            atyp = 4
            bin_addr = socket.inet_pton(socket.AF_INET6, remote_addr[0])
        else:
            atyp = 1
            bin_addr = socket.inet_pton(socket.AF_INET, remote_addr[0])
        header = struct.pack('!HBB', 0, 0, atyp) + bin_addr + struct.pack('!H', remote_addr[1])
        try:
            assoc.relay_sock.sendto(header + data, assoc.client_udp)
            with stats_lock:
                stats["udp_down"] += len(data)
        except Exception as e:
            logging.debug(f"UDP reply error: {e}")

# ====================== TCP SERVER ======================
class ThreadedProxyServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, server_address, RequestHandlerClass, username="", password=""):
        self.username = username or ""
        self.password = password or ""
        self.auth_required = bool(username and password)
        self.udp_relay = UDPRelayThread()
        self.udp_relay.start()
        super().__init__(server_address, RequestHandlerClass)

# ====================== MAIN HANDLER ======================
class ProxyHandler(socketserver.StreamRequestHandler):

    def handle(self):
        client_ip, client_port = self.client_address
        conn_type = None
        target = ""

        with stats_lock:
            if stats["current"] >= MAX_CONNECTIONS:
                logging.warning(f"{RED}Max connections reached from {client_ip}{RESET}")
                return
            stats["total"] += 1
            stats["current"] += 1

        try:
            # Peek first byte to detect protocol
            peek = self.connection.recv(1, socket.MSG_PEEK)
            if not peek:
                return
            first_byte = peek[0]

            if first_byte == SOCKS5_VER:
                self.handle_socks5()
                return
            elif first_byte in HTTP_FIRST_BYTES:
                conn_type = "HTTP"
                with stats_lock:
                    stats["http"] += 1
                self.handle_http()
            else:
                logging.warning(f"{YELLOW}Unknown protocol from {client_ip}:{client_port} (byte: {first_byte}){RESET}")
        except Exception as e:
            logging.error(f"Handler error {client_ip}:{client_port} → {e}")
        finally:
            with stats_lock:
                stats["current"] -= 1
            if conn_type:
                with active_lock:
                    active_conns.discard((client_ip, client_port, conn_type, target))

    # ---------- SOCKS5 (TCP + UDP) ----------
    def handle_socks5(self):
        client_ip, client_port = self.client_address
        assoc = None
        conn_type = None
        target = ""

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

            if self.server.auth_required and not self._socks5_auth():
                return

            ver, cmd, _, atyp = struct.unpack("!BBBB", self.connection.recv(4))
            if cmd == SOCKS5_CMD_CONNECT:
                conn_type = "SOCKS5_TCP"
                host, port = self._read_socks5_addr(atyp)
                if not host:
                    self._socks5_reply(0x04)
                    return
                target = f"{host}:{port}"
                # Log connection
                self._log_connection(f"{GREEN}SOCKS5 TCP → {client_ip}:{client_port} → {WHITE}{target}{RESET}")
                remote = self._connect_remote(host, port)
                if not remote:
                    self._socks5_reply(0x05)
                    return
                bind_ip, bind_port = remote.getsockname()[:2]
                self._socks5_reply(0x00, bind_ip, bind_port)
                with active_lock:
                    active_conns.add((client_ip, client_port, conn_type, target))
                with stats_lock:
                    stats["socks5_tcp"] += 1
                self._tunnel(self.connection, remote)

            elif cmd == SOCKS5_CMD_UDP:
                conn_type = "SOCKS5_UDP"
                host, port = self._read_socks5_addr(atyp)   # client requested bind address (ignored)
                target = f"UDP:{host}:{port}" if host else "UDP:any"
                self._log_connection(f"{PURPLE}UDP Associate → {client_ip}:{client_port} → {WHITE}{target}{RESET}")
                udp_port = self._find_free_port()
                assoc = UDPAssociation((client_ip, client_port), udp_port)
                if not assoc.create_relay():
                    self._socks5_reply(0x01)
                    return
                with udp_lock:
                    udp_assocs[f"{client_ip}:{client_port}:{udp_port}"] = assoc
                with active_lock:
                    active_conns.add((client_ip, client_port, conn_type, target))
                with stats_lock:
                    stats["socks5_udp"] += 1
                bind_ip = self.server.server_address[0]
                if bind_ip == '0.0.0.0':
                    bind_ip = '127.0.0.1'
                self._socks5_reply(0x00, bind_ip, udp_port)
                self._keep_udp_association(assoc)
            else:
                self._socks5_reply(0x07)
        except Exception as e:
            logging.error(f"SOCKS5 error: {e}")
        finally:
            if assoc:
                assoc.close()
                with udp_lock:
                    for aid in list(udp_assocs.keys()):
                        if udp_assocs[aid] == assoc:
                            del udp_assocs[aid]
                            break
            if conn_type:
                with active_lock:
                    active_conns.discard((client_ip, client_port, conn_type, target))

    def _log_connection(self, message):
        """Log connection with special flag for filter"""
        extra = {'connection': True}
        connection_logger.info(message, extra=extra)

    def _socks5_auth(self):
        try:
            ver = self.connection.recv(1)[0]
            if ver != 1:
                self.connection.sendall(b'\x01\xff')
                return False
            ulen = self.connection.recv(1)[0]
            user = self.connection.recv(ulen)
            plen = self.connection.recv(1)[0]
            pwd = self.connection.recv(plen)
            ok = (user == self.server.username.encode()) and (pwd == self.server.password.encode())
            self.connection.sendall(b'\x01\x00' if ok else b'\x01\xff')
            if not ok:
                logging.warning(f"{RED}SOCKS5 auth fail from {self.client_address[0]} user={user!r}{RESET}")
                with stats_lock:
                    stats["auth_fail"] += 1
            else:
                logging.info(f"{GREEN}SOCKS5 auth OK user={user.decode(errors='ignore')}{RESET}")
            return ok
        except:
            self.connection.sendall(b'\x01\xff')
            return False

    def _read_socks5_addr(self, atyp):
        try:
            if atyp == 1:    # IPv4
                addr = socket.inet_ntop(socket.AF_INET, self.connection.recv(4))
            elif atyp == 3:  # domain
                length = self.connection.recv(1)[0]
                addr = self.connection.recv(length).decode('idna', errors='ignore')
            elif atyp == 4:  # IPv6
                addr = socket.inet_ntop(socket.AF_INET6, self.connection.recv(16))
            else:
                return None, 0
            port = struct.unpack("!H", self.connection.recv(2))[0]
            return addr, port
        except:
            return None, 0

    def _socks5_reply(self, rep, addr="0.0.0.0", port=0):
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

    def _keep_udp_association(self, assoc):
        """Keep TCP control connection alive"""
        try:
            while assoc.active and not assoc.is_expired():
                r, _, e = select.select([self.connection], [], [self.connection], 5)
                if e:
                    break
                if r:
                    # Client may send UDP bind address (optional, we ignore)
                    self.connection.recv(1024)
        except:
            pass

    def _find_free_port(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('', 0))
        port = sock.getsockname()[1]
        sock.close()
        return port

    # ---------- HTTP/HTTPS ----------
    def handle_http(self):
        client_ip, client_port = self.client_address
        remote = None
        target = ""
        method = ""
        
        try:
            # Read request line
            request_line = self.rfile.readline(BUFFER_SIZE).decode('latin-1', errors='ignore').strip()
            if not request_line:
                return
            parts = request_line.split()
            if len(parts) < 2:
                return
            method, url = parts[0], parts[1]
            method = method.upper()

            # Read headers
            headers = {}
            while True:
                line = self.rfile.readline(BUFFER_SIZE).decode('latin-1', errors='ignore').rstrip('\r\n')
                if not line:
                    break
                if ':' in line:
                    k, v = line.split(':', 1)
                    headers[k.strip().lower()] = v.strip()

            # Authentication
            if self.server.auth_required and not self._http_auth(headers):
                self.wfile.write(b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                                 b"Proxy-Authenticate: Basic realm=\"Proxy\"\r\n\r\n")
                self.wfile.flush()
                with stats_lock:
                    stats["auth_fail"] += 1
                return

            # Determine target host/port
            if method == "CONNECT":
                host_port = url.split(':', 1)
                host = host_port[0]
                port = int(host_port[1]) if len(host_port) > 1 else 443
                target = f"{host}:{port}"
            else:
                parsed = urlparse(url if url.startswith(('http://', 'https://')) else 'http://' + url)
                host = parsed.hostname
                port = parsed.port or (443 if parsed.scheme == 'https' else 80)
                target = f"{host}:{port}"
                if parsed.path:
                    target += parsed.path[:50]  # Limit path length for display
            
            # Log HTTP connection with URL
            self._log_connection(f"{GREEN}HTTP {method} → {client_ip}:{client_port} → {WHITE}{target}{RESET}")
            
            with active_lock:
                active_conns.add((client_ip, client_port, "HTTP", target))

            remote = self._connect_remote(host, port)
            if not remote:
                self.wfile.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                self.wfile.flush()
                return

            if method == "CONNECT":
                self.wfile.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                self.wfile.flush()
                self._tunnel(self.connection, remote)
            else:
                # Forward full HTTP request (including body)
                self._forward_http_request(method, url, headers, remote)
                # Read response and send back
                self._forward_response(remote, self.connection)
        except Exception as e:
            logging.error(f"HTTP error: {e}")
        finally:
            if remote:
                try:
                    remote.close()
                except:
                    pass
            with active_lock:
                active_conns.discard((client_ip, client_port, "HTTP", target))

    def _http_auth(self, headers):
        auth = headers.get('proxy-authorization', '')
        if not auth.lower().startswith('basic '):
            return False
        try:
            cred = base64.b64decode(auth[6:]).decode('utf-8', errors='ignore')
            u, p = cred.split(':', 1)
            return u == self.server.username and p == self.server.password
        except:
            return False

    def _forward_http_request(self, method, url, headers, remote):
        # Build path
        parsed = urlparse(url if url.startswith(('http://', 'https://')) else 'http://' + url)
        path = parsed.path or '/'
        if parsed.query:
            path += '?' + parsed.query

        # Build request line
        req = f"{method} {path} HTTP/1.1\r\n"

        # Add Host header if missing
        if 'host' not in headers:
            req += f"Host: {parsed.hostname}\r\n"
        for k, v in headers.items():
            if k not in ('proxy-authorization', 'proxy-connection', 'connection'):
                req += f"{k.title()}: {v}\r\n"
        req += "Connection: close\r\n\r\n"

        remote.sendall(req.encode('latin-1'))

        # Read and forward body (if any)
        content_length = headers.get('content-length')
        transfer_encoding = headers.get('transfer-encoding', '').lower()
        if content_length:
            remaining = int(content_length)
            while remaining > 0:
                chunk = self.connection.recv(min(remaining, BUFFER_SIZE))
                if not chunk:
                    break
                remote.sendall(chunk)
                remaining -= len(chunk)
        elif transfer_encoding == 'chunked':
            while True:
                # Read chunk size line
                line = self._read_line()
                if not line:
                    break
                try:
                    chunk_size = int(line.strip().split(b';')[0], 16)
                except:
                    break
                if chunk_size == 0:
                    # Read trailing headers and discard
                    while True:
                        trail = self._read_line()
                        if not trail or trail == b'\r\n':
                            break
                    break
                data = self.connection.recv(chunk_size)
                if len(data) != chunk_size:
                    break
                remote.sendall(data)
                # Consume trailing CRLF
                self.connection.recv(2)
        # else no body

    def _read_line(self):
        """Read a line from connection (used for chunked decoding)"""
        line = b''
        while True:
            ch = self.connection.recv(1)
            if not ch:
                return None
            line += ch
            if line.endswith(b'\n'):
                return line

    def _forward_response(self, src, dst):
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

    # ---------- Common ----------
    def _connect_remote(self, host, port):
        family = socket.AF_INET6 if ':' in host else socket.AF_INET
        for attempt in range(RETRY_ATTEMPTS):
            try:
                sock = socket.socket(family)
                sock.settimeout(CONNECTION_TIMEOUT)
                sock.connect((host, port))
                # Log successful connection with target
                self._log_connection(f"{CYAN}✓ Connected to {host}:{port}{RESET}")
                return sock
            except Exception as e:
                if attempt == RETRY_ATTEMPTS - 1:
                    logging.warning(f"Connect failed {host}:{port} after {RETRY_ATTEMPTS} tries → {e}")
                time.sleep(min(0.5 * (attempt + 1), 4.0))
        return None

    def _tunnel(self, client, remote):
        socks = [client, remote]
        while True:
            r, _, e = select.select(socks, [], socks, IDLE_TIMEOUT)
            if e or not r:
                break
            for s in r:
                data = s.recv(BUFFER_SIZE)
                if not data:
                    return
                if s == client:
                    remote.sendall(data)
                    with stats_lock:
                        stats["bytes_up"] += len(data)
                else:
                    client.sendall(data)
                    with stats_lock:
                        stats["bytes_down"] += len(data)
        try:
            client.close()
        except:
            pass
        try:
            remote.close()
        except:
            pass

# ====================== MONITOR & UTILS ======================
def format_bytes(b):
    for unit in ['B', 'KiB', 'MiB', 'GiB', 'TiB']:
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} PiB"

def realtime_stats():
    """Display realtime stats without spamming - uses carriage return to overwrite"""
    while True:
        time.sleep(2)  # Update every 2 seconds for smoother display
        
        uptime = time.time() - stats["start"]
        h = int(uptime // 3600)
        m = int((uptime % 3600) // 60)
        s = int(uptime % 60)

        with active_lock:
            cur = len(active_conns)
            s5_tcp = sum(1 for _, _, t, _ in active_conns if t == "SOCKS5_TCP")
            s5_udp = sum(1 for _, _, t, _ in active_conns if t == "SOCKS5_UDP")
            http = sum(1 for _, _, t, _ in active_conns if t == "HTTP")

        with udp_lock:
            udp_assoc_count = len(udp_assocs)
        
        # Build stats line with colors
        line1 = (f"{YELLOW}↑TCP {format_bytes(stats['bytes_up']):>9} ↓TCP {format_bytes(stats['bytes_down']):>9} │ "
                f"↑UDP {format_bytes(stats['udp_up']):>7} ↓UDP {format_bytes(stats['udp_down']):>7}{RESET}")
        
        line2 = (f"{CYAN}Active: {cur:>4} (TCP:{s5_tcp:>3} UDP:{s5_udp:>3} HTTP:{http:>3}) │ "
                f"UDP Assoc: {udp_assoc_count:>3} │ Uptime {h:02d}:{m:02d}:{s:02d}{RESET}")
        
        # Move cursor up 2 lines, clear lines and print new stats
        sys.stdout.write('\033[2A')  # Move up 2 lines
        sys.stdout.write('\033[2K')  # Clear current line
        sys.stdout.write(line1 + '\n')
        sys.stdout.write('\033[2K')  # Clear next line
        sys.stdout.write(line2 + '\n')
        sys.stdout.flush()

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
    with udp_lock:
        for assoc in udp_assocs.values():
            assoc.close()
        udp_assocs.clear()
    
    # Print final stats with newline
    sys.stdout.write('\n')  # Ensure we're on a new line
    logging.info(
        f"{RED}Proxy STOPPED │ Uptime {h:02d}:{m:02d}:{s:02d} │ "
        f"Total conn {stats['total']} │ "
        f"↑TCP {format_bytes(stats['bytes_up'])} ↓TCP {format_bytes(stats['bytes_down'])} │ "
        f"↑UDP {format_bytes(stats['udp_up'])} ↓UDP {format_bytes(stats['udp_down'])}{RESET}"
    )
    sys.exit(0)

# ====================== MAIN ======================
def main():
    parser = argparse.ArgumentParser(description="Universal Proxy (SOCKS5 + HTTP + UDP) v5.2")
    parser.add_argument("-l", "--listen", default="0.0.0.0", help="Bind address")
    parser.add_argument("-p", "--port", type=int, default=1080, help="Port to listen on")
    parser.add_argument("-u", "--username", help="Username for auth")
    parser.add_argument("-P", "--password", help="Password for auth")
    parser.add_argument("--force-kill", action="store_true", help="Kill port before start")
    args = parser.parse_args()

    if args.force_kill:
        kill_port(args.port)

    signal.signal(signal.SIGINT, lambda sig, frame: shutdown())
    signal.signal(signal.SIGTERM, lambda sig, frame: shutdown())
    atexit.register(shutdown)

    server = ThreadedProxyServer(
        (args.listen, args.port),
        ProxyHandler,
        username=args.username,
        password=args.password
    )

    auth_str = f" (auth: {args.username}:{args.password})" if args.username else ""
    logging.info(f"{GREEN}Proxy v5.2 STARTED → {args.listen}:{args.port}{auth_str}{RESET}")
    logging.info(f"{CYAN}Features: SOCKS5 TCP/UDP + HTTP/HTTPS on same port (fixed UDP/HTTP body){RESET}")
    
    # Print initial empty lines for stats display
    print("\n" * 2)

    threading.Thread(target=realtime_stats, daemon=True).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        shutdown()

if __name__ == "__main__":
    main()
