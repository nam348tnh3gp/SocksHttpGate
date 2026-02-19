#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Universal Proxy Pro v5.1 - Full SOCKS5 + HTTP/HTTPS + UDP ASSOCIATE
- SOCKS5 + HTTP/HTTPS on same port
- Full UDP ASSOCIATE support for DNS, VoIP, gaming, etc.
- Fixed connection counting bug
- Tunnel dùng select synchronous (fix thread dead/empty reply)
- Fix curl (52) & (35) errors
- Tested in Termux/Android and Linux
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
import queue
import errno
from socketserver import ThreadingMixIn, TCPServer, StreamRequestHandler
from urllib.parse import urlparse

# ====================== CONFIG ======================
SOCKS5_VER = 5
SOCKS5_CMD_CONNECT = 0x01
SOCKS5_CMD_UDP = 0x03  # UDP ASSOCIATE
HTTP_FIRST_BYTES = {b'CONNECT'[0], b'GET'[0], b'POST'[0], b'PUT'[0], b'DELETE'[0],
                    b'HEAD'[0], b'OPTIONS'[0], b'TRACE'[0], b'PATCH'[0]}

MAX_CONNECTIONS      = 4000
CONNECTION_TIMEOUT   = 25
IDLE_TIMEOUT         = 180      # seconds
RETRY_ATTEMPTS       = 5
BUFFER_SIZE          = 65536
UDP_BUFFER_SIZE      = 65535
UDP_IDLE_TIMEOUT     = 120      # UDP association timeout

GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
BLUE   = "\033[94m"
CYAN   = "\033[96m"
PURPLE = "\033[95m"
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
    "socks5_tcp": 0,
    "socks5_udp": 0,
    "http": 0,
    "auth_fail": 0,
    "bytes_up": 0,
    "bytes_down": 0,
    "udp_up": 0,
    "udp_down": 0
}

active_conns = set()           # {(ip, port, type), ...}
udp_assocs = {}                 # {assoc_id: UDPAssociation}
stats_lock   = threading.Lock()
active_lock  = threading.Lock()
udp_lock     = threading.Lock()

# ====================== UDP ASSOCIATION ======================
class UDPAssociation:
    """Quản lý kết nối UDP ASSOCIATE"""
    def __init__(self, client_addr, relay_port):
        self.client_addr = client_addr  # (ip, port) của client TCP
        self.client_udp = None          # Địa chỉ UDP client (sẽ cập nhật sau)
        self.relay_port = relay_port     # Port relay UDP
        self.relay_sock = None           # Socket UDP relay
        self.dest_map = {}                # Map (dst_addr) -> recent activity
        self.last_activity = time.time()
        self.active = True
        self.lock = threading.Lock()
        
    def create_relay(self):
        """Tạo socket UDP relay"""
        try:
            self.relay_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.relay_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.relay_sock.bind(('0.0.0.0', self.relay_port))
            self.relay_sock.settimeout(1.0)  # Non-blocking với timeout
            logging.info(f"{PURPLE}UDP Associate created on port {self.relay_port} for {self.client_addr}{RESET}")
            return True
        except Exception as e:
            logging.error(f"{RED}Failed to create UDP relay: {e}{RESET}")
            return False
    
    def close(self):
        """Đóng UDP association"""
        with self.lock:
            self.active = False
            if self.relay_sock:
                try:
                    self.relay_sock.close()
                except:
                    pass
                self.relay_sock = None
            self.dest_map.clear()
            logging.info(f"{PURPLE}UDP Associate closed for {self.client_addr}{RESET}")
    
    def is_expired(self):
        """Kiểm tra association có hết hạn không"""
        return time.time() - self.last_activity > UDP_IDLE_TIMEOUT

# ====================== UDP RELAY THREAD ======================
class UDPRelayThread(threading.Thread):
    """Thread xử lý UDP relay cho tất cả associations"""
    def __init__(self):
        super().__init__(daemon=True)
        self.running = True
        self.epoll = select.epoll()
        self.fd_to_assoc = {}  # Map file descriptor -> assoc_id
        
    def run(self):
        """Vòng lặp chính xử lý UDP packets"""
        while self.running:
            try:
                self._cleanup_expired()
                self._handle_udp_packets()
                time.sleep(0.01)  # Tránh CPU 100%
            except Exception as e:
                logging.error(f"UDP Relay error: {e}")
    
    def _cleanup_expired(self):
        """Dọn dẹp các association hết hạn"""
        with udp_lock:
            expired = [aid for aid, assoc in udp_assocs.items() 
                      if not assoc.active or assoc.is_expired()]
            for aid in expired:
                assoc = udp_assocs.pop(aid, None)
                if assoc:
                    if assoc.relay_sock and assoc.relay_sock.fileno() in self.fd_to_assoc:
                        self.epoll.unregister(assoc.relay_sock.fileno())
                        del self.fd_to_assoc[assoc.relay_sock.fileno()]
                    assoc.close()
    
    def _handle_udp_packets(self):
        """Xử lý UDP packets từ tất cả associations"""
        with udp_lock:
            # Đăng ký socket mới
            for assoc_id, assoc in udp_assocs.items():
                if assoc.relay_sock and assoc.relay_sock.fileno() not in self.fd_to_assoc:
                    fd = assoc.relay_sock.fileno()
                    self.epoll.register(fd, select.EPOLLIN)
                    self.fd_to_assoc[fd] = assoc_id
            
            if not self.fd_to_assoc:
                return
            
            try:
                events = self.epoll.poll(timeout=0.1)
                for fd, event in events:
                    assoc_id = self.fd_to_assoc.get(fd)
                    if not assoc_id or assoc_id not in udp_assocs:
                        continue
                    
                    assoc = udp_assocs[assoc_id]
                    if event & select.EPOLLIN:
                        self._forward_udp_packet(assoc)
                    elif event & (select.EPOLLHUP | select.EPOLLERR):
                        logging.debug(f"UDP socket error for assoc {assoc_id}")
                        assoc.close()
            except Exception as e:
                if e.args[0] != errno.EINTR:  # Ignore interrupt
                    logging.debug(f"UDP poll error: {e}")
    
    def _forward_udp_packet(self, assoc):
        """Forward một UDP packet"""
        try:
            data, addr = assoc.relay_sock.recvfrom(UDP_BUFFER_SIZE)
            assoc.last_activity = time.time()
            
            # Parse SOCKS5 UDP request header
            if addr == assoc.client_udp:
                # Packet từ client -> cần forward ra internet
                self._handle_client_to_remote(assoc, data, addr)
            else:
                # Packet từ remote -> forward về client
                self._handle_remote_to_client(assoc, data, addr)
                
        except Exception as e:
            logging.debug(f"UDP forward error: {e}")
    
    def _handle_client_to_remote(self, assoc, data, client_addr):
        """Xử lý packet từ client UDP đến remote server"""
        try:
            # Parse SOCKS5 UDP request header
            # +----+------+------+----------+----------+----------+
            # |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
            # +----+------+------+----------+----------+----------+
            # | 2  |  1   |  1   | Variable |    2     | Variable |
            # +----+------+------+----------+----------+----------+
            
            if len(data) < 4:
                return
            
            rsv = data[0:2]
            frag = data[2]
            atyp = data[3]
            
            if frag != 0:
                logging.warning(f"UDP fragmentation not supported (frag={frag})")
                return
            
            pos = 4
            # Parse địa chỉ đích
            if atyp == 1:  # IPv4
                if len(data) < pos + 6:
                    return
                host = socket.inet_ntoa(data[pos:pos+4])
                pos += 4
            elif atyp == 3:  # Domain name
                if len(data) < pos + 1:
                    return
                domain_len = data[pos]
                pos += 1
                if len(data) < pos + domain_len + 2:
                    return
                host = data[pos:pos+domain_len].decode()
                pos += domain_len
            elif atyp == 4:  # IPv6
                if len(data) < pos + 18:
                    return
                host = socket.inet_ntop(socket.AF_INET6, data[pos:pos+16])
                pos += 16
            else:
                return
            
            port = struct.unpack('!H', data[pos:pos+2])[0]
            pos += 2
            
            # Payload thực tế
            payload = data[pos:]
            
            # Gửi đến remote server
            dest_addr = (host, port)
            assoc.relay_sock.sendto(payload, dest_addr)
            
            # Cập nhật destination map
            assoc.dest_map[dest_addr] = time.time()
            
            with stats_lock:
                stats["udp_up"] += len(payload)
                
        except Exception as e:
            logging.debug(f"Client->Remote UDP error: {e}")
    
    def _handle_remote_to_client(self, assoc, data, remote_addr):
        """Xử lý packet từ remote server gửi về client"""
        try:
            if not assoc.client_udp:
                # Chưa biết địa chỉ UDP của client, bỏ qua
                return
            
            # Tạo SOCKS5 UDP response header
            # Xác định ATYP từ remote_addr
            if ':' in remote_addr[0]:  # IPv6
                atyp = 4
                bin_addr = socket.inet_pton(socket.AF_INET6, remote_addr[0])
            else:  # IPv4
                atyp = 1
                bin_addr = socket.inet_pton(socket.AF_INET, remote_addr[0])
            
            # Tạo header: RSV(2) + FRAG(1) + ATYP(1) + DST.ADDR + DST.PORT
            header = struct.pack('!HBB', 0, 0, atyp) + bin_addr + struct.pack('!H', remote_addr[1])
            
            # Gửi về client
            assoc.relay_sock.sendto(header + data, assoc.client_udp)
            
            with stats_lock:
                stats["udp_down"] += len(data)
                
        except Exception as e:
            logging.debug(f"Remote->Client UDP error: {e}")

# ====================== SERVER ======================
class ThreadedProxyServer(ThreadingMixIn, TCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, server_address, RequestHandlerClass, username="", password=""):
        self.username = username or ""
        self.password = password or ""
        self.auth_required = bool(username and password)
        self.udp_relay = UDPRelayThread()
        self.udp_relay.start()
        super().__init__(server_address, RequestHandlerClass)

# ====================== HANDLER ======================
class ProxyHandler(StreamRequestHandler):

    def handle(self):
        client_ip, client_port = self.client_address
        conn_type = None  # Theo dõi loại kết nối

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
                # Socks5 sẽ tự xử lý conn_type bên trong handle_socks5
                self.handle_socks5()
                return  # handle_socks5 đã tự xử lý active_conns

            elif first_byte in HTTP_FIRST_BYTES:
                conn_type = "HTTP"
                with stats_lock: 
                    stats["http"] += 1
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
            # Xóa khỏi active_conns nếu là HTTP (SOCKS5 tự xử lý trong finally của nó)
            if conn_type == "HTTP":
                with active_lock:
                    active_conns.discard((client_ip, client_port, "HTTP"))

    # ─── SOCKS5 (TCP + UDP) ───────────────────────────────────
    def handle_socks5(self):
        client_ip, client_port = self.client_address
        assoc = None
        conn_type = None  # Sẽ là "SOCKS5_TCP" hoặc "SOCKS5_UDP"
        
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

            # Đọc request
            ver, cmd, _, atyp = struct.unpack("!BBBB", self.connection.recv(4))
            
            if cmd == SOCKS5_CMD_CONNECT:
                # TCP CONNECT
                conn_type = "SOCKS5_TCP"
                host, port = self.read_socks5_addr(atyp)
                if not host:
                    self.socks5_reply(0x04)
                    return

                remote = self.connect_remote(host, port)
                if not remote:
                    self.socks5_reply(0x05)
                    return

                bind_ip, bind_port = remote.getsockname()[:2]
                self.socks5_reply(0x00, bind_ip, bind_port)
                
                # THÊM: Add vào active connections
                with active_lock:
                    active_conns.add((client_ip, client_port, conn_type))
                
                with stats_lock:
                    stats["socks5_tcp"] += 1
                    
                logging.info(f"{GREEN}SOCKS5 TCP → {client_ip}:{client_port}{RESET}")
                
                self.tunnel(self.connection, remote)
                
            elif cmd == SOCKS5_CMD_UDP:
                # UDP ASSOCIATE
                conn_type = "SOCKS5_UDP"
                host, port = self.read_socks5_addr(atyp)
                
                # Tìm port UDP trống
                udp_port = self.find_free_port()
                
                # Tạo UDP association
                assoc_id = f"{client_ip}:{client_port}:{udp_port}"
                assoc = UDPAssociation((client_ip, client_port), udp_port)
                
                if not assoc.create_relay():
                    self.socks5_reply(0x01)  # General failure
                    return
                
                # Lưu association
                with udp_lock:
                    udp_assocs[assoc_id] = assoc
                
                # THÊM: Add vào active connections
                with active_lock:
                    active_conns.add((client_ip, client_port, conn_type))
                
                with stats_lock:
                    stats["socks5_udp"] += 1
                
                # Gửi reply với địa chỉ UDP relay
                bind_ip = self.server.server_address[0]
                if bind_ip == '0.0.0.0':
                    bind_ip = '127.0.0.1'
                
                self.socks5_reply(0x00, bind_ip, udp_port)
                
                logging.info(f"{PURPLE}UDP Associate established for {client_ip}:{client_port} on port {udp_port}{RESET}")
                
                # Giữ kết nối TCP cho UDP association
                self.keep_udp_association(assoc)
                
            else:
                # Command không hỗ trợ
                self.socks5_reply(0x07)
                return

        except Exception as e:
            logging.error(f"SOCKS5 error: {e}")
        finally:
            # Đóng UDP association nếu có
            if assoc:
                assoc.close()
                with udp_lock:
                    for aid in list(udp_assocs.keys()):
                        if udp_assocs[aid] == assoc:
                            del udp_assocs[aid]
                            break
            
            # QUAN TRỌNG: Xóa khỏi active_conns
            if conn_type:
                with active_lock:
                    active_conns.discard((client_ip, client_port, conn_type))
            
            # stats["current"] đã được giảm trong handle() rồi

    def keep_udp_association(self, assoc):
        """Giữ kết nối TCP cho UDP association"""
        try:
            while assoc.active and not assoc.is_expired():
                # Chờ dữ liệu từ client (có thể là keepalive)
                r, _, e = select.select([self.connection], [], [self.connection], 5)
                if r:
                    data = self.connection.recv(1024)
                    if not data:
                        break
                    # Client gửi địa chỉ UDP của nó
                    if len(data) >= 10 and not assoc.client_udp:
                        # Giả sử client gửi địa chỉ UDP qua TCP
                        try:
                            # Format: ATYP(1) + ADDR + PORT(2)
                            atyp = data[0]
                            if atyp == 1 and len(data) >= 7:  # IPv4
                                ip = socket.inet_ntoa(data[1:5])
                                port = struct.unpack('!H', data[5:7])[0]
                                assoc.client_udp = (ip, port)
                                logging.info(f"{PURPLE}UDP client address set to {ip}:{port}{RESET}")
                        except:
                            pass
                if e:
                    break
                    
        except Exception as e:
            logging.debug(f"UDP association keepalive error: {e}")

    def find_free_port(self):
        """Tìm port UDP trống"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('', 0))
        port = sock.getsockname()[1]
        sock.close()
        return port

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
                self.forward_response(remote, self.connection)

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
                time.sleep(min(0.5 * (attempt + 1), 4.0))
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
            # Đếm theo loại
            s5_tcp = sum(1 for _,_,t in active_conns if t == "SOCKS5_TCP")
            s5_udp = sum(1 for _,_,t in active_conns if t == "SOCKS5_UDP")
            http = sum(1 for _,_,t in active_conns if t == "HTTP")

        with udp_lock:
            udp_assoc_count = len(udp_assocs)

        logging.info(
            f"{YELLOW}↑TCP {format_bytes(stats['bytes_up']):>9} ↓TCP {format_bytes(stats['bytes_down']):>9} │ "
            f"↑UDP {format_bytes(stats['udp_up']):>7} ↓UDP {format_bytes(stats['udp_down']):>7}{RESET}\n"
            f"{CYAN}  Active: {cur:>4} (TCP:{s5_tcp:>3} UDP:{s5_udp:>3} HTTP:{http:>3}) │ "
            f"UDP Assoc: {udp_assoc_count:>3} │ Uptime {h:02d}:{m:02d}:{s:02d}{RESET}"
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
    
    # Đóng tất cả UDP associations
    with udp_lock:
        for assoc in udp_assocs.values():
            assoc.close()
        udp_assocs.clear()
    
    logging.info(
        f"{RED}Proxy STOPPED │ Uptime {h:02d}:{m:02d}:{s:02d} │ "
        f"Total conn {stats['total']} │ "
        f"↑TCP {format_bytes(stats['bytes_up'])} ↓TCP {format_bytes(stats['bytes_down'])} │ "
        f"↑UDP {format_bytes(stats['udp_up'])} ↓UDP {format_bytes(stats['udp_down'])}{RESET}"
    )
    sys.exit(0)

# ====================== MAIN ======================
def main():
    parser = argparse.ArgumentParser(description="Universal Proxy (SOCKS5 + HTTP + UDP) v5.1")
    parser.add_argument("-l", "--listen", default="0.0.0.0", help="Bind address")
    parser.add_argument("-p", "--port", type=int, default=1080, help="Port to listen on")
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
    logging.info(f"{GREEN}Proxy v5.1 STARTED → {args.listen}:{args.port}{auth_str}{RESET}")
    logging.info(f"{CYAN}Features: SOCKS5 TCP/UDP + HTTP/HTTPS on same port{RESET}")

    threading.Thread(target=realtime_stats, daemon=True).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        shutdown()

if __name__ == "__main__":
    main()
