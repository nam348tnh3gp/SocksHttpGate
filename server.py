#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Universal Proxy Pro v6.3 — Python (FULL parity với C/Go)
- SOCKS5 TCP/UDP + HTTP/HTTPS + upstream
- Dashboard: auth, multi-user, quota, API token, audit log, reload history
- SSE real-time traffic chart, kick connection, Prometheus /metrics, /healthz
- Config: proxy_config.json | Usage: proxy_usage.json

FIXES v6.3.4:
  - Thêm SSE /api/stream + biểu đồ real-time (Chart.js)
  - Thêm throttle() — enforce bandwidth limit trên TCP (đã lưu rate_bps nhưng chưa dùng)
  - Thêm /api/kick + nút Kick trên dashboard (giống C/Go)
  - Thêm /healthz (cho orchestrator) + /metrics (Prometheus)
  - Dashboard: hiển thị cột User, upload/download chart
"""

import argparse, atexit, base64, csv, hashlib, hmac, io, ipaddress, json, logging
import os, queue, resource, secrets, select, signal, socket, socketserver
import ssl, struct, sys, threading, time, urllib.parse
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

# ---------- optional deps ----------
try:
    import orjson
    def json_dumps(o): return orjson.dumps(o)
    def json_loads(b): return orjson.loads(b)
except ImportError:
    def json_dumps(o): return json.dumps(o, separators=(',', ':')).encode('utf-8')
    def json_loads(b): return json.loads(b)

def json_str(o):
    """Serialize to string (cho SSE payload)."""
    try:
        import orjson
        return orjson.dumps(o).decode()
    except ImportError:
        return json.dumps(o)

try:
    import psutil
    HAVE_PSUTIL = True
except ImportError:
    HAVE_PSUTIL = False

# ====================== CONFIG ======================
SOCKS5_VER = 5
SOCKS5_CMD_CONNECT = 0x01
SOCKS5_CMD_UDP = 0x03
HTTP_FIRST_BYTES = {ord(c) for c in "CGPDAHOT"}

MAX_CONNECTIONS      = 4000
CONNECTION_TIMEOUT   = 25
IDLE_TIMEOUT         = 180
RETRY_ATTEMPTS       = 5
BUFFER_SIZE          = 65536
UDP_BUFFER_SIZE      = 65535
UDP_IDLE_TIMEOUT     = 120
DASHBOARD_PORT       = 8081
UDP_DEST_MAX         = 4096
HIST_MAX             = 300              # 300 mẫu * 2s = 10 phút
DASH_MAX_SSE         = 16

HASH_ITERATIONS      = 200000
AUTH_FAIL_THRESHOLD  = 5
DASH_AUTH_FAIL_THRESHOLD = 30
AUTH_FAIL_WINDOW     = 300
AUTH_BLOCK_SECONDS   = 900

GREEN="\033[92m"; YELLOW="\033[93m"; RED="\033[91m"; BLUE="\033[94m"
CYAN="\033[96m"; PURPLE="\033[95m"; WHITE="\033[97m"; RESET="\033[0m"

logging.basicConfig(level=logging.INFO,
                    format=f'{BLUE}%(asctime)s{RESET} │ %(message)s',
                    datefmt='%H:%M:%S')

# ====================== UTIL ======================
def normalize_ip(ip):
    if ip and ip.startswith('::ffff:'): return ip[7:]
    return ip

def format_bytes(b):
    if b < 1024: return f"{b:.1f} B"
    for u in ['B','KiB','MiB','GiB','TiB']:
        if b < 1024: return f"{b:.1f} {u}"
        b /= 1024
    return f"{b:.1f} PiB"

def ct_equal(a, b):
    return hmac.compare_digest(a.encode() if isinstance(a, str) else a,
                               b.encode() if isinstance(b, str) else b)

# ---------- Password hash (tương thích Go/C: "iterations:saltHex:hashHex") ----------
def _pw_digest(password, salt, iterations):
    d = hashlib.sha256(salt + password.encode()).digest()
    for _ in range(1, iterations):
        d = hashlib.sha256(d).digest()
    return d

def hash_password(password, iterations=HASH_ITERATIONS):
    salt = secrets.token_bytes(16)
    dg = _pw_digest(password, salt, iterations)
    return f"{iterations}:{salt.hex()}:{dg.hex()}"

def verify_password(password, stored):
    try:
        parts = stored.split(':')
        if len(parts) != 3: return False
        iters = int(parts[0])
        if iters <= 0 or iters > 5_000_000: return False
        salt = bytes.fromhex(parts[1])
        want = bytes.fromhex(parts[2])
        if len(want) != 32: return False
        got = _pw_digest(password, salt, iters)
        return hmac.compare_digest(got, want)
    except Exception:
        return False

_pwcache = {}
_pwcache_lock = threading.Lock()
_pw_compute_lock = threading.Lock()
PW_CACHE_TTL = 300

def verify_password_cached(password, stored):
    key = hashlib.sha256((stored + "\x00" + password).encode()).digest()
    now = time.time()
    with _pwcache_lock:
        exp = _pwcache.get(key)
        if exp and exp > now: return True
    with _pw_compute_lock:
        with _pwcache_lock:
            exp = _pwcache.get(key)
            if exp and exp > time.time(): return True
        if not verify_password(password, stored): return False
        with _pwcache_lock:
            now2 = time.time()
            if len(_pwcache) >= 1024:
                for k in [k for k, e in _pwcache.items() if e <= now2]:
                    _pwcache.pop(k, None)
                if len(_pwcache) >= 1024: _pwcache.clear()
            _pwcache[key] = now2 + PW_CACHE_TTL
    return True

# ---------- CIDR ----------
def parse_cidrs(items):
    out, invalid = [], []
    for it in items:
        it = (it or '').strip()
        if not it: continue
        try:
            if '/' not in it:
                net = ipaddress.ip_network(it + ('/128' if ':' in it else '/32'), strict=False)
            else:
                net = ipaddress.ip_network(it, strict=False)
            out.append(net)
        except Exception:
            invalid.append(it)
    return out, invalid

def ip_in_nets(ip_str, nets):
    try:
        ip = ipaddress.ip_address(ip_str)
    except Exception:
        return False
    for n in nets:
        try:
            if ip in n: return True
        except Exception:
            pass
    return False

# ---------- SSRF guard ----------
def _ip_is_blocked(ip):
    try:
        if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_multicast:
            return True
        if ip.is_unspecified or ip.is_reserved:
            return True
    except AttributeError:
        return True
    if ip.version == 4:
        n = int(ip)
        if 0x64400000 <= n <= 0x647FFFFF: return True
        if (n >> 24) == 0: return True
        if 0xE0000000 <= n <= 0xEFFFFFFF: return True
        if n >= 0xF0000000: return True
    if ip.version == 6:
        mapped = getattr(ip, 'ipv4_mapped', None)
        if mapped is not None:
            return _ip_is_blocked(mapped)
    return False

def _host_is_blocked(host):
    try:
        return _ip_is_blocked(ipaddress.ip_address(host))
    except ValueError:
        return False

def _resolve_udp_target(host, port):
    try:
        ip = ipaddress.ip_address(host)
        if _ip_is_blocked(ip): return None
        return str(ip)
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)
    except Exception:
        return None
    chosen = None
    for fam, _, _, _, sa in infos:
        ip_str = sa[0]
        try: ip = ipaddress.ip_address(ip_str)
        except ValueError: continue
        if _ip_is_blocked(ip):
            logging.warning(f"{RED}UDP relay chặn {host} → {ip_str} (địa chỉ nội bộ){RESET}")
            return None
        if chosen is None: chosen = ip_str
    return chosen

def _resolve_tcp_target(host, port):
    """Resolve + check SSRF cho TCP. Trả list [(ip_str, port)] hoặc None nếu bị chặn."""
    try:
        ip = ipaddress.ip_address(host)
        if _ip_is_blocked(ip): return None
        return [(str(ip), port)]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except Exception:
        return None
    out = []
    for fam, _, _, _, sa in infos:
        ip_str = sa[0]
        try: ip = ipaddress.ip_address(ip_str)
        except ValueError: continue
        if _ip_is_blocked(ip):
            logging.warning(f"{RED}TCP connect chặn {host} → {ip_str}{RESET}")
            return None
        out.append((ip_str, sa[1]))
    return out or None

# ====================== CONFIG DATA ======================
class AppConfig:
    def __init__(self, data=None):
        data = data or {}
        self.dashboard_user = data.get('dashboard_user', '')
        self.dashboard_password_hash = data.get('dashboard_password_hash', '')
        self.users = data.get('users', []) or []
        self.allow_list = data.get('allow_list', []) or []
        self.deny_list = data.get('deny_list', []) or []
        self.upstream_proxies = data.get('upstream_proxies', []) or []
        self.api_tokens = data.get('api_tokens', []) or []
        self.require_proxy_auth = bool(data.get('require_proxy_auth', False))

    def to_dict(self):
        d = {
            'dashboard_user': self.dashboard_user,
            'dashboard_password_hash': self.dashboard_password_hash,
        }
        if self.users: d['users'] = self.users
        if self.allow_list: d['allow_list'] = self.allow_list
        if self.deny_list: d['deny_list'] = self.deny_list
        if self.upstream_proxies: d['upstream_proxies'] = self.upstream_proxies
        if self.api_tokens: d['api_tokens'] = self.api_tokens
        if self.require_proxy_auth: d['require_proxy_auth'] = True
        return d

# ====================== GLOBAL STATE ======================
stats = {
    "start": time.time(), "total": 0, "current": 0,
    "socks5_tcp": 0, "socks5_udp": 0, "http": 0, "auth_fail": 0,
    "bytes_up": 0, "bytes_down": 0, "udp_up": 0, "udp_down": 0,
    "udp_assocs": 0,
}
stats_lock = threading.Lock()

class ConnectionInfo:
    __slots__ = ('id','ip','port','conn_type','target','start_time',
                 'bytes_up','bytes_down','rate_bps','username','conn')
    def __init__(self, cid, ip, port, conn_type, target, rate_bps=0, username='', conn=None):
        self.id = cid; self.ip = ip; self.port = port
        self.conn_type = conn_type; self.target = target
        self.start_time = time.time()
        self.bytes_up = 0; self.bytes_down = 0
        self.rate_bps = rate_bps; self.username = username; self.conn = conn

active_conns = {}
active_lock = threading.Lock()
_conn_id_counter = 0
_conn_id_lock = threading.Lock()

def next_conn_id():
    global _conn_id_counter
    with _conn_id_lock:
        _conn_id_counter += 1
        return f"c{_conn_id_counter}"

# UDP associations
udp_assocs = {}
udp_lock = threading.Lock()

# ---------- SSE / history (MỚI) ----------
_sample_history = deque(maxlen=HIST_MAX)
_hist_lock = threading.Lock()
_sse_clients = set()
_sse_lock = threading.Lock()

# ---------- Config runtime ----------
config_path = "proxy_config.json"
usage_path = "proxy_usage.json"
cfg = AppConfig()
cfg_lock = threading.RLock()
dashboard_user = ""
dashboard_hash = ""

allowed_cidrs, denied_cidrs = [], []
cidr_lock = threading.Lock()

upstream_proxies = []
upstream_index = 0
upstream_lock = threading.Lock()

upstream_health = {}
upstream_health_lock = threading.RLock()

# ---------- Audit / Reload history ----------
audit_log = []
audit_lock = threading.Lock()
AUDIT_MAX = 200

reload_history = []
reload_lock = threading.Lock()
RELOAD_MAX = 30

def record_audit(actor, action, details=""):
    with audit_lock:
        audit_log.append({"t": int(time.time()), "actor": actor, "action": action, "details": details})
        if len(audit_log) > AUDIT_MAX: del audit_log[:-AUDIT_MAX]

def record_reload(ev):
    with reload_lock:
        reload_history.append(ev)
        if len(reload_history) > RELOAD_MAX: del reload_history[:-RELOAD_MAX]

# ---------- Usage / quota ----------
usage = {}
usage_lock = threading.Lock()

def current_period(): return time.strftime("%Y-%m")

def load_usage(path):
    global usage
    if not path or not os.path.exists(path): return
    try:
        with open(path, 'r') as f: data = json.load(f)
        if isinstance(data, dict): usage = data
    except Exception as e:
        logging.warning(f"Usage file lỗi, bỏ qua: {e}")

def save_usage(path):
    if not path: return
    with usage_lock:
        snap = dict(usage)
    tmp = path + '.tmp'
    try:
        with open(tmp, 'w') as f: json.dump(snap, f, indent=2)
        os.replace(tmp, path)
    except Exception as e:
        logging.warning(f"Không lưu được usage: {e}")

def usage_get(username):
    if not username: return 0
    per = current_period()
    with usage_lock:
        r = usage.get(username)
        if not r or r.get('period') != per: return 0
        return int(r.get('bytes_used', 0))

def usage_add(username, n):
    if not username or n <= 0: return
    per = current_period()
    with usage_lock:
        r = usage.get(username)
        if not r or r.get('period') != per:
            r = {"period": per, "bytes_used": 0}
            usage[username] = r
        r['bytes_used'] = int(r.get('bytes_used', 0)) + int(n)

# ---------- Auth fail ----------
fail_counts = defaultdict(int)
fail_last = {}
blocked_until = {}
fail_lock = threading.Lock()

def record_auth_fail(ip, threshold):
    now = time.time()
    with fail_lock:
        last = fail_last.get(ip, 0)
        if last and now - last < 2.0: return
        if last and now - last > AUTH_FAIL_WINDOW:
            fail_counts[ip] = 0
        fail_last[ip] = now
        fail_counts[ip] += 1
        if fail_counts[ip] >= threshold:
            blocked_until[ip] = now + AUTH_BLOCK_SECONDS
            fail_counts[ip] = 0
            logging.warning(f"{RED}IP {ip} bị chặn {AUTH_BLOCK_SECONDS}s do sai xác thực nhiều lần{RESET}")

def reset_auth_fail(ip):
    with fail_lock:
        fail_counts.pop(ip, None); fail_last.pop(ip, None); blocked_until.pop(ip, None)

def is_auth_blocked(ip):
    with fail_lock:
        until = blocked_until.get(ip)
        if not until: return False
        if time.time() > until:
            blocked_until.pop(ip, None); return False
        return True

# ---------- IP allow/deny ----------
def is_ip_allowed(ip_str):
    with cidr_lock:
        allow, deny = list(allowed_cidrs), list(denied_cidrs)
    if ip_in_nets(ip_str, deny): return False
    if not allow: return True
    return ip_in_nets(ip_str, allow)

# ---------- API tokens ----------
def hash_api_token(tok): return hashlib.sha256(tok.encode()).hexdigest()

def check_api_token(tok):
    if not tok: return None
    h = hash_api_token(tok)
    with cfg_lock:
        for t in cfg.api_tokens:
            if ct_equal(t.get('token_hash',''), h):
                return t.get('name', 'unknown')
    return None

# ---------- User lookup ----------
def get_user_cfg(username):
    if not username: return None
    with cfg_lock:
        for u in cfg.users:
            if u.get('username') == username: return u
    return None

def count_user_conns(username):
    with active_lock:
        return sum(1 for c in active_conns.values() if c.username == username)

def check_user_limits(username):
    if not username: return True, ""
    u = get_user_cfg(username)
    if not u: return True, ""
    maxc = int(u.get('max_connections', 0) or 0)
    quota = int(u.get('quota_bytes_per_month', 0) or 0)
    if maxc > 0 and count_user_conns(username) >= maxc:
        return False, f"đã đạt giới hạn {maxc} connection đồng thời"
    if quota > 0 and usage_get(username) >= quota:
        return False, "đã vượt quota dung lượng tháng"
    return True, ""

# ---------- THROTTLE (MỚI) ----------
def _throttle(ci, n):
    """Sleep ~ n/rate giây nếu ci.rate_bps > 0. Giới hạn cap 1.5s để kick vẫn kịp."""
    if ci is None or n <= 0: return
    r = ci.rate_bps
    if r <= 0: return
    delay = n / r
    if delay > 1.5: delay = 1.5
    if delay > 0.0005:
        time.sleep(delay)

# ====================== CONFIG LOAD/SAVE ======================
def save_config_locked():
    tmp = config_path + '.tmp'
    try:
        with open(tmp, 'w') as f:
            json.dump(cfg.to_dict(), f, indent=2)
        os.chmod(tmp, 0o600)
        os.replace(tmp, config_path)
        return None
    except Exception as e:
        return str(e)

def load_or_init_config(path, fallback_user, fallback_pass):
    global cfg, dashboard_user, dashboard_hash
    if os.path.exists(path):
        try:
            with open(path, 'r') as f: data = json.load(f)
            c = AppConfig(data)
            if not c.dashboard_user or not c.dashboard_password_hash:
                raise ValueError("thiếu dashboard_user/dashboard_password_hash")
            cfg = c
            dashboard_user = cfg.dashboard_user
            dashboard_hash = cfg.dashboard_password_hash
            return False
        except Exception as e:
            raise RuntimeError(f"config file {path} không hợp lệ: {e}")
    new_hash = hash_password(fallback_pass)
    cfg = AppConfig({'dashboard_user': fallback_user, 'dashboard_password_hash': new_hash})
    dashboard_user = fallback_user
    dashboard_hash = new_hash
    with cfg_lock:
        save_config_locked()
    return True

def reload_config(source):
    global cfg, dashboard_user, dashboard_hash, allowed_cidrs, denied_cidrs
    global upstream_proxies, upstream_index
    ev = {"t": int(time.time()), "source": source, "success": False}
    try:
        with open(config_path, 'r') as f: data = json.load(f)
    except Exception as e:
        ev["error"] = f"đọc file thất bại: {e}"
        record_reload(ev); return False, ev["error"]
    try:
        new_cfg = AppConfig(data)
        if not new_cfg.dashboard_user or not new_cfg.dashboard_password_hash:
            raise ValueError("thiếu dashboard_user/dashboard_password_hash")
    except Exception as e:
        ev["error"] = f"config không hợp lệ: {e}"
        record_reload(ev); return False, ev["error"]

    na, inv_a = parse_cidrs(new_cfg.allow_list)
    nd, inv_d = parse_cidrs(new_cfg.deny_list)
    invalid = inv_a + inv_d

    with cidr_lock:
        allowed_cidrs, denied_cidrs = na, nd
    with upstream_lock:
        new_up = []
        for it in new_cfg.upstream_proxies:
            if ':' in it:
                h, p = it.rsplit(':', 1)
                try: new_up.append((h, int(p)))
                except: pass
        upstream_proxies = new_up
        if upstream_index >= len(upstream_proxies): upstream_index = 0
    with cfg_lock:
        cfg = new_cfg
        dashboard_user = new_cfg.dashboard_user
        dashboard_hash = new_cfg.dashboard_password_hash
        lim_map = {u['username']: int(u.get('max_bandwidth_bps', 0) or 0) for u in cfg.users}
    with active_lock:
        for c in active_conns.values():
            if c.username in lim_map: c.rate_bps = lim_map[c.username]

    ev.update({"success": True, "allow_count": len(na), "deny_count": len(nd),
               "upstream_count": len(upstream_proxies), "user_count": len(new_cfg.users)})
    if invalid: ev["invalid_cidrs"] = invalid
    record_reload(ev)
    logging.info(f"Đã reload config ({source}): {len(na)} allow, {len(nd)} deny, "
                 f"{len(upstream_proxies)} upstream, {len(new_cfg.users)} user"
                 + (f" — CẢNH BÁO: {len(invalid)} CIDR sai" if invalid else ""))
    return True, None

# ====================== AUTH ======================
def proxy_auth_required(server):
    if server.auth_required: return True
    with cfg_lock:
        return cfg.require_proxy_auth or len(cfg.users) > 0

def authenticate_proxy_user(server, user, password):
    if server.username and user == server.username and password == server.password:
        return True, 0, user
    with cfg_lock:
        users = list(cfg.users)
    for u in users:
        if u.get('username') == user and verify_password_cached(password, u.get('password_hash','')):
            return True, int(u.get('max_bandwidth_bps', 0) or 0), user
    return False, 0, ''

# ====================== SERVER ======================
class ThreadedProxyServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True
    def __init__(self, addr, Handler, username="", password="", enable_udp=True,
                 upstreams=None, cert=None, key=None, dashboard_port=DASHBOARD_PORT,
                 dashboard_bind="0.0.0.0"):
        self.username = username or ""
        self.password = password or ""
        self.auth_required = bool(username and password)
        self.enable_udp = enable_udp
        self.executor = ThreadPoolExecutor(max_workers=MAX_CONNECTIONS)
        self.cert = cert; self.key = key
        self.dashboard_port = dashboard_port
        self.dashboard_bind = dashboard_bind
        super().__init__(addr, Handler)
    def process_request(self, req, addr): self.executor.submit(self.process_request_thread, req, addr)
    def server_close(self):
        self.executor.shutdown(wait=False)
        super().server_close()

class ProxyHandler(socketserver.StreamRequestHandler):
    def handle(self):
        cip, cport = self.client_address[:2]
        cip = normalize_ip(cip)
        try:
            with stats_lock:
                if stats["current"] >= MAX_CONNECTIONS: return
                stats["total"] += 1; stats["current"] += 1
            if not is_ip_allowed(cip):
                logging.warning(f"IP {cip} bị từ chối (whitelist/blacklist)"); return
            if is_auth_blocked(cip):
                logging.warning(f"IP {cip} đang bị chặn do auth fail"); return
            peek = self.connection.recv(1, socket.MSG_PEEK)
            if not peek: return
            fb = peek[0]
            if fb == SOCKS5_VER: self.handle_socks5()
            elif fb in HTTP_FIRST_BYTES:
                with stats_lock: stats["http"] += 1
                self.handle_http()
            else:
                logging.warning(f"Unknown protocol từ {cip}:{cport}")
        except Exception as e:
            logging.error(f"Handler error {cip}:{cport} → {e}")
        finally:
            with stats_lock: stats["current"] -= 1

    # ---------- SOCKS5 ----------
    def handle_socks5(self):
        cip, cport = self.client_address[:2]; cip = normalize_ip(cip)
        ci = None
        try:
            ver, nm = struct.unpack("!BB", self.connection.recv(2))
            if ver != 5: return
            methods = self.connection.recv(nm)
            need_auth = proxy_auth_required(self.server)
            want = 0x02 if need_auth else 0x00
            if want not in methods:
                self.connection.sendall(b'\x05\xff'); return
            self.connection.sendall(struct.pack("!BB", 5, want))
            username = ''; rate_bps = 0
            if need_auth:
                ok, rate_bps, username = self._socks5_auth()
                if not ok: return
                allowed, reason = check_user_limits(username)
                if not allowed:
                    logging.warning(f"SOCKS5 từ chối user '{username}': {reason}")
                    self._reply(0x02); return

            ver, cmd, _, atyp = struct.unpack("!BBBB", self.connection.recv(4))
            if cmd == SOCKS5_CMD_CONNECT:
                host, port = self._read_addr(atyp)
                if not host: self._reply(0x04); return
                target = f"{host}:{port}"
                logging.info(f"{GREEN}SOCKS5 TCP → {cip}:{cport} → {target}{RESET}")
                remote = self._connect_target(host, port)
                if not remote: self._reply(0x05); return
                bip, bport = remote.getsockname()[:2]
                self._reply(0x00, bip, bport)
                ci = ConnectionInfo(next_conn_id(), cip, cport, "SOCKS5_TCP",
                                    target, rate_bps, username, self.connection)
                with active_lock: active_conns[ci.id] = ci
                with stats_lock: stats["socks5_tcp"] += 1
                self._tunnel(self.connection, remote, ci)
            elif cmd == SOCKS5_CMD_UDP:
                if not self.server.enable_udp: self._reply(0x07); return
                self._handle_udp_associate(cip, cport, username, rate_bps, atyp)
            else:
                self._reply(0x07)
        except Exception as e:
            logging.error(f"SOCKS5 error: {e}")
        finally:
            if ci:
                with active_lock: active_conns.pop(ci.id, None)

    # ---------- SOCKS5 UDP ----------
    def _handle_udp_associate(self, cip, cport, username, rate_bps, atyp):
        host, port = self._read_addr(atyp)
        target = f"UDP:{host}:{port}" if host else "UDP:any"
        logging.info(f"{PURPLE}UDP Associate → {cip}:{cport} → {target}{RESET}")

        family = socket.AF_INET6 if ':' in cip else socket.AF_INET
        try:
            relay = socket.socket(family, socket.SOCK_DGRAM)
            relay.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            relay.bind(('::' if family == socket.AF_INET6 else '0.0.0.0', 0))
            relay.setblocking(False)
        except Exception as e:
            logging.error(f"{RED}UDP relay bind failed: {e}{RESET}")
            self._reply(0x01); return

        relay_port = relay.getsockname()[1]
        logging.info(f"{PURPLE}UDP relay bound port {relay_port}{RESET}")

        key = f"{cip}:{cport}:{relay_port}"
        ci = ConnectionInfo(next_conn_id(), cip, cport, "SOCKS5_UDP",
                            target, rate_bps, username, self.connection)
        with udp_lock:
            udp_assocs[key] = {
                "client_addr": (cip, cport),
                "relay_port": relay_port,
                "active": True,
                "last_activity": time.time(),
                "dest_count": 0,
                "username": username,
            }
        with active_lock: active_conns[ci.id] = ci
        with stats_lock:
            stats["udp_assocs"] += 1
            stats["socks5_udp"] += 1

        self._reply(0x00, cip, relay_port)
        logging.info(f"{PURPLE}UDP reply sent → client dùng {cip}:{relay_port}{RESET}")

        client_udp = None
        dest_map = {}
        last_activity = time.time()

        try:
            while not shutdown_flag.is_set():
                if time.time() - last_activity > UDP_IDLE_TIMEOUT:
                    logging.info(f"UDP association idle-expired ({cip}:{cport})")
                    break
                try:
                    r, _, e = select.select(
                        [self.connection, relay], [], [self.connection, relay], 1)
                except (OSError, ValueError):
                    break
                if e: break
                for s in r:
                    if s is self.connection:
                        try: d = self.connection.recv(1024)
                        except OSError: return
                        if not d:
                            logging.info(f"UDP control TCP closed ({cip}:{cport})")
                            return
                    else:
                        try:
                            data, addr = relay.recvfrom(UDP_BUFFER_SIZE)
                        except OSError:
                            continue
                        last_activity = time.time()
                        with udp_lock:
                            rec = udp_assocs.get(key)
                            if rec: rec["last_activity"] = last_activity

                        addr_ip = normalize_ip(addr[0])
                        if client_udp is None:
                            if addr_ip != cip:
                                logging.warning(
                                    f"{RED}UDP: bỏ packet từ {addr} "
                                    f"(IP không khớp client TCP {cip}){RESET}")
                                continue
                            client_udp = addr
                            logging.info(f"{PURPLE}UDP client learned: {addr}{RESET}")

                        if addr == client_udp:
                            self._udp_to_dest(relay, data, dest_map, ci, key)
                        else:
                            self._udp_to_client(relay, data, addr, client_udp, dest_map, ci)
        finally:
            try: relay.close()
            except: pass
            with udp_lock: udp_assocs.pop(key, None)
            with active_lock: active_conns.pop(ci.id, None)
            with stats_lock:
                if stats["udp_assocs"] > 0: stats["udp_assocs"] -= 1
            logging.info(f"UDP association ended ({cip}:{cport})")

    def _udp_to_dest(self, relay, data, dest_map, ci, key):
        if len(data) < 4 or data[2] != 0: return
        atyp = data[3]; pos = 4
        try:
            if atyp == 1:
                if len(data) < pos + 6: return
                host = socket.inet_ntoa(data[pos:pos+4]); pos += 4
            elif atyp == 3:
                if len(data) < pos + 1: return
                ln = data[pos]; pos += 1
                if len(data) < pos + ln + 2: return
                host = data[pos:pos+ln].decode('idna', errors='ignore'); pos += ln
            elif atyp == 4:
                if len(data) < pos + 18: return
                host = socket.inet_ntop(socket.AF_INET6, data[pos:pos+16]); pos += 16
            else:
                logging.warning(f"UDP unknown atyp={atyp}"); return
            port = struct.unpack('!H', data[pos:pos+2])[0]; pos += 2
            payload = data[pos:]

            dest_ip = _resolve_udp_target(host, port)
            if dest_ip is None:
                logging.warning(f"{RED}UDP relay: bỏ target không hợp lệ/bị chặn: {host}:{port}{RESET}")
                return
            dest = (dest_ip, port)

            try:
                relay.sendto(payload, dest)
            except Exception as e:
                logging.warning(f"{RED}UDP sendto {dest_ip}:{port} failed: {e}{RESET}")
                return

            if len(dest_map) >= UDP_DEST_MAX:
                logging.warning(f"{YELLOW}UDP dest_map đầy ({UDP_DEST_MAX}) — clear{RESET}")
                dest_map.clear()

            is_new = dest not in dest_map
            dest_map[dest] = time.time()
            if is_new:
                with udp_lock:
                    rec = udp_assocs.get(key)
                    if rec: rec["dest_count"] = len(dest_map)

            with stats_lock: stats["udp_up"] += len(payload)
            usage_add(ci.username, len(payload))
        except Exception as e:
            logging.warning(f"UDP forward error: {e}")

    def _udp_to_client(self, relay, data, remote_addr, client_udp, dest_map, ci):
        remote_ip = normalize_ip(remote_addr[0])
        lookup = (remote_ip, remote_addr[1])
        if lookup not in dest_map:
            return
        try:
            if ':' in remote_ip:
                atyp = 4; bin_addr = socket.inet_pton(socket.AF_INET6, remote_ip)
            else:
                atyp = 1; bin_addr = socket.inet_pton(socket.AF_INET, remote_ip)
            hdr = struct.pack('!HBB', 0, 0, atyp) + bin_addr + struct.pack('!H', remote_addr[1])
            try:
                relay.sendto(hdr + data, client_udp)
            except Exception as e:
                logging.warning(f"{RED}UDP reply→client failed: {e}{RESET}")
                return
            with stats_lock: stats["udp_down"] += len(data)
            usage_add(ci.username, len(data))
        except Exception as e:
            logging.warning(f"UDP reply error: {e}")

    # ---------- SOCKS5 auth / addr / reply ----------
    def _socks5_auth(self):
        try:
            if self.connection.recv(1)[0] != 1:
                self.connection.sendall(b'\x01\xff'); return False, 0, ''
            ulen = self.connection.recv(1)[0]; u = self.connection.recv(ulen).decode()
            plen = self.connection.recv(1)[0]; p = self.connection.recv(plen).decode()
            ok, rate, uname = authenticate_proxy_user(self.server, u, p)
            self.connection.sendall(b'\x01\x00' if ok else b'\x01\xff')
            ip = normalize_ip(self.client_address[0])
            if not ok:
                logging.warning(f"{RED}SOCKS5 auth fail from {ip}{RESET}")
                with stats_lock: stats["auth_fail"] += 1
                record_auth_fail(ip, AUTH_FAIL_THRESHOLD)
                return False, 0, ''
            reset_auth_fail(ip)
            return True, rate, uname
        except:
            try: self.connection.sendall(b'\x01\xff')
            except: pass
            return False, 0, ''

    def _read_addr(self, atyp):
        try:
            if atyp == 1: h = socket.inet_ntop(socket.AF_INET, self.connection.recv(4))
            elif atyp == 3:
                ln = self.connection.recv(1)[0]
                h = self.connection.recv(ln).decode('idna', errors='ignore')
            elif atyp == 4: h = socket.inet_ntop(socket.AF_INET6, self.connection.recv(16))
            else: return None, 0
            p = struct.unpack("!H", self.connection.recv(2))[0]
            return h, p
        except: return None, 0

    def _reply(self, rep, addr="0.0.0.0", port=0):
        try:
            addr = normalize_ip(addr)
            if ':' in addr:
                bin_addr = socket.inet_pton(socket.AF_INET6, addr); atyp = 4
            else:
                bin_addr = socket.inet_pton(socket.AF_INET, addr); atyp = 1
            self.connection.sendall(struct.pack("!BBBB", 5, rep, 0, atyp) + bin_addr + struct.pack("!H", port))
        except Exception as e:
            logging.debug(f"reply error: {e}")

    # ---------- HTTP ----------
    def handle_http(self):
        cip, cport = self.client_address[:2]; cip = normalize_ip(cip)
        remote = None; ci = None
        try:
            rl = self.rfile.readline(BUFFER_SIZE).decode('latin-1', errors='ignore').strip()
            if not rl: return
            parts = rl.split()
            if len(parts) < 2: return
            method, url = parts[0].upper(), parts[1]
            headers = {}
            for _ in range(200):
                line = self.rfile.readline(BUFFER_SIZE).decode('latin-1', errors='ignore').rstrip('\r\n')
                if not line: break
                if ':' in line:
                    k, v = line.split(':', 1); headers[k.strip().lower()] = v.strip()
            username = ''; rate_bps = 0
            if proxy_auth_required(self.server):
                ok, rate_bps, username = self._http_auth(headers)
                if not ok:
                    self.wfile.write(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Proxy\"\r\n\r\n")
                    self.wfile.flush()
                    with stats_lock: stats["auth_fail"] += 1
                    record_auth_fail(cip, AUTH_FAIL_THRESHOLD)
                    return
                reset_auth_fail(cip)
                allowed, reason = check_user_limits(username)
                if not allowed:
                    self.wfile.write(f"HTTP/1.1 429 Too Many Requests\r\n\r\n{reason}".encode()); self.wfile.flush(); return

            if method == "CONNECT":
                hp = url.split(':', 1)
                host = hp[0]; port = int(hp[1]) if len(hp) > 1 else 443
            else:
                parsed = urlparse(url if url.startswith(('http://','https://')) else 'http://'+url)
                host = parsed.hostname
                port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            target = f"{host}:{port}"
            logging.info(f"{GREEN}HTTP {method} → {cip}:{cport} → {target}{RESET}")
            ci = ConnectionInfo(next_conn_id(), cip, cport, "HTTP", target, rate_bps, username, self.connection)
            with active_lock: active_conns[ci.id] = ci

            remote = self._connect_target(host, port)
            if not remote:
                self.wfile.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n"); self.wfile.flush(); return
            if method == "CONNECT":
                self.wfile.write(b"HTTP/1.1 200 Connection Established\r\n\r\n"); self.wfile.flush()
                self._tunnel(self.connection, remote, ci)
            else:
                self._forward_http(method, url, headers, remote, ci)
                self._forward_response(remote, self.connection, ci)
        except Exception as e:
            logging.error(f"HTTP error: {e}")
        finally:
            if remote:
                try: remote.close()
                except: pass
            if ci:
                with active_lock: active_conns.pop(ci.id, None)

    def _http_auth(self, headers):
        a = headers.get('proxy-authorization', '')
        if not a.lower().startswith('basic '): return False, 0, ''
        try:
            cred = base64.b64decode(a[6:]).decode('utf-8', errors='ignore')
            u, p = cred.split(':', 1)
            return authenticate_proxy_user(self.server, u, p)
        except: return False, 0, ''

    def _forward_http(self, method, url, headers, remote, ci=None):
        parsed = urlparse(url if url.startswith(('http://','https://')) else 'http://'+url)
        path = parsed.path or '/'
        if parsed.query: path += '?' + parsed.query
        req = f"{method} {path} HTTP/1.1\r\n"
        if 'host' not in headers: req += f"Host: {parsed.hostname}\r\n"
        for k, v in headers.items():
            if k not in ('proxy-authorization','proxy-connection','connection'): req += f"{k.title()}: {v}\r\n"
        req += "Connection: close\r\n\r\n"
        remote.sendall(req.encode('latin-1'))
        if ci: ci.bytes_up += len(req); usage_add(ci.username, len(req))
        cl = headers.get('content-length')
        te = headers.get('transfer-encoding', '').lower()
        if cl:
            rem = int(cl)
            while rem > 0:
                ch = self.connection.recv(min(rem, BUFFER_SIZE))
                if not ch: break
                remote.sendall(ch)
                if ci: ci.bytes_up += len(ch); usage_add(ci.username, len(ch)); _throttle(ci, len(ch))
                rem -= len(ch)
        elif te == 'chunked':
            while True:
                line = self._read_line()
                if not line: break
                try: sz = int(line.strip().split(b';')[0], 16)
                except: break
                if sz == 0:
                    while True:
                        t = self._read_line()
                        if not t or t == b'\r\n': break
                    break
                d = self.connection.recv(sz)
                if len(d) != sz: break
                remote.sendall(d); self.connection.recv(2)
                if ci: ci.bytes_up += len(d); usage_add(ci.username, len(d)); _throttle(ci, len(d))

    def _read_line(self):
        line = b''
        while True:
            ch = self.connection.recv(1)
            if not ch: return None
            line += ch
            if line.endswith(b'\n'): return line

    def _forward_response(self, src, dst, ci):
        while True:
            try:
                r, _, e = select.select([src], [], [src], IDLE_TIMEOUT)
                if e or not r: break
                d = src.recv(BUFFER_SIZE)
                if not d: break
                dst.sendall(d)
                with stats_lock: stats["bytes_down"] += len(d)
                if ci:
                    ci.bytes_down += len(d)
                    usage_add(ci.username, len(d))
                    _throttle(ci, len(d))
            except Exception: break

    # ---------- Common ----------
    def _connect_target(self, host, port):
        global upstream_index
        # Upstream (tin cậy, không check SSRF)
        with upstream_lock:
            ups = list(upstream_proxies)
            start = upstream_index
        if ups:
            total = len(ups)
            alive_n = sum(1 for u in ups if upstream_health.get(f"{u[0]}:{u[1]}", True))
            for i in range(total):
                idx = (start + i) % total
                uh, up = ups[idx]
                key = f"{uh}:{up}"
                if alive_n > 0 and not upstream_health.get(key, True): continue
                with upstream_lock:
                    upstream_index = (idx + 1) % total
                s = self._try_connect(uh, up, attempts=1)
                if s:
                    upstream_health[key] = True
                    return s
                upstream_health[key] = False
        # Direct — check SSRF
        resolved = _resolve_tcp_target(host, port)
        if not resolved:
            logging.warning(f"{RED}Connect target {host}:{port} bị chặn bởi SSRF guard{RESET}")
            return None
        for ip_str, port2 in resolved:
            s = self._try_connect(ip_str, port2, attempts=2)
            if s: return s
        return None

    def _try_connect(self, host, port, attempts=None):
        attempts = attempts or RETRY_ATTEMPTS
        for i in range(attempts):
            try:
                s = socket.create_connection((host, port), timeout=CONNECTION_TIMEOUT)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                return s
            except Exception as e:
                if i == attempts - 1:
                    logging.warning(f"Connect failed {host}:{port} → {e}")
                time.sleep(min(0.5 * (i + 1), 4.0))
        return None

    def _tunnel(self, client, remote, ci):
        socks = [client, remote]
        while True:
            try:
                r, _, e = select.select(socks, [], socks, IDLE_TIMEOUT)
                if e or not r: break
                for s in r:
                    d = s.recv(BUFFER_SIZE)
                    if not d: return
                    if s == client:
                        remote.sendall(d)
                        with stats_lock: stats["bytes_up"] += len(d)
                        if ci:
                            ci.bytes_up += len(d); usage_add(ci.username, len(d))
                            _throttle(ci, len(d))
                    else:
                        client.sendall(d)
                        with stats_lock: stats["bytes_down"] += len(d)
                        if ci:
                            ci.bytes_down += len(d); usage_add(ci.username, len(d))
                            _throttle(ci, len(d))
            except Exception: break
        for s in (client, remote):
            try: s.close()
            except: pass

# ====================== DASHBOARD HTML ======================
DASH_HTML = r"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Proxy Dashboard</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#0f0f1a;--fg:#e0e0e0;--container-bg:#14141f;--box-bg:#1a1a2e;--box-hover:#22223b;--border:#2a2a3a;--border2:#28283a;--th-bg:#1e1e32;--muted:#9999bb;--muted2:#b4b4d4;--accent:#f0c27a;--btn-bg:#2a2a3a;--btn-border:#3a3a52;--btn-hover:#33334a;--badge-bg:#2a2a4a;--badge-fg:#c0c0e0;--danger-border:#7a3030;--danger-hover-bg:#4a1a1a;--danger-fg:#fca5a5;--ok-fg:#86efac}
html[data-theme="light"]{--bg:#f4f4f9;--fg:#1c1c2a;--container-bg:#fff;--box-bg:#f0f0f7;--box-hover:#e6e6f2;--border:#dcdce8;--border2:#e4e4f0;--th-bg:#ececf5;--muted:#52526a;--muted2:#33334a;--accent:#8a5010;--btn-bg:#ececf5;--btn-border:#c8c8dc;--btn-hover:#e0e0ee;--badge-bg:#e4e4f4;--badge-fg:#3f3f66;--danger-border:#e5a5a5;--danger-hover-bg:#fde2e2;--danger-fg:#b91c1c;--ok-fg:#15803d}
body{background:var(--bg);color:var(--fg);font-family:'Segoe UI','Roboto',monospace;padding:30px 20px;transition:background .2s,color .2s}
.container{max-width:1400px;margin:0 auto}
h1{font-size:2.2rem;font-weight:300;letter-spacing:1px;color:var(--accent);display:flex;align-items:center;gap:10px}
h1 span{background:var(--btn-bg);padding:0 12px;border-radius:30px;font-size:.8rem;color:var(--muted)}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:15px;margin:20px 0}
.stat-box{background:var(--box-bg);padding:14px 16px;border-radius:12px;border-left:4px solid #6c6c9a}
.stat-box:hover{background:var(--box-hover)}
.stat-label{font-size:.8rem;text-transform:uppercase;letter-spacing:.5px;color:var(--muted)}
.stat-value{font-size:1.7rem;font-weight:600;margin-top:4px}
.section{margin-top:30px;background:var(--container-bg);border-radius:14px;padding:20px 20px 10px;border:1px solid var(--border)}
.section-title-row{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;margin-bottom:15px}
.section-title{font-size:1.2rem;color:var(--muted2)}
.toolbar{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.toolbar input[type=text]{background:var(--box-bg);border:1px solid var(--border);border-radius:8px;padding:6px 10px;color:var(--fg);font-size:.85rem}
table{width:100%;border-collapse:collapse;font-size:.9rem}
th{text-align:left;padding:10px 8px;background:var(--th-bg);color:var(--muted);font-weight:500;white-space:nowrap}
td{padding:8px;border-bottom:1px solid var(--border2)}
tr:hover td{background:var(--box-bg)}
.badge{display:inline-block;padding:2px 12px;border-radius:20px;font-size:.7rem;font-weight:600;background:var(--badge-bg);color:var(--badge-fg)}
.badge.s5t{background:#1e3a5f;color:#7dd3fc}.badge.s5u{background:#3b1f4a;color:#d8b4fe}.badge.h{background:#2d4a2d;color:#86efac}
.header-bar{display:flex;align-items:center;justify-content:space-between;border-bottom:2px solid var(--border);padding-bottom:15px;margin-bottom:10px;flex-wrap:wrap;gap:10px}
.header-actions{display:flex;gap:8px;flex-wrap:wrap}
.btn{background:var(--btn-bg);color:var(--fg);border:1px solid var(--btn-border);padding:8px 16px;border-radius:8px;cursor:pointer;font-size:.85rem;transition:.2s}
.btn:hover{background:var(--btn-hover);border-color:var(--accent)}
.btn-sm{padding:4px 10px;font-size:.75rem}
.btn-danger{border-color:var(--danger-border);color:var(--danger-fg)}
.btn-danger:hover{background:var(--danger-hover-bg)}
.btn-primary{background:var(--accent);color:#1a1a2e;border-color:var(--accent);font-weight:600}
.modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.6);align-items:center;justify-content:center;z-index:100}
.modal-overlay.open{display:flex}
.modal{background:var(--container-bg);border:1px solid var(--border);border-radius:14px;padding:24px;width:400px;max-width:90vw;max-height:90vh;overflow:auto}
.modal h2{font-size:1.1rem;color:var(--accent);margin-bottom:16px}
.modal label{display:block;font-size:.8rem;color:var(--muted);margin:12px 0 4px}
.modal input,.modal textarea{width:100%;background:var(--box-bg);border:1px solid var(--border);border-radius:8px;padding:9px 10px;color:var(--fg);font-size:.9rem;font-family:inherit}
.modal input:focus,.modal textarea:focus{outline:none;border-color:var(--accent)}
.modal-actions{display:flex;gap:10px;margin-top:20px}.modal-actions .btn{flex:1}
.modal-msg{margin-top:12px;font-size:.82rem;min-height:18px}
.modal-msg.error{color:var(--danger-fg)}.modal-msg.success{color:var(--ok-fg)}
#trafficChart{width:100%;height:200px}
</style></head><body>
<div class="container">
<div class="header-bar"><h1>⚡ Proxy Pro <span>v6.3 (Py)</span></h1>
<div class="header-actions">
<button class="btn" id="themeToggleBtn" onclick="toggleTheme()">🌙 Theme</button>
<button class="btn" onclick="openPwModal()">🔒 Change Password</button>
</div></div>
<div id="statsGrid" class="stats-grid">Loading stats...</div>

<div class="section">
<div class="section-title-row">
<div class="section-title">📈 Real-time Traffic <span id="streamStatus" style="font-size:.75rem;color:var(--muted)">(connecting...)</span></div>
</div>
<canvas id="trafficChart"></canvas>
</div>

<div class="section">
<div class="section-title-row"><div class="section-title">🔗 Active Connections <span id="connCount"></span></div>
<div class="toolbar">
<input type="text" id="connFilter" placeholder="Filter..." oninput="renderConns()">
<button class="btn btn-sm" onclick="exportConns('csv')">⬇ CSV</button>
<button class="btn btn-sm" onclick="exportConns('json')">⬇ JSON</button>
</div></div>
<div id="connTable">Loading...</div>
</div>
<div class="section"><div class="section-title">👤 Proxy Users</div>
<div style="margin-bottom:8px"><button class="btn btn-sm" onclick="openUserModal()">+ Add / Update User</button></div>
<div id="usersTable">Loading...</div></div>
<div class="section"><div class="section-title">🌐 Network Rules</div>
<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px;margin-top:10px">
<div><label style="display:block;font-size:.8rem;color:var(--muted);margin-bottom:4px">Whitelist IP/CIDR</label>
<textarea id="netAllow" rows="5" style="width:100%;background:var(--box-bg);border:1px solid var(--border);border-radius:8px;padding:8px;color:var(--fg);font-family:monospace;font-size:.82rem"></textarea></div>
<div><label style="display:block;font-size:.8rem;color:var(--muted);margin-bottom:4px">Blacklist IP/CIDR</label>
<textarea id="netDeny" rows="5" style="width:100%;background:var(--box-bg);border:1px solid var(--border);border-radius:8px;padding:8px;color:var(--fg);font-family:monospace;font-size:.82rem"></textarea></div>
<div><label style="display:block;font-size:.8rem;color:var(--muted);margin-bottom:4px">Upstream (host:port)</label>
<textarea id="netUpstream" rows="5" style="width:100%;background:var(--box-bg);border:1px solid var(--border);border-radius:8px;padding:8px;color:var(--fg);font-family:monospace;font-size:.82rem"></textarea></div>
</div>
<div style="margin-top:10px;display:flex;gap:8px;flex-wrap:wrap">
<button class="btn btn-primary" onclick="saveNetwork()">Save & Apply</button>
<button class="btn" onclick="reloadFromDisk()">↻ Reload from disk</button>
</div>
<div class="modal-msg" id="netMsg"></div></div>
<div class="section"><div class="section-title">🕒 Reload History</div><div id="reloadTable">Loading...</div></div>
<div class="section"><div class="section-title">🔑 API Tokens</div>
<div style="margin-bottom:8px;font-size:.8rem;color:var(--muted)">Dùng <code>Authorization: Bearer &lt;token&gt;</code> cho script.</div>
<div style="margin-bottom:8px"><button class="btn btn-sm" onclick="openTokenModal()">+ Create Token</button></div>
<div id="tokensTable">Loading...</div></div>
<div class="section"><div class="section-title">📋 Audit Log</div><div id="auditTable">Loading...</div></div>
<div class="section"><div class="section-title">💾 Backup / Restore</div>
<div class="toolbar" style="margin-top:10px">
<a class="btn btn-sm" href="/api/config/export" download>⬇ Download Backup</a>
<input type="file" id="restoreFile" style="display:none" onchange="restoreConfig(event)">
<button class="btn btn-sm" onclick="document.getElementById('restoreFile').click()">⬆ Restore</button>
</div><div class="modal-msg" id="backupMsg"></div></div>
</div>

<div class="modal-overlay" id="userModalOverlay"><div class="modal">
<h2>👤 Add / Update Proxy User</h2>
<form id="userForm" onsubmit="return submitUser(event)">
<label>Username</label><input type="text" id="uUsername" required>
<label>Password (blank = giữ nguyên nếu sửa user cũ)</label><input type="password" id="uPassword">
<label>Max bandwidth KB/s (0 = unlimited)</label><input type="number" id="uBandwidth" value="0" min="0">
<label>Max conns (0 = unlimited)</label><input type="number" id="uMaxConn" value="0" min="0">
<label>Quota MB/tháng (0 = unlimited)</label><input type="number" id="uQuota" value="0" min="0">
<div class="modal-msg" id="userMsg"></div>
<div class="modal-actions"><button type="button" class="btn" onclick="closeUserModal()">Cancel</button>
<button type="submit" class="btn btn-primary">Save</button></div></form>
</div></div>

<div class="modal-overlay" id="tokenModalOverlay"><div class="modal">
<h2>🔑 Create API Token</h2>
<form id="tokenForm" onsubmit="return submitToken(event)">
<label>Token name</label><input type="text" id="tName" required>
<div class="modal-msg" id="tokenMsg"></div>
<div id="tokenResultBox" style="display:none;margin-top:12px;padding:10px;background:var(--box-bg);border-radius:8px">
<div style="font-size:.78rem;color:var(--danger-fg);margin-bottom:6px">⚠️ Chỉ hiện MỘT LẦN:</div>
<code id="tokenResultValue" style="word-break:break-all;font-size:.8rem"></code></div>
<div class="modal-actions"><button type="button" class="btn" onclick="closeTokenModal()">Close</button>
<button type="submit" class="btn btn-primary" id="tokenSubmitBtn">Create</button></div></form>
</div></div>

<div class="modal-overlay" id="pwModalOverlay"><div class="modal">
<h2>🔒 Change Dashboard Credentials</h2>
<form id="pwForm" onsubmit="return submitPw(event)">
<label>Current password</label><input type="password" id="curPass" required>
<label>New username (blank = giữ nguyên)</label><input type="text" id="newUser">
<label>New password (min 8)</label><input type="password" id="newPass" minlength="8" required>
<label>Confirm</label><input type="password" id="newPass2" minlength="8" required>
<div class="modal-msg" id="pwMsg"></div>
<div class="modal-actions"><button type="button" class="btn" onclick="closePwModal()">Cancel</button>
<button type="submit" class="btn btn-primary">Save</button></div></form>
</div></div>

<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js"></script>
<script>
let lastConns=[];
let trafficChart=null;
const CHART_MAX_POINTS=150;
function esc(v){return String(v==null?'':v).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;')}
function fmtB(b){if(b==null)return '0 B';const u=['B','KiB','MiB','GiB','TiB'];let i=0;while(b>=1024&&i<u.length-1){b/=1024;i++}return b.toFixed(1)+' '+u[i]}
function fmtT(s){if(!s)return '00:00:00';const h=Math.floor(s/3600),m=Math.floor((s%3600)/60),x=Math.floor(s%60);return String(h).padStart(2,'0')+':'+String(m).padStart(2,'0')+':'+String(x).padStart(2,'0')}
function applyTheme(t){document.documentElement.setAttribute('data-theme',t);document.getElementById('themeToggleBtn').textContent=t==='light'?'☀️ Theme':'🌙 Theme';try{localStorage.setItem('dashboard-theme',t)}catch(e){}}
function toggleTheme(){const c=document.documentElement.getAttribute('data-theme')||'dark';applyTheme(c==='light'?'dark':'light')}
(function(){let s='dark';try{s=localStorage.getItem('dashboard-theme')||'dark'}catch(e){}applyTheme(s)})();

/* ---- CHART + SSE ---- */
function initChart(){
  if (typeof Chart === 'undefined') return;
  const ctx = document.getElementById('trafficChart').getContext('2d');
  const isDark = (document.documentElement.getAttribute('data-theme')||'dark') === 'dark';
  const fg = isDark ? '#b4b4d4' : '#33334a';
  const grid = isDark ? '#28283a' : '#e4e4f0';
  trafficChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: [],
      datasets: [
        { label: 'Upload (B/s)', data: [], borderColor: '#ea580c', backgroundColor: 'rgba(234,88,12,0.1)', tension: 0.3, pointRadius: 0, borderWidth: 2, fill: true },
        { label: 'Download (B/s)', data: [], borderColor: '#0891b2', backgroundColor: 'rgba(8,145,178,0.1)', tension: 0.3, pointRadius: 0, borderWidth: 2, fill: true }
      ]
    },
    options: {
      responsive: true, maintainAspectRatio: false, animation: false,
      interaction: { mode: 'index', intersect: false },
      scales: {
        x: { ticks: { color: fg, maxTicksLimit: 10 }, grid: { color: grid } },
        y: { ticks: { color: fg, callback: v => fmtB(v)+'/s' }, grid: { color: grid }, beginAtZero: true }
      },
      plugins: { legend: { labels: { color: fg } } }
    }
  });
}
function pushSample(s){
  if(!trafficChart) return;
  const label = new Date(s.t*1000).toLocaleTimeString();
  trafficChart.data.labels.push(label);
  trafficChart.data.datasets[0].data.push(s.up_bps);
  trafficChart.data.datasets[1].data.push(s.down_bps);
  if(trafficChart.data.labels.length > CHART_MAX_POINTS){
    trafficChart.data.labels.shift();
    trafficChart.data.datasets[0].data.shift();
    trafficChart.data.datasets[1].data.shift();
  }
  trafficChart.update('none');
}
function connectStream(){
  const statusEl = document.getElementById('streamStatus');
  if(typeof EventSource === 'undefined'){ statusEl.textContent='(no EventSource)'; return; }
  const es = new EventSource('/api/stream');
  es.addEventListener('history', e => {
    try { JSON.parse(e.data).forEach(pushSample); statusEl.textContent='(live)'; statusEl.style.color='var(--ok-fg)'; }
    catch(err){ console.error(err); }
  });
  es.addEventListener('sample', e => {
    try { pushSample(JSON.parse(e.data)); } catch(err){ console.error(err); }
  });
  es.onerror = () => { statusEl.textContent='(reconnecting...)'; statusEl.style.color='var(--danger-fg)'; };
  es.onopen = () => { statusEl.textContent='(live)'; statusEl.style.color='var(--ok-fg)'; };
}

/* ---- API helper ---- */
async function api(url,opt){
  const r = await fetch(url,opt); const t = await r.text();
  let d; try{ d=JSON.parse(t) }catch(e){ d={raw:t} }
  if(!r.ok) throw new Error(d.error||('HTTP '+r.status));
  return d;
}

async function refresh(){
  try{
    const d = await api('/api/all');
    const boxes = [
      ['Total', d.total], ['Active', d.active], ['SOCKS5 TCP', d.socks5_tcp],
      ['SOCKS5 UDP', d.socks5_udp], ['HTTP', d.http], ['UDP Assoc', d.udp_assocs||0],
      ['Bytes Up', fmtB(d.bytes_up)], ['Bytes Down', fmtB(d.bytes_down)],
      ['UDP Up', fmtB(d.udp_up)], ['UDP Down', fmtB(d.udp_down)],
      ['Uptime', fmtT(d.uptime)]
    ];
    document.getElementById('statsGrid').innerHTML = boxes.map(b=>`<div class="stat-box"><div class="stat-label">${b[0]}</div><div class="stat-value">${b[1]}</div></div>`).join('');
    lastConns = d.active_connections||[];
    renderConns();
  }catch(e){ document.getElementById('statsGrid').innerHTML='<div style="color:#dc2626">⚠️ '+esc(e.message)+'</div>' }
}
function renderConns(){
  const f = (document.getElementById('connFilter').value||'').toLowerCase().trim();
  let cs = lastConns.slice();
  if(f) cs = cs.filter(c=>(c.ip||'').toLowerCase().includes(f)||(c.target||'').toLowerCase().includes(f)||(c.type||'').toLowerCase().includes(f));
  document.getElementById('connCount').textContent='('+cs.length+')';
  if(!cs.length){ document.getElementById('connTable').innerHTML='<div style="padding:15px;color:var(--muted)">No active connections</div>'; return; }
  let h = '<table><thead><tr><th>IP</th><th>Port</th><th>Type</th><th>Target</th><th>User</th><th>Duration</th><th>Up</th><th>Down</th><th>Action</th></tr></thead><tbody>';
  cs.forEach(c=>{
    let cls = c.type==='SOCKS5_TCP'?'s5t':c.type==='SOCKS5_UDP'?'s5u':c.type==='HTTP'?'h':'';
    h += `<tr><td>${esc(c.ip)}</td><td>${esc(c.port)}</td><td><span class="badge ${cls}">${esc(c.type)}</span></td><td>${esc(c.target||'')}</td><td>${esc(c.user||'')}</td><td>${fmtT(c.duration)}</td><td>${fmtB(c.bytes_up)}</td><td>${fmtB(c.bytes_down)}</td><td><button class="btn btn-sm btn-danger" onclick="kick('${esc(c.id)}')">Kick</button></td></tr>`;
  });
  h+='</tbody></table>';
  document.getElementById('connTable').innerHTML = h;
}
async function kick(id){ try{ await api('/api/kick',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id})}); refresh(); }catch(e){ alert(e.message); } }
function exportConns(f){ window.location.href='/api/export?format='+f; }

async function refreshUsers(){
  try{
    const d = await api('/api/users');
    if(!d.users.length){ document.getElementById('usersTable').innerHTML='<div style="padding:15px;color:var(--muted)">No users yet</div>'; return; }
    let h = '<table><thead><tr><th>Username</th><th>Max BW</th><th>Max Conns</th><th>Quota/tháng</th><th>Used</th><th>Action</th></tr></thead><tbody>';
    d.users.forEach(u=>{
      const bw = u.max_bandwidth_bps>0 ? fmtB(u.max_bandwidth_bps)+'/s' : '∞';
      const mc = u.max_connections>0 ? u.max_connections : '∞';
      const q = u.quota_bytes_per_month>0 ? fmtB(u.quota_bytes_per_month) : '∞';
      const used = fmtB(u.usage_bytes_this_month||0);
      const over = u.quota_bytes_per_month>0 && (u.usage_bytes_this_month||0)>=u.quota_bytes_per_month;
      h += `<tr><td>${esc(u.username)}</td><td>${bw}</td><td>${mc}</td><td>${q}</td><td>${over?'<span style="color:var(--danger-fg)">'+used+' ⚠️</span>':used}</td><td><button class="btn btn-sm btn-danger" onclick="delUser('${esc(u.username)}')">Delete</button></td></tr>`;
    });
    h+='</tbody></table>';
    document.getElementById('usersTable').innerHTML = h;
  }catch(e){ document.getElementById('usersTable').innerHTML='<div style="padding:15px;color:var(--muted)">Failed to load</div>' }
}
async function delUser(u){ if(!confirm('Delete user "'+u+'"?'))return; try{ await api('/api/users/delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u})}); refreshUsers(); }catch(e){ alert(e.message) } }
function openUserModal(){ document.getElementById('userMsg').textContent=''; document.getElementById('userForm').reset(); document.getElementById('userModalOverlay').classList.add('open') }
function closeUserModal(){ document.getElementById('userModalOverlay').classList.remove('open') }
async function submitUser(e){
  e.preventDefault();
  const m = document.getElementById('userMsg');
  try{
    await api('/api/users',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({
      username: document.getElementById('uUsername').value.trim(),
      password: document.getElementById('uPassword').value,
      max_bandwidth_bps: Math.round((parseFloat(document.getElementById('uBandwidth').value)||0)*1024),
      max_connections: parseInt(document.getElementById('uMaxConn').value)||0,
      quota_bytes_per_month: Math.round((parseFloat(document.getElementById('uQuota').value)||0)*1024*1024)
    })});
    closeUserModal(); refreshUsers();
  }catch(err){ m.textContent=err.message; m.className='modal-msg error' }
  return false;
}

async function refreshNet(){
  try{
    const d = await api('/api/network-config');
    document.getElementById('netAllow').value = (d.allow_list||[]).join('\n');
    document.getElementById('netDeny').value = (d.deny_list||[]).join('\n');
    document.getElementById('netUpstream').value = (d.upstream_proxies||[]).join('\n');
  }catch(e){}
}
function lines(t){ return t.split('\n').map(s=>s.trim()).filter(s=>s) }
async function saveNetwork(){
  const m = document.getElementById('netMsg'); m.textContent='Saving...'; m.className='modal-msg';
  try{
    await api('/api/network-config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({
      allow_list: lines(document.getElementById('netAllow').value),
      deny_list: lines(document.getElementById('netDeny').value),
      upstream_proxies: lines(document.getElementById('netUpstream').value)
    })});
    m.textContent='Saved & applied'; m.className='modal-msg success'; refreshReload();
  }catch(e){ m.textContent=e.message; m.className='modal-msg error' }
}
async function reloadFromDisk(){
  const m = document.getElementById('netMsg'); m.textContent='Reloading...'; m.className='modal-msg';
  try{ await api('/api/reload',{method:'POST',headers:{'Content-Type':'application/json'}}); m.textContent='Reloaded'; m.className='modal-msg success'; refreshNet(); refreshReload(); }
  catch(e){ m.textContent=e.message; m.className='modal-msg error' }
}

async function refreshReload(){
  try{
    const d = await api('/api/reload-history');
    if(!d.history.length){ document.getElementById('reloadTable').innerHTML='<div style="padding:15px;color:var(--muted)">No reload events</div>'; return; }
    let h = '<table><thead><tr><th>Time</th><th>Source</th><th>Status</th><th>Details</th></tr></thead><tbody>';
    d.history.forEach(e=>{
      const t = new Date(e.t*1000).toLocaleString();
      const st = e.success ? '<span class="badge h">OK</span>' : '<span class="badge" style="background:var(--danger-hover-bg);color:var(--danger-fg)">FAIL</span>';
      let det = e.success ? `${e.allow_count} allow, ${e.deny_count} deny, ${e.upstream_count} upstream, ${e.user_count} users` : '<span style="color:var(--danger-fg)">'+esc(e.error||'')+'</span>';
      h += `<tr><td>${t}</td><td>${esc(e.source)}</td><td>${st}</td><td>${det}</td></tr>`;
    });
    h+='</tbody></table>';
    document.getElementById('reloadTable').innerHTML = h;
  }catch(e){}
}

async function refreshTokens(){
  try{
    const d = await api('/api/tokens');
    if(!d.tokens.length){ document.getElementById('tokensTable').innerHTML='<div style="padding:15px;color:var(--muted)">No tokens</div>'; return; }
    let h = '<table><thead><tr><th>Name</th><th>Created</th><th>Action</th></tr></thead><tbody>';
    d.tokens.forEach(t=>{ h += `<tr><td>${esc(t.name)}</td><td>${new Date(t.created_at*1000).toLocaleString()}</td><td><button class="btn btn-sm btn-danger" onclick="delToken('${esc(t.name)}')">Revoke</button></td></tr>`; });
    h+='</tbody></table>';
    document.getElementById('tokensTable').innerHTML = h;
  }catch(e){}
}
async function delToken(n){ if(!confirm('Revoke "'+n+'"?'))return; try{ await api('/api/tokens/delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:n})}); refreshTokens(); }catch(e){ alert(e.message) } }
function openTokenModal(){ document.getElementById('tokenMsg').textContent=''; document.getElementById('tokenResultBox').style.display='none'; document.getElementById('tokenForm').reset(); document.getElementById('tName').disabled=false; document.getElementById('tokenSubmitBtn').style.display='inline-block'; document.getElementById('tokenModalOverlay').classList.add('open') }
function closeTokenModal(){ document.getElementById('tokenModalOverlay').classList.remove('open'); refreshTokens() }
async function submitToken(e){
  e.preventDefault();
  const m = document.getElementById('tokenMsg');
  try{
    const d = await api('/api/tokens',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:document.getElementById('tName').value.trim()})});
    document.getElementById('tokenResultValue').textContent = d.token;
    document.getElementById('tokenResultBox').style.display = 'block';
    document.getElementById('tName').disabled = true; document.getElementById('tokenSubmitBtn').style.display = 'none';
  }catch(err){ m.textContent=err.message; m.className='modal-msg error' }
  return false;
}

async function refreshAudit(){
  try{
    const d = await api('/api/audit-log');
    if(!d.events.length){ document.getElementById('auditTable').innerHTML='<div style="padding:15px;color:var(--muted)">No events</div>'; return; }
    let h = '<table><thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Details</th></tr></thead><tbody>';
    d.events.forEach(e=>{ h += `<tr><td>${new Date(e.t*1000).toLocaleString()}</td><td>${esc(e.actor)}</td><td>${esc(e.action)}</td><td style="font-size:.8rem;color:var(--muted2)">${esc(e.details||'')}</td></tr>`; });
    h+='</tbody></table>';
    document.getElementById('auditTable').innerHTML = h;
  }catch(e){}
}

async function restoreConfig(e){
  const f = e.target.files[0]; if(!f) return;
  const m = document.getElementById('backupMsg');
  if(!confirm('Restore from '+f.name+'?')){ e.target.value=''; return; }
  m.textContent='Restoring...'; m.className='modal-msg';
  try{
    const text = await f.text();
    await api('/api/config/import',{method:'POST',headers:{'Content-Type':'application/json'},body:text});
    m.textContent='Restored. Reloading...'; m.className='modal-msg success';
    setTimeout(()=>location.reload(), 1500);
  }catch(err){ m.textContent=err.message; m.className='modal-msg error' }
  finally{ e.target.value=''; }
}

function openPwModal(){ document.getElementById('pwMsg').textContent=''; document.getElementById('pwForm').reset(); document.getElementById('pwModalOverlay').classList.add('open') }
function closePwModal(){ document.getElementById('pwModalOverlay').classList.remove('open') }
async function submitPw(e){
  e.preventDefault();
  const m = document.getElementById('pwMsg');
  const p1 = document.getElementById('newPass').value, p2 = document.getElementById('newPass2').value;
  if(p1!==p2){ m.textContent='Passwords do not match'; m.className='modal-msg error'; return false; }
  try{
    await api('/api/change-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({
      current_password: document.getElementById('curPass').value,
      new_username: document.getElementById('newUser').value.trim(),
      new_password: p1
    })});
    m.textContent='Changed. Reloading...'; m.className='modal-msg success';
    setTimeout(()=>location.reload(), 1500);
  }catch(err){ m.textContent=err.message; m.className='modal-msg error' }
  return false;
}

/* Khởi động */
document.addEventListener('DOMContentLoaded', ()=>{ initChart(); connectStream(); });
refresh(); refreshUsers(); refreshNet(); refreshReload(); refreshTokens(); refreshAudit();
setInterval(refresh, 5000);
setInterval(refreshUsers, 15000);
setInterval(refreshReload, 15000);
setInterval(refreshAudit, 15000);
</script></body></html>
"""

# ====================== DASHBOARD HANDLER ======================
class DashboardHandler(BaseHTTPRequestHandler):
    server_version = "ProxyDashboard/1.0"
    protocol_version = "HTTP/1.1"
    timeout = 30

    def log_message(self, *a): pass

    def _peer_ip(self):
        return normalize_ip(self.client_address[0])

    def _send(self, code, ctype, body, extra=None):
        try:
            self.send_response(code)
            self.send_header('Content-Type', ctype)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            if extra:
                for k, v in extra.items(): self.send_header(k, v)
            self.end_headers()
            if self.command != 'HEAD':
                self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json(self, code, obj, extra=None):
        self._send(code, 'application/json', json_dumps(obj), extra)

    def _err(self, code, msg):
        self._json(code, {"error": msg})

    def _check_auth(self):
        ip = self._peer_ip()
        if is_auth_blocked(ip):
            self._send(429, 'text/plain', b'Too Many Requests\n'); return False
        auth = self.headers.get('Authorization', '')

        if auth.startswith('Bearer '):
            tok = auth[7:]
            name = check_api_token(tok)
            if name:
                reset_auth_fail(ip)
                self._actor_name = 'token:' + name
                return True
            record_auth_fail(ip, DASH_AUTH_FAIL_THRESHOLD)
            self._send(401, 'text/plain', b'401 Unauthorized (invalid token)\n'); return False

        if not auth.startswith('Basic '):
            record_auth_fail(ip, DASH_AUTH_FAIL_THRESHOLD)
            self._send(401, 'text/plain', b'401 Unauthorized\n',
                       {'WWW-Authenticate': 'Basic realm="Dashboard"'})
            return False
        try:
            u, p = base64.b64decode(auth[6:]).decode().split(':', 1)
        except Exception:
            record_auth_fail(ip, DASH_AUTH_FAIL_THRESHOLD)
            self._send(401, 'text/plain', b'401 Unauthorized\n',
                       {'WWW-Authenticate': 'Basic realm="Dashboard"'})
            return False
        with cfg_lock:
            cu = cfg.dashboard_user; ch = cfg.dashboard_password_hash
        if not ct_equal(u, cu) or not verify_password_cached(p, ch):
            record_auth_fail(ip, DASH_AUTH_FAIL_THRESHOLD)
            self._send(401, 'text/plain', b'401 Unauthorized\n',
                       {'WWW-Authenticate': 'Basic realm="Dashboard"'})
            return False
        reset_auth_fail(ip)
        self._actor_name = 'dashboard:' + cu
        return True

    def _csrf_ok(self):
        m = self.command
        if m in ('GET', 'HEAD', 'OPTIONS'): return True
        sfs = self.headers.get('Sec-Fetch-Site', '')
        if sfs and sfs not in ('same-origin', 'none'): return False
        origin = self.headers.get('Origin', '')
        if origin:
            try:
                u = urlparse(origin)
                host_hdr = self.headers.get('Host', '')
                if u.hostname and u.hostname != host_hdr.split(':')[0]:
                    return False
            except: return False
        ct = self.headers.get('Content-Type', '').lower()
        return ct.startswith('application/json')

    def _read_body(self, limit=5*1024*1024):
        cl = int(self.headers.get('Content-Length', '0') or 0)
        if cl > limit: return None
        return self.rfile.read(cl) if cl > 0 else b''

    def _json_body(self, limit=65536):
        b = self._read_body(limit)
        if b is None: return None
        try: return json_loads(b)
        except Exception: return None

    def do_GET(self):
        p = urlparse(self.path).path
        if p == '/healthz':
            return self._health()
        if p == '/metrics':
            return self._metrics()
        if not self._check_auth(): return

        if p == '/':
            return self._send(200, 'text/html; charset=utf-8', DASH_HTML.encode())
        if p == '/stats':
            return self._json(200, self._stats_basic())
        if p == '/api/all':
            return self._json(200, self._stats_all())
        if p == '/api/stream':
            return self._stream()
        if p == '/api/audit-log':
            with audit_lock: evs = list(reversed(audit_log))
            return self._json(200, {"events": evs})
        if p == '/api/reload-history':
            with reload_lock: hist = list(reversed(reload_history))
            return self._json(200, {"history": hist})
        if p == '/api/users':
            with cfg_lock:
                out = [{
                    "username": u.get('username',''),
                    "max_bandwidth_bps": u.get('max_bandwidth_bps',0),
                    "max_connections": u.get('max_connections',0),
                    "quota_bytes_per_month": u.get('quota_bytes_per_month',0),
                    "usage_bytes_this_month": usage_get(u.get('username','')),
                } for u in cfg.users]
            return self._json(200, {"users": out})
        if p == '/api/tokens':
            with cfg_lock:
                out = [{"name": t.get('name',''), "created_at": t.get('created_at',0)} for t in cfg.api_tokens]
            return self._json(200, {"tokens": out})
        if p == '/api/network-config':
            with cfg_lock:
                return self._json(200, {
                    "allow_list": list(cfg.allow_list),
                    "deny_list": list(cfg.deny_list),
                    "upstream_proxies": list(cfg.upstream_proxies),
                })
        if p == '/api/export':
            return self._export_conns()
        if p == '/api/config/export':
            with cfg_lock: data = json.dumps(cfg.to_dict(), indent=2).encode()
            record_audit(self._actor_name, 'export_config_backup', '')
            fn = 'proxy_config_backup_' + time.strftime('%Y%m%d_%H%M%S') + '.json'
            return self._send(200, 'application/json', data,
                              {'Content-Disposition': f'attachment; filename={fn}'})
        return self._send(404, 'text/plain', b'404\n')

    def do_POST(self):
        p = urlparse(self.path).path
        if not self._check_auth(): return
        if not self._csrf_ok():
            return self._send(403, 'text/plain', b'403 CSRF\n')

        if p == '/api/kick': return self._kick()
        if p == '/api/users': return self._upsert_user()
        if p == '/api/users/delete': return self._delete_user()
        if p == '/api/tokens': return self._create_token()
        if p == '/api/tokens/delete': return self._delete_token()
        if p == '/api/change-password': return self._change_password()
        if p == '/api/reload': return self._do_reload()
        if p == '/api/network-config': return self._save_network()
        if p == '/api/config/import': return self._import_config()
        return self._send(404, 'text/plain', b'404\n')

    # ---------- NEW: healthz / metrics / stream / kick ----------
    def _health(self):
        if shutdown_flag.is_set():
            return self._send(503, 'application/json', b'{"status":"shutting_down"}')
        return self._send(200, 'application/json', b'{"status":"ok"}')

    def _metrics(self):
        with stats_lock: s = dict(stats)
        with active_lock: ac = len(active_conns)
        with udp_lock: ua = len(udp_assocs)
        up = time.time() - s['start']
        L = []
        def m(name, typ, val):
            L.append(f"# TYPE proxy_{name} {typ}\nproxy_{name} {val}")
        m('connections_total','counter', s['total'])
        m('connections_current','gauge', s['current'])
        m('connections_active','gauge', ac)
        m('socks5_tcp_total','counter', s['socks5_tcp'])
        m('socks5_udp_total','counter', s['socks5_udp'])
        m('http_requests_total','counter', s['http'])
        m('bytes_up_total','counter', s['bytes_up'])
        m('bytes_down_total','counter', s['bytes_down'])
        m('udp_bytes_up_total','counter', s['udp_up'])
        m('udp_bytes_down_total','counter', s['udp_down'])
        m('udp_associations','gauge', ua)
        m('auth_fail_total','counter', s['auth_fail'])
        m('uptime_seconds','gauge', f"{up:.0f}")
        self._send(200, 'text/plain; version=0.0.4; charset=utf-8', ("\n".join(L)+"\n").encode())

    def _stream(self):
        """SSE real-time traffic."""
        if len(_sse_clients) >= DASH_MAX_SSE:
            return self._err(503, "Too many streaming clients")
        try:
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Cache-Control', 'no-cache')
            self.send_header('Connection', 'keep-alive')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('X-Accel-Buffering', 'no')
            self.end_headers()
        except Exception:
            return
        # KHÔNG dùng Content-Length cho SSE — client tự đọc theo dòng trống.
        # BaseHTTPRequestHandler sẽ ghi raw header; Content-Length không có nghĩa.

        # Gửi history
        with _hist_lock:
            hist = list(_sample_history)
        try:
            payload = json_str(hist)
            self.wfile.write(f"event: history\ndata: {payload}\n\n".encode())
            self.wfile.flush()
        except Exception:
            return

        my_q = queue.Queue(maxsize=8)
        with _sse_lock:
            _sse_clients.add(my_q)
        last_keepalive = time.time()
        try:
            while not shutdown_flag.is_set():
                try:
                    sample = my_q.get(timeout=1)
                    self.wfile.write(f"event: sample\ndata: {json_str(sample)}\n\n".encode())
                    self.wfile.flush()
                    last_keepalive = time.time()
                except queue.Empty:
                    if time.time() - last_keepalive >= 15:
                        self.wfile.write(b": keepalive\n\n")
                        self.wfile.flush()
                        last_keepalive = time.time()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            with _sse_lock:
                _sse_clients.discard(my_q)

    def _kick(self):
        b = self._json_body(2048)
        if not b or not b.get('id'): return self._err(400, "Missing 'id'")
        cid = b['id']
        with active_lock: c = active_conns.get(cid)
        if not c: return self._err(404, "Connection not found")
        try:
            if c.conn:
                try: c.conn.shutdown(socket.SHUT_RDWR)
                except: pass
                try: c.conn.close()
                except: pass
        except: pass
        info = f"id={c.id} ip={c.ip} target={c.target} user={c.username}"
        logging.info(f"Dashboard kicked {info}")
        record_audit(self._actor_name, 'kick_connection', info)
        self._json(200, {"success": True, "id": cid})

    # ---------- EXISTING handlers ----------
    def _stats_basic(self):
        with stats_lock: d = dict(stats)
        with active_lock: d['active'] = len(active_conns)
        d['uptime'] = time.time() - d.pop('start', time.time())
        return d

    def _stats_all(self):
        d = self._stats_basic()
        with active_lock: conns = list(active_conns.values())
        d['active_connections'] = [{
            'id': c.id, 'ip': c.ip, 'port': c.port, 'type': c.conn_type,
            'target': c.target, 'user': c.username,
            'start_time': c.start_time, 'bytes_up': c.bytes_up, 'bytes_down': c.bytes_down,
            'duration': time.time() - c.start_time,
        } for c in conns]
        with upstream_lock:
            ups = [f"{h}:{p}" for h, p in upstream_proxies]
            idx = upstream_index
        d['upstream'] = {'proxies': ups, 'current_index': idx,
                         'status': [{'addr': u, 'alive': upstream_health.get(u, True)} for u in ups]}
        sysinfo = {}
        if HAVE_PSUTIL:
            try:
                sysinfo = {'cpu_percent': psutil.cpu_percent(interval=None),
                           'memory_percent': psutil.virtual_memory().percent}
            except: pass
        try: sysinfo['fd_limit'] = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
        except: pass
        d['system'] = sysinfo
        with udp_lock:
            d['udp_associations'] = {
                k: {'client_addr': list(v.get("client_addr", ("",""))),
                    'relay_port': v.get("relay_port", 0),
                    'active': v.get("active", False),
                    'last_activity': v.get("last_activity", 0),
                    'dest_count': v.get("dest_count", 0)}
                for k, v in udp_assocs.items()
            }
        return d

    def _upsert_user(self):
        b = self._json_body(4096)
        if not isinstance(b, dict): return self._err(400, "Invalid JSON body")
        uname = (b.get('username') or '').strip()
        if not uname: return self._err(400, "Username required")
        if len(uname) >= 64: return self._err(400, "Username too long")
        pwd = b.get('password') or ''
        if pwd and len(pwd) < 4: return self._err(400, "Password must be >= 4 chars")
        try:
            bw = int(b.get('max_bandwidth_bps', 0) or 0)
            mc = int(b.get('max_connections', 0) or 0)
            q = int(b.get('quota_bytes_per_month', 0) or 0)
        except: return self._err(400, "Invalid number")
        bw = max(0, bw); mc = max(0, mc); q = max(0, q)
        pwd_hash = hash_password(pwd) if pwd else None
        with cfg_lock:
            idx = next((i for i, u in enumerate(cfg.users) if u.get('username') == uname), -1)
            if idx >= 0:
                if pwd_hash: cfg.users[idx]['password_hash'] = pwd_hash
                cfg.users[idx]['max_bandwidth_bps'] = bw
                cfg.users[idx]['max_connections'] = mc
                cfg.users[idx]['quota_bytes_per_month'] = q
            else:
                if not pwd_hash: return self._err(400, "Password required for new user")
                cfg.users.append({
                    'username': uname, 'password_hash': pwd_hash,
                    'max_bandwidth_bps': bw, 'max_connections': mc,
                    'quota_bytes_per_month': q,
                })
                cfg.require_proxy_auth = True
            err = save_config_locked()
        if err: return self._err(500, f"Saved in memory but write failed: {err}")
        with active_lock:
            for c in active_conns.values():
                if c.username == uname: c.rate_bps = bw
        logging.info(f"Dashboard: upsert user '{uname}' (bw={bw}, mc={mc}, q={q})")
        record_audit(self._actor_name, 'upsert_user',
                     f"username={uname} bw={bw} mc={mc} q={q} pwd_changed={bool(pwd)}")
        self._json(200, {"success": True})

    def _delete_user(self):
        b = self._json_body(2048)
        uname = (b or {}).get('username')
        if not uname: return self._err(400, "Missing 'username'")
        with cfg_lock:
            before = len(cfg.users)
            cfg.users = [u for u in cfg.users if u.get('username') != uname]
            removed = len(cfg.users) < before
            err = save_config_locked() if removed else None
        if not removed: return self._err(404, "User not found")
        if err: return self._err(500, f"Remove ok but write failed: {err}")
        logging.info(f"Dashboard: deleted user '{uname}'")
        record_audit(self._actor_name, 'delete_user', f"username={uname}")
        self._json(200, {"success": True})

    def _create_token(self):
        b = self._json_body(2048)
        name = ((b or {}).get('name') or '').strip()
        if not name: return self._err(400, "Name required")
        if len(name) >= 64: return self._err(400, "Name too long")
        with cfg_lock:
            if any(t.get('name') == name for t in cfg.api_tokens):
                return self._err(409, "Token name exists")
            token = secrets.token_hex(32)
            cfg.api_tokens.append({
                'name': name, 'token_hash': hash_api_token(token),
                'created_at': int(time.time()),
            })
            err = save_config_locked()
        if err: return self._err(500, f"Saved but write failed: {err}")
        logging.info(f"Dashboard: created token '{name}'")
        record_audit(self._actor_name, 'create_api_token', f"name={name}")
        self._json(200, {"success": True, "token": token, "name": name})

    def _delete_token(self):
        b = self._json_body(2048)
        name = (b or {}).get('name')
        if not name: return self._err(400, "Missing 'name'")
        with cfg_lock:
            before = len(cfg.api_tokens)
            cfg.api_tokens = [t for t in cfg.api_tokens if t.get('name') != name]
            removed = len(cfg.api_tokens) < before
            err = save_config_locked() if removed else None
        if not removed: return self._err(404, "Token not found")
        if err: return self._err(500, f"Remove ok but write failed: {err}")
        record_audit(self._actor_name, 'revoke_api_token', f"name={name}")
        self._json(200, {"success": True})

    def _change_password(self):
        b = self._json_body(4096)
        if not isinstance(b, dict): return self._err(400, "Invalid JSON")
        cur = b.get('current_password', '')
        nu = (b.get('new_username', '') or '').strip()
        np = b.get('new_password', '')
        with cfg_lock:
            ch = cfg.dashboard_password_hash; cu = cfg.dashboard_user
        if not verify_password(cur, ch):
            return self._err(403, "Current password incorrect")
        if len(np) < 8: return self._err(400, "New password must be >= 8")
        if np == cur: return self._err(400, "New password must differ")
        new_hash = hash_password(np)
        global dashboard_user, dashboard_hash
        with cfg_lock:
            if nu: cfg.dashboard_user = nu
            cfg.dashboard_password_hash = new_hash
            dashboard_user = cfg.dashboard_user
            dashboard_hash = cfg.dashboard_password_hash
            err = save_config_locked()
        if err: logging.warning(f"Đổi mật khẩu OK nhưng ghi file lỗi: {err}")
        logging.info(f"Dashboard creds changed: {cu} -> {cfg.dashboard_user}")
        record_audit(self._actor_name, 'change_dashboard_password', f"user: {cu} -> {cfg.dashboard_user}")
        self._json(200, {"success": True, "username": cfg.dashboard_user})

    def _do_reload(self):
        ok, err = reload_config(self._actor_name)
        if not ok:
            record_audit(self._actor_name, 'reload_config', f"failed: {err}")
            return self._err(400, err or "reload failed")
        record_audit(self._actor_name, 'reload_config', 'success')
        self._json(200, {"success": True})

    def _save_network(self):
        b = self._json_body(65536)
        if not isinstance(b, dict): return self._err(400, "Invalid JSON")
        allow = b.get('allow_list', []) or []
        deny = b.get('deny_list', []) or []
        ups = b.get('upstream_proxies', []) or []
        with cfg_lock:
            cfg.allow_list = allow
            cfg.deny_list = deny
            cfg.upstream_proxies = ups
            err = save_config_locked()
        if err: return self._err(500, f"Saved but write failed: {err}")
        ok, rerr = reload_config(self._actor_name)
        if not ok:
            record_audit(self._actor_name, 'update_network_config', f"failed: {rerr}")
            return self._err(500, f"Saved but reload failed: {rerr}")
        record_audit(self._actor_name, 'update_network_config',
                     f"{len(allow)} allow, {len(deny)} deny, {len(ups)} upstream")
        self._json(200, {"success": True})

    def _import_config(self):
        b = self._read_body(5*1024*1024)
        if b is None: return self._err(413, "File too large")
        try: data = json_loads(b)
        except Exception as e: return self._err(400, f"Invalid JSON: {e}")
        if not isinstance(data, dict) or not data.get('dashboard_user') or not data.get('dashboard_password_hash'):
            return self._err(400, "Not a valid backup file")
        try: tmp_cfg = AppConfig(data)
        except Exception as e: return self._err(400, f"Invalid config: {e}")
        tmp = config_path + '.tmp'
        try:
            with open(tmp, 'w') as f: json.dump(tmp_cfg.to_dict(), f, indent=2)
            os.chmod(tmp, 0o600); os.replace(tmp, config_path)
        except Exception as e:
            return self._err(500, f"Write failed: {e}")
        ok, rerr = reload_config(self._actor_name)
        if not ok:
            record_audit(self._actor_name, 'import_config_backup', f"failed: {rerr}")
            return self._err(500, f"Imported but reload failed: {rerr}")
        record_audit(self._actor_name, 'import_config_backup',
                     f"{len(tmp_cfg.users)} users, {len(tmp_cfg.api_tokens)} tokens")
        self._json(200, {"success": True})

    def _export_conns(self):
        fmt = urllib.parse.parse_qs(urlparse(self.path).query).get('format', ['json'])[0]
        with active_lock: conns = list(active_conns.values())
        rows = [{'id': c.id, 'ip': c.ip, 'port': c.port, 'type': c.conn_type,
                 'target': c.target, 'user': c.username,
                 'bytes_up': c.bytes_up, 'bytes_down': c.bytes_down,
                 'duration': time.time() - c.start_time} for c in conns]
        if fmt == 'csv':
            buf = io.StringIO()
            w = csv.writer(buf)
            w.writerow(['id','ip','port','type','target','user','bytes_up','bytes_down','duration'])
            for r in rows: w.writerow([r['id'],r['ip'],r['port'],r['type'],r['target'],r['user'],r['bytes_up'],r['bytes_down'],f"{r['duration']:.1f}"])
            return self._send(200, 'text/csv', buf.getvalue().encode(),
                              {'Content-Disposition': 'attachment; filename=connections.csv'})
        return self._send(200, 'application/json', json_dumps(rows),
                          {'Content-Disposition': 'attachment; filename=connections.json'})

# ====================== MONITOR ======================
def realtime_stats():
    """Terminal 2-line display (như C/Go)."""
    while not shutdown_flag.is_set():
        time.sleep(2)
        try:
            with stats_lock: s = dict(stats)
            up = time.time() - s['start']
            h, m, sec = int(up//3600), int((up%3600)//60), int(up%60)
            with active_lock:
                cur = len(active_conns)
                s5t = sum(1 for c in active_conns.values() if c.conn_type == "SOCKS5_TCP")
                s5u = sum(1 for c in active_conns.values() if c.conn_type == "SOCKS5_UDP")
                hh = sum(1 for c in active_conns.values() if c.conn_type == "HTTP")
            with udp_lock: ua = len(udp_assocs)
            cpu = mem = None
            if HAVE_PSUTIL:
                try: cpu = psutil.cpu_percent(interval=None); mem = psutil.virtual_memory().percent
                except: pass
            cs = f"{cpu:>5.1f}%" if cpu is not None else "  N/A "
            ms = f"{mem:>5.1f}%" if mem is not None else "  N/A "
            l1 = (f"{YELLOW}↑TCP {format_bytes(s['bytes_up']):>9} ↓TCP {format_bytes(s['bytes_down']):>9} │ "
                  f"↑UDP {format_bytes(s['udp_up']):>7} ↓UDP {format_bytes(s['udp_down']):>7}{RESET}")
            l2 = (f"{CYAN}Active: {cur:>4} (TCP:{s5t:>3} UDP:{s5u:>3} HTTP:{hh:>3}) │ "
                  f"UDP Assoc: {ua:>3} │ CPU {cs}  MEM {ms} │ Uptime {h:02d}:{m:02d}:{sec:02d}{RESET}")
            sys.stdout.write('\033[2A\033[2K' + l1 + '\n\033[2K' + l2 + '\n')
            sys.stdout.flush()
        except Exception:
            pass

# ---- NEW: SSE sample broadcaster thread ----
def stats_reporter():
    """Mỗi 2s: tính up_bps/down_bps, push vào history + broadcast tới mọi SSE client."""
    last_up = last_down = 0
    first = True
    interval = 2.0
    while not shutdown_flag.is_set():
        time.sleep(interval)
        try:
            with stats_lock:
                up = stats['bytes_up']; down = stats['bytes_down']
            up_bps = 0 if first else int((up - last_up) / interval)
            down_bps = 0 if first else int((down - last_down) / interval)
            last_up = up; last_down = down; first = False
            with active_lock: ac = len(active_conns)
            with udp_lock: ua = len(udp_assocs)
            sample = {
                "t": int(time.time()),
                "up_bps": up_bps,
                "down_bps": down_bps,
                "active": ac,
                "udp_assocs": ua,
            }
            with _hist_lock:
                _sample_history.append(sample)
            # Broadcast tới các SSE client (không block)
            with _sse_lock:
                clients = list(_sse_clients)
            for q in clients:
                try: q.put_nowait(sample)
                except queue.Full: pass
        except Exception:
            pass

def upstream_health_loop():
    while not shutdown_flag.is_set():
        time.sleep(15)
        with upstream_lock:
            ups = list(upstream_proxies)
        for h, p in ups:
            try:
                s = socket.create_connection((h, p), timeout=3)
                s.close()
                upstream_health[f"{h}:{p}"] = True
            except Exception:
                upstream_health[f"{h}:{p}"] = False

def enforce_quota_loop():
    while not shutdown_flag.is_set():
        time.sleep(10)
        with cfg_lock:
            quotas = {u['username']: int(u.get('quota_bytes_per_month', 0) or 0) for u in cfg.users}
        for uname, q in quotas.items():
            if q <= 0 or usage_get(uname) < q: continue
            with active_lock:
                victims = [c for c in active_conns.values() if c.username == uname]
            for c in victims:
                try:
                    if c.conn: c.conn.close()
                except: pass
            if victims:
                logging.warning(f"{RED}Ngắt {len(victims)} conn của user {uname} do vượt quota{RESET}")

def usage_save_loop():
    while not shutdown_flag.is_set():
        time.sleep(30)
        save_usage(usage_path)

# ====================== SIGNAL ======================
shutdown_flag = threading.Event()

def shutdown_handler(signum, frame):
    if shutdown_flag.is_set(): return
    shutdown_flag.set()

def hup_handler(signum, frame):
    threading.Thread(target=lambda: reload_config("SIGHUP"), daemon=True).start()

# ====================== MAIN ======================
def main():
    global config_path, usage_path, dashboard_user, dashboard_hash
    global allowed_cidrs, denied_cidrs, upstream_proxies
    ap = argparse.ArgumentParser(description="Universal Proxy Pro v6.3 (Python, FULL parity)")
    ap.add_argument("-l", "--listen", default="0.0.0.0")
    ap.add_argument("-p", "--port", type=int, default=1080)
    ap.add_argument("-u", "--username", default="")
    ap.add_argument("-P", "--password", default="")
    ap.add_argument("--no-udp", action="store_true")
    ap.add_argument("--upstream", default="")
    ap.add_argument("--cert"); ap.add_argument("--key")
    ap.add_argument("--dashboard-port", type=int, default=DASHBOARD_PORT)
    ap.add_argument("--dashboard-bind", default="0.0.0.0")
    ap.add_argument("--config", default="proxy_config.json")
    ap.add_argument("--usage-file", default="proxy_usage.json")
    ap.add_argument("--dashboard-user", default="admin")
    ap.add_argument("--dashboard-pass", default="")
    ap.add_argument("--allow", default="")
    ap.add_argument("--deny", default="")
    args = ap.parse_args()

    config_path = args.config
    usage_path = args.usage_file

    try: resource.setrlimit(resource.RLIMIT_NOFILE, (65536, 65536))
    except: pass

    load_usage(usage_path)

    init_user = args.dashboard_user or 'admin'
    init_pass = args.dashboard_pass
    generated_pass = None
    if not os.path.exists(config_path) and not init_pass:
        init_pass = secrets.token_hex(8)
        generated_pass = init_pass

    try:
        was_created = load_or_init_config(config_path, init_user, init_pass or 'changeme')
    except Exception as e:
        logging.error(f"{RED}{e}{RESET}"); sys.exit(1)

    if was_created and generated_pass:
        logging.warning(f"{RED}Dashboard lần đầu — user: {init_user} | password: {generated_pass}{RESET}")
        logging.warning(f"{RED}(chỉ hiện MỘT LẦN — đổi ngay trên dashboard){RESET}")

    if was_created:
        with cfg_lock:
            cfg.allow_list = [x.strip() for x in args.allow.split(',') if x.strip()]
            cfg.deny_list = [x.strip() for x in args.deny.split(',') if x.strip()]
            cfg.upstream_proxies = [x.strip() for x in args.upstream.split(',') if x.strip()]
            save_config_locked()

    na, _ = parse_cidrs(cfg.allow_list)
    nd, _ = parse_cidrs(cfg.deny_list)
    with cidr_lock: allowed_cidrs, denied_cidrs = na, nd
    new_up = []
    for it in cfg.upstream_proxies:
        if ':' in it:
            h, p = it.rsplit(':', 1)
            try: new_up.append((h, int(p)))
            except: pass
    with upstream_lock: upstream_proxies = new_up

    if dashboard_user == 'admin' and verify_password('admin', dashboard_hash):
        logging.warning(f"{RED}Dashboard đang dùng admin/admin — đổi ngay!{RESET}")

    server = ThreadedProxyServer(
        (args.listen, args.port), ProxyHandler,
        username=args.username, password=args.password,
        enable_udp=not args.no_udp,
        upstreams=new_up,
        cert=args.cert, key=args.key,
        dashboard_port=args.dashboard_port, dashboard_bind=args.dashboard_bind,
    )
    if args.cert and args.key:
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.load_cert_chain(args.cert, args.key)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)

    try:
        dash = ThreadingHTTPServer((args.dashboard_bind, args.dashboard_port), DashboardHandler)
        dash.daemon_threads = True
        threading.Thread(target=dash.serve_forever, daemon=True).start()
    except Exception as e:
        logging.error(f"Dashboard failed to start: {e}")

    logging.info(f"{GREEN}Proxy v6.3 (Py, full) STARTED → {args.listen}:{args.port}"
                 + (f" (auth: {args.username})" if args.username else "") + RESET)
    logging.info(f"{CYAN}Dashboard: http://{args.dashboard_bind}:{args.dashboard_port} | "
                 f"Users: {len(cfg.users)} | Upstream: {len(upstream_proxies)} | "
                 f"Config: {config_path}{RESET}")
    logging.info(f"Gửi SIGHUP để reload config không cần restart")

    # Accept loop
    threading.Thread(target=server.serve_forever, daemon=True).start()

    threading.Thread(target=realtime_stats, daemon=True).start()
    threading.Thread(target=stats_reporter, daemon=True).start()   # NEW: SSE broadcaster
    threading.Thread(target=upstream_health_loop, daemon=True).start()
    threading.Thread(target=enforce_quota_loop, daemon=True).start()
    threading.Thread(target=usage_save_loop, daemon=True).start()

    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)
    signal.signal(signal.SIGHUP, hup_handler)

    def _atexit():
        save_usage(usage_path)
        try: server.server_close()
        except: pass
    atexit.register(_atexit)

    while not shutdown_flag.is_set():
        time.sleep(0.5)

    logging.info(f"{RED}Proxy STOPPED{RESET}")

if __name__ == '__main__':
    main()
