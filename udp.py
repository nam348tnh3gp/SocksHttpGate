#!/usr/bin/env python3
"""
UDP keep-alive qua SOCKS5 proxy — v3.0.1.

V3.0.1 (so với v3.0.0):
  * CRITICAL: fix concurrent probe race. Mỗi target giờ có TCP control + UDP relay
    RIÊNG với proxy, thay vì share 1 self.udp. Trước đây, khi --concurrent bật và
    có nhiều target, response của target A có thể bị thread của target B "hớt" →
    RTT/loss/public_ip gán sai target.
  * fix STUN IPv6 XOR-MAPPED-ADDRESS: decode đúng bằng magic_cookie||txid
    (RFC 5389 §15.2). Trước đây trả raw bytes (đã XOR) → public_ip sai.
  * fix WireGuard handshake initiation length: 132 byte (không phải 136/148).
  * fix parse_proxy_arg: raise khi IPv6 literal không có bracket thay vì
    âm thầm trả (":", 1).
  * Per-target reconnect/backoff — 1 target tệ không còn kéo chậm cả cụm.
  * Multi-proxy: mỗi target tự chọn proxy round-robin khi kết nối.

Giữ nguyên: percentiles, adaptive interval, circuit breaker, health state machine,
Prometheus, alert webhook, structured JSON log, config JSON/YAML+env, SIGHUP.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import math
import os
import queue
import random
import re
import select
import signal
import socket
import struct
import sys
import threading
import time
import urllib.error
import urllib.request
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

VERSION = "3.0.1"

# ══════════════════════════════════════════════════════════════════════
#   UTIL
# ══════════════════════════════════════════════════════════════════════

def recvn(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        c = sock.recv(n - len(buf))
        if not c:
            raise IOError("connection closed")
        buf += c
    return buf


def now() -> float:
    return time.time()


def iso(ts: Optional[float] = None) -> str:
    return datetime.fromtimestamp(ts or now(), tz=timezone.utc).isoformat(timespec="milliseconds")


def human_dur(sec: float) -> str:
    s = int(sec)
    h, m, r = s // 3600, (s % 3600) // 60, s % 60
    return f"{h:02d}:{m:02d}:{r:02d}"


# ══════════════════════════════════════════════════════════════════════
#   SOCKS5 (RFC 1928 + RFC 1929)
# ══════════════════════════════════════════════════════════════════════

class Socks5Error(IOError):
    pass


def socks5_handshake_tcp(host: str, port: int,
                         user: Optional[str] = None,
                         password: Optional[str] = None,
                         timeout: float = 10.0) -> socket.socket:
    s = socket.create_connection((host, port), timeout=timeout)
    s.settimeout(timeout)
    greeting = bytes([5, 2, 0, 2]) if user else bytes([5, 1, 0])
    s.sendall(greeting)
    r = recvn(s, 2)
    if r[0] != 5:
        s.close()
        raise Socks5Error(f"SOCKS5 version mismatch: {r.hex()}")
    if r[1] == 0xFF:
        s.close()
        raise Socks5Error("SOCKS5: no acceptable auth")
    if r[1] == 0x02:
        if not user:
            s.close()
            raise Socks5Error("SOCKS5 requires auth")
        u, p = user.encode(), (password or "").encode()
        if len(u) > 255 or len(p) > 255:
            s.close()
            raise Socks5Error("username/password too long")
        s.sendall(bytes([1, len(u)]) + u + bytes([len(p)]) + p)
        ar = recvn(s, 2)
        if ar[1] != 0:
            s.close()
            raise Socks5Error("SOCKS5 auth failed")
    return s


def socks5_udp_associate(tcp: socket.socket) -> tuple[str, int]:
    """Gửi UDP ASSOCIATE và trả về (relay_ip, relay_port) mà proxy chỉ định."""
    tcp.sendall(bytes([5, 3, 0, 1, 0, 0, 0, 0, 0, 0]))
    hdr = recvn(tcp, 4)
    if hdr[0] != 5:
        raise Socks5Error("bad SOCKS5 reply version")
    if hdr[1] != 0:
        raise Socks5Error(f"UDP ASSOCIATE failed, REP={hdr[1]}")
    atyp = hdr[3]
    if atyp == 1:
        host = socket.inet_ntoa(recvn(tcp, 4))
    elif atyp == 4:
        host = socket.inet_ntop(socket.AF_INET6, recvn(tcp, 16))
    elif atyp == 3:
        ln = recvn(tcp, 1)[0]
        host = recvn(tcp, ln).decode()
    else:
        raise Socks5Error(f"bad ATYP={atyp}")
    port = struct.unpack(">H", recvn(tcp, 2))[0]
    return host, port


def socks5_udp_wrap(dst_ip: str, dst_port: int, payload: bytes) -> bytes:
    """Đóng gói payload thành 1 datagram SOCKS5 (RFC 1928 §7)."""
    if ":" in dst_ip:
        hdr = b"\x00\x00\x00\x04" + socket.inet_pton(socket.AF_INET6, dst_ip) \
              + struct.pack(">H", dst_port)
    else:
        try:
            hdr = b"\x00\x00\x00\x01" + socket.inet_aton(dst_ip) + struct.pack(">H", dst_port)
        except OSError:
            hb = dst_ip.encode()
            if len(hb) > 255:
                raise ValueError("domain name too long")
            hdr = b"\x00\x00\x00\x03" + bytes([len(hb)]) + hb + struct.pack(">H", dst_port)
    return hdr + payload


def socks5_udp_unwrap(data: bytes) -> Optional[tuple[str, int, bytes]]:
    """Trả (src_ip, src_port, payload) hoặc None nếu malformed."""
    if len(data) < 10 or data[0] or data[1] or data[2]:
        return None
    atyp, i = data[3], 4
    if atyp == 1:
        if len(data) < i + 6:
            return None
        ip = socket.inet_ntoa(data[i:i+4]); i += 4
    elif atyp == 4:
        if len(data) < i + 18:
            return None
        ip = socket.inet_ntop(socket.AF_INET6, data[i:i+16]); i += 16
    elif atyp == 3:
        ln = data[i]; i += 1
        if len(data) < i + ln + 2:
            return None
        ip = data[i:i+ln].decode("ascii", "replace"); i += ln
    else:
        return None
    port = struct.unpack(">H", data[i:i+2])[0]; i += 2
    return ip, port, data[i:]


# ══════════════════════════════════════════════════════════════════════
#   PAYLOAD BUILDERS
# ══════════════════════════════════════════════════════════════════════

def p_dns(name: str = "example.com", qtype: int = 1) -> bytes:
    tid = os.urandom(2)
    hdr = tid + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return hdr + q + struct.pack(">HH", qtype, 1)


def p_stun(binding: bool = True) -> bytes:
    """STUN Binding Request — 20-byte header + magic cookie + 12-byte txid."""
    typ = 0x0001 if binding else 0x0004
    return struct.pack(">HHI", typ, 0, 0x2112A442) + os.urandom(12)


def p_ntp() -> bytes:
    b = bytearray(48)
    b[0] = 0x23  # LI=0 VN=4 Mode=3 (client)
    b[40:44] = os.urandom(4)
    return bytes(b)


def p_quic_initial(sni: str = "example.com") -> bytes:
    """
    QUIC Initial packet TỐI GIẢN — đủ để nhiều server trả về (ServerHello, Retry,
    hoặc Version Negotiation). KHÔNG phải client QUIC hoàn chỉnh (không có TLS
    handshake), nhưng dùng để kiểm tra đường UDP/443 có thông hay không.
    """
    dcid = os.urandom(8)
    scid = os.urandom(0)
    flags = 0xC0 | (random.randint(0, 3))
    header = bytes([flags]) + b"\x00\x00\x00\x01" \
             + bytes([len(dcid)]) + dcid \
             + bytes([len(scid)]) + scid \
             + b"\x00"
    length = b"\x44\x00"
    return header + length + b"\x00" + b"\x00" * 20


def p_doh(name: str = "example.com") -> bytes:
    """DNS query kèm EDNS0 OPT record (thường dùng cho DoH/DoT qua UDP)."""
    base = p_dns(name, qtype=1)
    opt = b"\x00" + struct.pack(">HHIH", 41, 4096, 0, 0)
    return base[:10] + b"\x00\x01" + base[12:] + opt


def p_wireguard_init() -> bytes:
    """
    WireGuard handshake initiation — ĐÚNG 132 byte (RFC/whitepaper):
        msg_type (4 LE = 1)
      + sender_index (4)
      + ephemeral (32)
      + encrypted_static (32)
      + encrypted_timestamp (28 = 12 timestamp + 16 AEAD tag)
      + mac1 (16)
      + mac2 (16)
      = 132 byte.

    Đây là blob ngẫu nhiên đúng kích thước. WireGuard server thật sẽ reject vì
    crypto sai, nhưng packet vẫn qua được đường UDP để test connectivity.

    v3.0.0 bug: gửi 136 byte (sai) và docstring ghi "148 byte" (sai).
    """
    return struct.pack("<I", 1) + os.urandom(4 + 32 + 32 + 28 + 16 + 16)


def p_mdns(name: str = "_services._dns-sd._udp.local") -> bytes:
    """mDNS query — chỉ dùng được nếu proxy hỗ trợ multicast."""
    return p_dns(name, qtype=12)  # PTR


def p_dhcp_discover() -> bytes:
    """DHCP DISCOVER — chỉ test đường UDP/67."""
    xid = os.urandom(4)
    return (b"\x01\x01\x06\x00" + xid
            + b"\x00\x00\x00\x00" + b"\x00\x00\x00\x00"
            + b"\x00" * 16 + b"\x00" * 64 + b"\x00" * 128
            + b"\x63\x82\x53\x63" + b"\x35\x01\x01\xff")


PAYLOADS: dict[str, Callable[[], bytes]] = {
    "dns-a":       lambda: p_dns(qtype=1),
    "dns-aaaa":    lambda: p_dns(qtype=28),
    "dns-mx":      lambda: p_dns(qtype=15),
    "dns-txt":     lambda: p_dns(qtype=16),
    "dns-ptr":     lambda: p_dns(qtype=12),
    "doh":         p_doh,
    "stun":        p_stun,
    "ntp":         p_ntp,
    "quic":        p_quic_initial,
    "wireguard":   p_wireguard_init,
    "mdns":        p_mdns,
    "dhcp":        p_dhcp_discover,
}


def build_payload(spec: str) -> bytes:
    """
    spec:
      - tên payload có sẵn ("dns-a", "quic", ...)
      - "text:STR"
      - "hex:DEADBEEF"
      - "file:/path/to/payload.bin"
    """
    if spec in PAYLOADS:
        return PAYLOADS[spec]()
    if spec.startswith("text:"):
        return spec[5:].encode()
    if spec.startswith("hex:"):
        return bytes.fromhex(spec[4:].replace(" ", "").replace("_", ""))
    if spec.startswith("file:"):
        return Path(spec[5:]).read_bytes()
    raise ValueError(f"unknown payload: {spec}")


# ══════════════════════════════════════════════════════════════════════
#   STUN PARSER (đầy đủ, RFC 5389)
# ══════════════════════════════════════════════════════════════════════

STUN_MAGIC = 0x2112A442


@dataclass
class StunResult:
    xor_mapped: Optional[tuple[str, int]] = None
    mapped: Optional[tuple[str, int]] = None
    software: Optional[str] = None
    changed: Optional[tuple[str, int]] = None
    error_code: Optional[int] = None
    error_reason: Optional[str] = None


def _iter_stun_attrs(data: bytes) -> Iterable[tuple[int, bytes]]:
    if len(data) < 20:
        return
    i = 20
    while i + 4 <= len(data):
        typ, ln = struct.unpack(">HH", data[i:i+4])
        val = data[i+4:i+4+ln]
        yield typ, val
        i += 4 + ((ln + 3) & ~3)


def _parse_stun_addr(val: bytes) -> Optional[tuple[str, int]]:
    if len(val) < 4:
        return None
    _res, fam = val[0], val[1]
    port = struct.unpack(">H", val[2:4])[0]
    if fam == 1 and len(val) >= 8:
        return socket.inet_ntoa(val[4:8]), port
    if fam == 2 and len(val) >= 20:
        return socket.inet_ntop(socket.AF_INET6, val[4:20]), port
    return None


def parse_stun(data: bytes) -> StunResult:
    """
    Parse toàn bộ STUN attribute. Trả StunResult (best-effort).

    v3.0.1 fix: XOR-MAPPED-ADDRESS IPv6 (family=2) phải được XOR với
    (magic_cookie || transaction_id) — 16 byte. Trước đây trả raw → public_ip sai.
    """
    res = StunResult()
    if len(data) < 20:
        return res
    txid = data[8:20]
    xor_key_v4 = b"\x21\x12\xA4\x42"
    xor_key_v6 = xor_key_v4 + txid

    for typ, val in _iter_stun_attrs(data):
        if typ == 0x0020:  # XOR-MAPPED-ADDRESS
            if len(val) < 4:
                continue
            fam = val[1]
            port = struct.unpack(">H", val[2:4])[0] ^ 0x2112
            if fam == 1 and len(val) >= 8:
                ip = socket.inet_ntoa(
                    bytes(b ^ k for b, k in zip(val[4:8], xor_key_v4))
                )
                res.xor_mapped = (ip, port)
            elif fam == 2 and len(val) >= 20:
                ip = socket.inet_ntop(
                    socket.AF_INET6,
                    bytes(b ^ k for b, k in zip(val[4:20], xor_key_v6)),
                )
                res.xor_mapped = (ip, port)
        elif typ == 0x0001:  # MAPPED-ADDRESS (không XOR)
            a = _parse_stun_addr(val)
            if a:
                res.mapped = a
        elif typ == 0x8022:  # SOFTWARE
            try:
                res.software = val.rstrip(b"\x00").decode("utf-8", "replace")
            except Exception:
                pass
        elif typ == 0x0005:  # CHANGE-REQUEST
            pass
        elif typ == 0x0009:  # ERROR-CODE
            if len(val) >= 4:
                res.error_code = val[2] * 100 + val[3]
                res.error_reason = val[4:].decode("utf-8", "replace")
    return res


# ══════════════════════════════════════════════════════════════════════
#   STATS
# ══════════════════════════════════════════════════════════════════════

class PercentileTracker:
    """Cửa sổ trượt giữ N mẫu RTT gần nhất để tính percentile chính xác."""
    __slots__ = ("_buf", "_cap")

    def __init__(self, capacity: int = 500):
        self._cap = capacity
        self._buf: deque[float] = deque(maxlen=capacity)

    def add(self, v: float) -> None:
        self._buf.append(v)

    def pct(self, p: float) -> float:
        if not self._buf:
            return 0.0
        arr = sorted(self._buf)
        idx = max(0, min(len(arr) - 1, int(round((p / 100.0) * (len(arr) - 1)))))
        return arr[idx]

    def __len__(self) -> int:
        return len(self._buf)

    def reset(self) -> None:
        self._buf.clear()


class Health:
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    DOWN = "DOWN"
    UNKNOWN = "UNKNOWN"


@dataclass
class Stats:
    sent: int = 0
    recv: int = 0
    lost: int = 0
    rtt_min: float = float("inf")
    rtt_max: float = 0.0
    rtt_sum: float = 0.0
    reconnects: int = 0
    send_err: int = 0
    recv_err: int = 0
    consecutive_lost: int = 0
    consecutive_ok: int = 0
    public_ip: Optional[str] = None
    public_port: Optional[int] = None
    last_seen: Optional[float] = None
    last_rtt: Optional[float] = None
    recent_oks: deque = field(default_factory=lambda: deque(maxlen=100))
    rtt_window: PercentileTracker = field(default_factory=lambda: PercentileTracker(500))
    health: str = Health.UNKNOWN

    @property
    def avg(self) -> float:
        return self.rtt_sum / self.recv if self.recv else 0.0

    @property
    def loss_pct(self) -> float:
        return self.lost / self.sent * 100 if self.sent else 0.0

    def recent_loss_pct(self, n: int = 20) -> float:
        r = list(self.recent_oks)[-n:]
        if not r:
            return 0.0
        return (1 - sum(r) / len(r)) * 100

    def update_health(self, degrade_pct: float = 10.0, down_pct: float = 50.0) -> None:
        if self.sent < 5:
            self.health = Health.UNKNOWN
            return
        rl = self.recent_loss_pct(20)
        if rl >= down_pct:
            self.health = Health.DOWN
        elif rl >= degrade_pct:
            self.health = Health.DEGRADED
        else:
            self.health = Health.HEALTHY

    def as_dict(self) -> dict[str, Any]:
        return {
            "sent": self.sent, "recv": self.recv, "lost": self.lost,
            "loss_pct": round(self.loss_pct, 3),
            "rtt_ms": {
                "min": round(self.rtt_min, 2) if self.rtt_min != float("inf") else None,
                "avg": round(self.avg, 2),
                "p50": round(self.rtt_window.pct(50), 2),
                "p95": round(self.rtt_window.pct(95), 2),
                "p99": round(self.rtt_window.pct(99), 2),
                "max": round(self.rtt_max, 2),
            },
            "reconnects": self.reconnects,
            "send_err": self.send_err,
            "recv_err": self.recv_err,
            "public_ip": self.public_ip,
            "public_port": self.public_port,
            "health": self.health,
            "last_rtt_ms": round(self.last_rtt, 2) if self.last_rtt is not None else None,
            "last_seen": self.last_seen,
        }


# ══════════════════════════════════════════════════════════════════════
#   TARGET
# ══════════════════════════════════════════════════════════════════════

@dataclass
class Target:
    host: str
    port: int
    payload: str = "dns-a"
    stats: Stats = field(default_factory=Stats)

    # circuit breaker
    _cb_fail_until: float = 0.0
    _cb_fail_count: int = 0

    # per-target session (v3.0.1)
    tcp: Optional[socket.socket] = None
    udp: Optional[socket.socket] = None
    relay: Optional[tuple[str, int]] = None
    proxy_used: Optional[tuple[str, int]] = None
    _backoff: float = 1.0
    _conn_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    @property
    def key(self) -> str:
        return f"{self.host}:{self.port}"

    def __str__(self) -> str:
        return f"[{self.host}]:{self.port}" if ":" in self.host else f"{self.host}:{self.port}"

    # ── circuit breaker ──
    def cb_open(self) -> bool:
        return now() < self._cb_fail_until

    def cb_on_ok(self) -> None:
        self._cb_fail_count = 0
        self._cb_fail_until = 0.0

    def cb_on_fail(self, base_cooldown: float = 30.0, max_cooldown: float = 300.0) -> None:
        self._cb_fail_count += 1
        if self._cb_fail_count >= 3:
            cd = min(base_cooldown * (2 ** (self._cb_fail_count - 3)), max_cooldown)
            self._cb_fail_until = now() + cd

    def cb_remaining(self) -> float:
        return max(0.0, self._cb_fail_until - now())


# ══════════════════════════════════════════════════════════════════════
#   ALERT
# ══════════════════════════════════════════════════════════════════════

class AlertManager:
    def __init__(self, url: Optional[str] = None, cooldown: float = 30.0):
        self.url = url
        self.cooldown = cooldown
        self._last: dict[str, float] = {}
        self._lock = threading.Lock()

    def _format(self, kind: str, target: str, msg: str, extra: dict) -> dict:
        text = f"[udpka] {kind} — {target}: {msg}"
        if self.url and "discord.com" in self.url:
            return {"content": text}
        if self.url and "hooks.slack.com" in self.url:
            return {"text": text}
        return {"text": text, "kind": kind, "target": target,
                "msg": msg, "ts": now(), **extra}

    def fire(self, kind: str, target: str, msg: str, **extra: Any) -> None:
        if not self.url:
            return
        key = f"{kind}:{target}"
        with self._lock:
            if now() - self._last.get(key, 0) < self.cooldown:
                return
            self._last[key] = now()

        payload = json.dumps(self._format(kind, target, msg, extra)).encode()
        req = urllib.request.Request(self.url, data=payload,
                                     headers={"Content-Type": "application/json",
                                              "User-Agent": f"udpka/{VERSION}"})

        def _send():
            try:
                with urllib.request.urlopen(req, timeout=5) as r:
                    r.read(1)
            except (urllib.error.URLError, OSError, TimeoutError):
                pass

        threading.Thread(target=_send, daemon=True).start()


# ══════════════════════════════════════════════════════════════════════
#   LOG (structured + rotate)
# ══════════════════════════════════════════════════════════════════════

class RotatingFile:
    def __init__(self, path: str, max_mb: int = 20, backups: int = 5):
        self.path = Path(path)
        self.max_bytes = max_mb * 1024 * 1024
        self.backups = backups
        self._fh: Optional[io.TextIOWrapper] = None
        self._lock = threading.Lock()
        self._open()

    def _open(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = self.path.open("a", encoding="utf-8")

    def _rotate(self) -> None:
        if self._fh:
            self._fh.close()
        for i in range(self.backups - 1, 0, -1):
            src = self.path.with_suffix(self.path.suffix + f".{i}")
            dst = self.path.with_suffix(self.path.suffix + f".{i+1}")
            if src.exists():
                dst.unlink(missing_ok=True)
                src.rename(dst)
        if self.path.exists():
            self.path.rename(self.path.with_suffix(self.path.suffix + ".1"))
        self._open()

    def write_line(self, line: str) -> None:
        with self._lock:
            try:
                if self._fh.tell() > self.max_bytes:
                    self._rotate()
            except Exception:
                self._open()
            try:
                self._fh.write(line + "\n")
                self._fh.flush()
            except Exception:
                pass

    def close(self) -> None:
        with self._lock:
            if self._fh:
                try:
                    self._fh.close()
                except Exception:
                    pass


# ══════════════════════════════════════════════════════════════════════
#   PROMETHEUS
# ══════════════════════════════════════════════════════════════════════

class MetricsHandler(BaseHTTPRequestHandler):
    ka: Optional["UDPKeepAlive"] = None

    def log_message(self, *a): pass

    def do_GET(self) -> None:
        if self.path != "/metrics":
            self.send_error(404); return
        ka = MetricsHandler.ka
        lines: list[str] = []
        if ka:
            proxy_list = ",".join(f"{h}:{p}" for h, p in ka.proxies)
            lines.append("# HELP udpka_info Info about running instance")
            lines.append("# TYPE udpka_info gauge")
            lines.append(f'udpka_info{{version="{VERSION}",'
                         f'proxies="{proxy_list}",'
                         f'targets="{len(ka.targets)}"}} 1')

            for t in ka.targets:
                s = t.stats
                lbl = f'target="{t.host}",port="{t.port}",payload="{t.payload}"'
                lines.append(f'udpka_sent_total{{{lbl}}} {s.sent}')
                lines.append(f'udpka_recv_total{{{lbl}}} {s.recv}')
                lines.append(f'udpka_lost_total{{{lbl}}} {s.lost}')
                lines.append(f'udpka_send_errors_total{{{lbl}}} {s.send_err}')
                lines.append(f'udpka_recv_errors_total{{{lbl}}} {s.recv_err}')
                lines.append(f'udpka_rtt_ms_avg{{{lbl}}} {s.avg:.3f}')
                rmin = s.rtt_min if s.rtt_min != float("inf") else 0.0
                lines.append(f'udpka_rtt_ms_min{{{lbl}}} {rmin:.3f}')
                lines.append(f'udpka_rtt_ms_max{{{lbl}}} {s.rtt_max:.3f}')
                lines.append(f'udpka_rtt_ms_p50{{{lbl}}} {s.rtt_window.pct(50):.3f}')
                lines.append(f'udpka_rtt_ms_p95{{{lbl}}} {s.rtt_window.pct(95):.3f}')
                lines.append(f'udpka_rtt_ms_p99{{{lbl}}} {s.rtt_window.pct(99):.3f}')
                lines.append(f'udpka_loss_ratio{{{lbl}}} {s.loss_pct/100:.6f}')
                lines.append(f'udpka_loss_ratio_recent{{{lbl}}} {s.recent_loss_pct(20)/100:.6f}')
                lines.append(f'udpka_health{{{lbl},state="{s.health}"}} 1')
                lines.append(f'udpka_consecutive_lost{{{lbl}}} {s.consecutive_lost}')
                lines.append(f'udpka_target_connected{{{lbl}}} '
                             f'{1 if t.tcp is not None else 0}')

            lines.append(f'udpka_reconnects_total {ka.stats_reconnects}')
            lines.append(f'udpka_uptime_seconds {now() - ka.started_at:.1f}')
            if ka.alert_mgr.url:
                lines.append('# HELP udpka_webhook_configured Whether webhook alert is configured')
                lines.append('# TYPE udpka_webhook_configured gauge')
                lines.append('udpka_webhook_configured 1')

        body = ("\n".join(lines) + "\n").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def start_metrics_server(port: int, ka: "UDPKeepAlive") -> ThreadingHTTPServer:
    MetricsHandler.ka = ka
    srv = ThreadingHTTPServer(("127.0.0.1", port), MetricsHandler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


# ══════════════════════════════════════════════════════════════════════
#   KEEP-ALIVE (v3.0.1 — per-target session)
# ══════════════════════════════════════════════════════════════════════

class UDPKeepAlive:
    def __init__(
        self,
        proxies: list[tuple[str, int]],
        targets: list[Target],
        interval: float = 20.0,
        timeout: float = 5.0,
        jitter: float = 0.15,
        user: Optional[str] = None,
        password: Optional[str] = None,
        output: str = "text",
        log_file: Optional[str] = None,
        json_log_file: Optional[str] = None,
        alert_loss: Optional[float] = None,
        alert_webhook: Optional[str] = None,
        alert_cooldown: float = 30.0,
        quiet: bool = False,
        color: bool = True,
        concurrent: bool = True,
        concurrency: int = 16,
        adaptive: bool = True,
    ):
        if not proxies:
            raise ValueError("at least one proxy required")
        if not targets:
            raise ValueError("at least one target required")

        self.proxies = proxies
        self._proxy_idx = 0
        self._proxy_lock = threading.Lock()
        self.targets = targets
        self.interval = interval
        self.timeout = timeout
        self.jitter = jitter
        self.user = user
        self.password = password
        self.output = output
        self.log_file = log_file
        self.json_log_file = json_log_file
        self.alert_loss = alert_loss
        self.quiet = quiet
        self.color = color and sys.stdout.isatty()
        # v3.0.1: concurrent giờ thực sự an toàn — mỗi target có session riêng.
        self.concurrent = concurrent and len(targets) > 1
        self.concurrency = max(1, concurrency)
        self.adaptive = adaptive

        self.stop = False
        self.started_at = now()
        self.stats_reconnects = 0
        self.alert_mgr = AlertManager(alert_webhook, cooldown=alert_cooldown)

        self._csv: Optional[csv.writer] = None
        self._csv_fp: Optional[io.TextIOWrapper] = None
        self._jsonlog: Optional[RotatingFile] = None
        self._lock = threading.Lock()
        self._executor: Optional[ThreadPoolExecutor] = None

    # ── color ──
    def _c(self, code: str, s: str) -> str:
        return f"\033[{code}m{s}\033[0m" if self.color else s
    def _green(self, s: str) -> str:  return self._c("92", s)
    def _red(self, s: str) -> str:    return self._c("91", s)
    def _yellow(self, s: str) -> str: return self._c("93", s)
    def _cyan(self, s: str) -> str:   return self._c("96", s)

    # ── proxy rotation (thread-safe) ──
    def _next_proxy(self) -> tuple[str, int]:
        with self._proxy_lock:
            p = self.proxies[self._proxy_idx % len(self.proxies)]
            self._proxy_idx = (self._proxy_idx + 1) % len(self.proxies)
            return p

    # ── per-target connection lifecycle ──
    def _connect_target(self, t: Target) -> bool:
        """Mở TCP control + UDP relay cho 1 target. Trả True nếu OK."""
        ph, pp = self._next_proxy()
        try:
            tcp = socks5_handshake_tcp(ph, pp, self.user, self.password,
                                       timeout=self.timeout)
        except Exception as e:
            if not self.quiet:
                print(self._red(f"[!] {t} TCP connect {ph}:{pp} fail: {e}"))
            return False

        try:
            relay_host, relay_port = socks5_udp_associate(tcp)
        except Exception as e:
            try: tcp.close()
            except Exception: pass
            if not self.quiet:
                print(self._red(f"[!] {t} UDP ASSOCIATE fail: {e}"))
            return False

        if relay_host in ("0.0.0.0", "::"):
            relay_host = ph

        fam = socket.AF_INET6 if ":" in relay_host else socket.AF_INET
        try:
            udp = socket.socket(fam, socket.SOCK_DGRAM)
            udp.bind(("::", 0) if fam == socket.AF_INET6 else ("0.0.0.0", 0))
            udp.settimeout(self.timeout)
        except OSError as e:
            try: udp.close()
            except Exception: pass
            try: tcp.close()
            except Exception: pass
            if not self.quiet:
                print(self._red(f"[!] {t} UDP bind fail: {e}"))
            return False

        with t._conn_lock:
            # close any previous
            for s in (t.udp, t.tcp):
                if s:
                    try: s.close()
                    except Exception: pass
            t.tcp = tcp
            t.udp = udp
            t.relay = (relay_host, relay_port)
            t.proxy_used = (ph, pp)
            t._backoff = 1.0

        if not self.quiet:
            print(f"[*] {t} ⇄ proxy {ph}:{pp}  relay {relay_host}:{relay_port}")
        return True

    def _close_target(self, t: Target) -> None:
        with t._conn_lock:
            for s in (t.udp, t.tcp):
                if s:
                    try: s.close()
                    except Exception: pass
            t.udp = t.tcp = None
            t.relay = None

    def _tcp_alive(self, t: Target) -> bool:
        """Non-blocking check trên TCP control của target."""
        tcp = t.tcp
        if tcp is None:
            return False
        try:
            r, _, _ = select.select([tcp], [], [], 0)
            if r:
                d = tcp.recv(1)
                if not d:
                    return False
                return False  # byte lạ trên control channel — coi như lỗi
            return True
        except (OSError, ValueError):
            return False

    def _reconnect_target(self, t: Target) -> None:
        t.stats.reconnects += 1
        self.stats_reconnects += 1
        if not self.quiet:
            print(self._yellow(
                f"[!] {t} control mất — reconnect #{t.stats.reconnects} "
                f"(backoff {t._backoff:.0f}s)"))
        if len(self.proxies) == 1:
            time.sleep(t._backoff)
            t._backoff = min(t._backoff * 2, 30.0)
        # multi-proxy: thử proxy khác ngay, không sleep
        self._close_target(t)
        if not self._connect_target(t):
            # thử lại vòng sau
            pass

    # ── probe ──
    def probe(self, t: Target) -> None:
        if t.cb_open():
            return
        with t._conn_lock:
            udp = t.udp
            relay = t.relay
        if udp is None or relay is None:
            return

        try:
            payload = build_payload(t.payload)
        except (ValueError, OSError) as e:
            if not self.quiet:
                print(f"[!] {e}")
            return

        wrapped = socks5_udp_wrap(t.host, t.port, payload)
        t0 = time.perf_counter()
        try:
            udp.sendto(wrapped, relay)
            t.stats.sent += 1
        except Exception as e:
            t.stats.lost += 1
            t.stats.send_err += 1
            t.stats.recent_oks.append(0)
            t.stats.consecutive_ok = 0
            t.stats.consecutive_lost += 1
            t.cb_on_fail()
            if not self.quiet:
                print(f"[!] send {t}: {e}")
            return

        try:
            data, _ = udp.recvfrom(65535)
            rtt = (time.perf_counter() - t0) * 1000
            with self._lock:
                t.stats.recv += 1
                t.stats.rtt_sum += rtt
                t.stats.rtt_min = min(t.stats.rtt_min, rtt)
                t.stats.rtt_max = max(t.stats.rtt_max, rtt)
                t.stats.rtt_window.add(rtt)
                t.stats.last_seen = now()
                t.stats.last_rtt = rtt
                t.stats.recent_oks.append(1)
                t.stats.consecutive_ok += 1
                t.stats.consecutive_lost = 0
                t.stats.update_health()
            t.cb_on_ok()

            u = socks5_udp_unwrap(data)
            src = (u[0], u[1]) if u else None
            if t.payload == "stun" and u:
                sres = parse_stun(u[2])
                if sres.xor_mapped:
                    t.stats.public_ip, t.stats.public_port = sres.xor_mapped
                elif sres.mapped:
                    t.stats.public_ip, t.stats.public_port = sres.mapped

            self._report(t, True, rtt, src)
        except socket.timeout:
            with self._lock:
                t.stats.lost += 1
                t.stats.recent_oks.append(0)
                t.stats.consecutive_ok = 0
                t.stats.consecutive_lost += 1
                t.stats.update_health()
            t.cb_on_fail()
            self._report(t, False, None, None)
        except Exception as e:
            with self._lock:
                t.stats.lost += 1
                t.stats.recv_err += 1
                t.stats.consecutive_ok = 0
                t.stats.consecutive_lost += 1
                t.stats.update_health()
            if not self.quiet:
                print(f"[!] recv {t}: {e}")

    # ── report ──
    def _report(self, t: Target, ok: bool, rtt: Optional[float],
                src: Optional[tuple[str, int]]) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        up = int(now() - self.started_at)
        st = t.stats

        if self._csv:
            with self._lock:
                self._csv.writerow([
                    round(now(), 3), ts, t.key, int(ok),
                    f"{rtt:.3f}" if rtt is not None else "",
                    f"{src[0]}:{src[1]}" if src else "",
                    st.sent, st.recv, st.lost,
                    f"{st.loss_pct:.2f}", f"{st.avg:.2f}",
                    st.health,
                ])
                try:
                    self._csv_fp.flush()
                except Exception:
                    pass

        if self._jsonlog:
            rec = {
                "t": round(now(), 3), "ts": iso(), "target": t.key,
                "ok": ok,
                "rtt_ms": round(rtt, 3) if rtt is not None else None,
                "src": f"{src[0]}:{src[1]}" if src else None,
                "sent": st.sent, "recv": st.recv, "lost": st.lost,
                "loss_pct": round(st.loss_pct, 3),
                "loss_pct_recent": round(st.recent_loss_pct(20), 3),
                "avg_ms": round(st.avg, 3),
                "p50_ms": round(st.rtt_window.pct(50), 3),
                "p95_ms": round(st.rtt_window.pct(95), 3),
                "p99_ms": round(st.rtt_window.pct(99), 3),
                "health": st.health,
                "consecutive_lost": st.consecutive_lost,
            }
            if st.public_ip:
                rec["public_ip"] = st.public_ip
                rec["public_port"] = st.public_port
            if t.proxy_used:
                rec["proxy"] = f"{t.proxy_used[0]}:{t.proxy_used[1]}"
            self._jsonlog.write_line(json.dumps(rec, separators=(",", ":")))

        if self.output == "json":
            rec = {
                "t": round(now(), 3), "ts": ts, "target": t.key, "ok": ok,
                "rtt_ms": round(rtt, 2) if rtt is not None else None,
                "src": f"{src[0]}:{src[1]}" if src else None,
                "sent": st.sent, "recv": st.recv, "lost": st.lost,
                "loss_pct": round(st.loss_pct, 2),
                "avg_ms": round(st.avg, 2),
                "p50": round(st.rtt_window.pct(50), 2),
                "p95": round(st.rtt_window.pct(95), 2),
                "health": st.health,
            }
            if st.public_ip:
                rec["public"] = f"{st.public_ip}:{st.public_port}"
            if t.proxy_used:
                rec["proxy"] = f"{t.proxy_used[0]}:{t.proxy_used[1]}"
            print(json.dumps(rec), flush=True)
        elif not self.quiet:
            if ok:
                mark = self._green(f"[{ts}] +{human_dur(up)} ✓ rtt={rtt:7.2f}ms")
            else:
                mark = self._red(f"[{ts}] +{human_dur(up)} ✗ LOST")
            hcolor = {"HEALTHY": self._green, "DEGRADED": self._yellow,
                      "DOWN": self._red}.get(st.health, lambda x: x)
            hstr = hcolor(st.health)
            line = (f"{mark} {t} [{hstr}] sent={st.sent} recv={st.recv} "
                    f"loss={st.loss_pct:5.1f}% p50={st.rtt_window.pct(50):6.1f} "
                    f"p95={st.rtt_window.pct(95):6.1f} avg={st.avg:6.1f}ms")
            if src:
                line += f" src={src[0]}:{src[1]}"
            if st.public_ip:
                line += f" pub={st.public_ip}:{st.public_port}"
            print(line, flush=True)

        if self.alert_loss is not None and st.sent >= 10:
            rl = st.recent_loss_pct(20)
            if rl >= self.alert_loss:
                self.alert_mgr.fire(
                    "loss", t.key,
                    f"loss(20)={rl:.1f}% >= {self.alert_loss}%",
                    loss_recent=round(rl, 2), sent=st.sent, lost=st.lost,
                )
        if st.health == Health.DOWN and st.sent >= 10:
            self.alert_mgr.fire("down", t.key,
                                f"health=DOWN recent_loss={st.recent_loss_pct(20):.1f}%",
                                sent=st.sent, lost=st.lost)

    # ── adaptive interval ──
    def _next_interval(self) -> float:
        if not self.adaptive:
            return self.interval
        worst = Health.HEALTHY
        for t in self.targets:
            if t.stats.health == Health.DOWN:
                worst = Health.DOWN; break
            if t.stats.health == Health.DEGRADED:
                worst = Health.DEGRADED
        if worst == Health.DOWN:
            return max(1.0, self.interval / 4)
        if worst == Health.DEGRADED:
            return max(1.0, self.interval / 2)
        return self.interval

    # ── main loop ──
    def run(self) -> None:
        self._banner()
        self._open_outputs()

        # Kết nối ban đầu cho từng target độc lập
        for t in self.targets:
            self._connect_target(t)

        if self.concurrent:
            self._executor = ThreadPoolExecutor(
                max_workers=self.concurrency, thread_name_prefix="probe")

        try:
            while not self.stop:
                # Kiểm tra + reconnect per-target
                for t in self.targets:
                    if self.stop:
                        break
                    if not self._tcp_alive(t):
                        self._reconnect_target(t)

                self._probe_round()

                base = self._next_interval()
                j = base * self.jitter
                slp = max(0.1, base + random.uniform(-j, j))
                end = now() + slp
                while not self.stop:
                    remaining = end - now()
                    if remaining <= 0:
                        break
        except KeyboardInterrupt:
            pass
        finally:
            if self._executor:
                self._executor.shutdown(wait=False)
            self.summary()
            self.close()
            self._close_outputs()

    def _probe_round(self) -> None:
        active = [t for t in self.targets
                  if not t.cb_open() and t.udp is not None]
        if not active:
            if not self.quiet and self.targets:
                cd = min((t.cb_remaining() for t in self.targets
                          if t.cb_open()), default=0.0)
                if cd > 0:
                    print(self._yellow(f"[~] tất cả target đang cooldown, chờ {cd:.0f}s"))
            return
        if self.concurrent and self._executor and len(active) > 1:
            futs = [self._executor.submit(self.probe, t) for t in active]
            for _ in as_completed(futs):
                pass
        else:
            for t in active:
                if self.stop:
                    break
                self.probe(t)

    def close(self) -> None:
        for t in self.targets:
            self._close_target(t)

    def _banner(self) -> None:
        if self.quiet:
            return
        print("=" * 78)
        print(f" UDP keep-alive via SOCKS5 — v{VERSION} (per-target session)")
        proxies = ", ".join(f"{h}:{p}" for h, p in self.proxies)
        print(f" proxies={proxies}")
        print(f" targets={len(self.targets)}  interval={self.interval}s  "
              f"jitter=±{self.jitter*100:.0f}%  output={self.output}  "
              f"concurrent={self.concurrent}  adaptive={self.adaptive}")
        for t in self.targets:
            print(f"   • {t}  payload={t.payload}")
        print("=" * 78)

    def _open_outputs(self) -> None:
        if self.log_file:
            self._csv_fp = open(self.log_file, "w", newline="", encoding="utf-8")
            self._csv = csv.writer(self._csv_fp)
            self._csv.writerow([
                "t_unix", "ts", "target", "ok", "rtt_ms", "src",
                "sent", "recv", "lost", "loss_pct", "avg_ms", "health",
            ])
        if self.json_log_file:
            self._jsonlog = RotatingFile(self.json_log_file)

    def _close_outputs(self) -> None:
        if self._csv_fp:
            try:
                self._csv_fp.close()
            except Exception:
                pass
        if self._jsonlog:
            self._jsonlog.close()

    def summary(self) -> None:
        dur = now() - self.started_at
        print("\n" + "=" * 78)
        print(" SUMMARY")
        print("=" * 78)
        print(f" Duration     : {dur:.0f}s ({dur/60:.1f} min)")
        print(f" Reconnects   : {self.stats_reconnects}")
        print(f" Proxies      : {', '.join(f'{h}:{p}' for h, p in self.proxies)}")
        for t in self.targets:
            s = t.stats
            pu = f"{t.proxy_used[0]}:{t.proxy_used[1]}" if t.proxy_used else "—"
            print(f"\n {t}  payload={t.payload}  health={s.health}  proxy={pu}")
            print(f"   sent/recv   : {s.sent} / {s.recv}")
            print(f"   lost        : {s.lost} ({s.loss_pct:.1f}%)  "
                  f"send_err={s.send_err}  recv_err={s.recv_err}")
            if s.recv:
                print(f"   rtt min/avg/max : {s.rtt_min:.2f} / {s.avg:.2f} / {s.rtt_max:.2f} ms")
                print(f"   rtt p50/p95/p99 : {s.rtt_window.pct(50):.2f} / "
                      f"{s.rtt_window.pct(95):.2f} / {s.rtt_window.pct(99):.2f} ms")
            if s.public_ip:
                print(f"   public seen : {s.public_ip}:{s.public_port}")
        print("=" * 78)


# ══════════════════════════════════════════════════════════════════════
#   CONFIG
# ══════════════════════════════════════════════════════════════════════

def _yaml_minimal(text: str) -> dict:
    out: dict[str, Any] = {}
    current_key: Optional[str] = None
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        m = re.match(r"^([A-Za-z0-9_\-]+)\s*:\s*(.*)$", line)
        if m:
            k, v = m.group(1), m.group(2).strip()
            if not v:
                out[k] = []
                current_key = k
                continue
            out[k] = _yaml_scalar(v)
            current_key = None
            continue
        m = re.match(r"^\s*-\s*(.+)$", line)
        if m and current_key:
            if isinstance(out[current_key], list):
                out[current_key].append(_yaml_scalar(m.group(1).strip()))
            continue
    return out


def _yaml_scalar(v: str) -> Any:
    if v.startswith("[") and v.endswith("]"):
        inner = v[1:-1].strip()
        if not inner:
            return []
        return [_yaml_scalar(x.strip()) for x in inner.split(",")]
    if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
        return v[1:-1]
    lo = v.lower()
    if lo in ("true", "yes", "on"):
        return True
    if lo in ("false", "no", "off"):
        return False
    if lo in ("null", "~", ""):
        return None
    try:
        if "." in v:
            return float(v)
        return int(v)
    except ValueError:
        return v


def load_config(path: str) -> dict:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    if p.suffix.lower() in (".yaml", ".yml"):
        return _yaml_minimal(text)
    return json.loads(text)


ENV_PREFIX = "UDPKA_"

def apply_env_overrides(args: argparse.Namespace) -> None:
    for k, v in os.environ.items():
        if not k.startswith(ENV_PREFIX):
            continue
        key = k[len(ENV_PREFIX):].lower()
        if not hasattr(args, key):
            continue
        cur = getattr(args, key)
        if cur not in (None, [], "", 0, 0.0, False):
            continue
        try:
            if isinstance(cur, bool):
                setattr(args, key, v.lower() in ("1", "true", "yes", "on"))
            elif isinstance(cur, int):
                setattr(args, key, int(v))
            elif isinstance(cur, float):
                setattr(args, key, float(v))
            elif isinstance(cur, list):
                setattr(args, key, [x for x in v.split(",") if x])
            else:
                setattr(args, key, v)
        except (ValueError, TypeError):
            pass


# ══════════════════════════════════════════════════════════════════════
#   TARGET PARSING
# ══════════════════════════════════════════════════════════════════════

def parse_target_arg(s: str) -> tuple[str, int, str]:
    """
    'host' | 'host:port' | 'host:port:payload' | '[v6]:port[:payload]'
    """
    s = s.strip()
    if s.startswith("["):
        end = s.index("]")
        host = s[1:end]
        rest = s[end+1:].lstrip(":")
        if not rest:
            return host, 53, "dns-a"
        parts = rest.split(":", 1)
        port = int(parts[0])
        payload = parts[1] if len(parts) > 1 else "dns-a"
        return host, port, payload
    parts = s.split(":")
    if len(parts) == 1:
        return parts[0], 53, "dns-a"
    if len(parts) == 2:
        return parts[0], int(parts[1]), "dns-a"
    if len(parts) == 3:
        return parts[0], int(parts[1]), parts[2]
    raise ValueError(f"cannot parse target: {s} (IPv6 cần bracket: [::1]:53)")


def parse_proxy_arg(s: str) -> tuple[str, int]:
    """
    '[v6]:port' | 'host:port' | 'host'
    Raise khi IPv6 literal không có bracket (vd '::1') — v3.0.0 âm thầm trả (':', 1).
    """
    s = s.strip()
    if s.startswith("["):
        end = s.index("]")
        host = s[1:end]
        rest = s[end+1:].lstrip(":")
        return host, int(rest or 1080)
    if s.count(":") > 1:
        raise ValueError(
            f"IPv6 literal cần bracket: dùng [{s}]:1080 thay vì {s}")
    if ":" in s:
        h, p = s.rsplit(":", 1)
        return h, int(p)
    return s, 1080


# ══════════════════════════════════════════════════════════════════════
#   SELFTEST
# ══════════════════════════════════════════════════════════════════════

def selftest() -> int:
    import unittest

    class T(unittest.TestCase):
        def test_payloads(self):
            for name in PAYLOADS:
                b = build_payload(name)
                self.assertIsInstance(b, bytes)
                self.assertGreater(len(b), 0, f"{name} empty")

        def test_wireguard_length(self):
            # v3.0.1 fix: 132 byte (msg_type+idx+ephemeral+static+timestamp+mac1+mac2)
            self.assertEqual(len(p_wireguard_init()), 132)

        def test_text_hex_file(self):
            self.assertEqual(build_payload("text:hello"), b"hello")
            self.assertEqual(build_payload("hex:de ad be ef"), bytes.fromhex("deadbeef"))
            import tempfile
            with tempfile.NamedTemporaryFile(delete=False) as f:
                f.write(b"\x01\x02\x03")
                fn = f.name
            try:
                self.assertEqual(build_payload(f"file:{fn}"), b"\x01\x02\x03")
            finally:
                os.unlink(fn)

        def test_socks_wrap_unwrap_roundtrip_ipv4(self):
            wrapped = socks5_udp_wrap("1.2.3.4", 53, b"payload")
            ip, port, pl = socks5_udp_unwrap(wrapped)
            self.assertEqual((ip, port, pl), ("1.2.3.4", 53, b"payload"))

        def test_socks_wrap_unwrap_roundtrip_ipv6(self):
            wrapped = socks5_udp_wrap("2001:db8::1", 443, b"x")
            ip, port, pl = socks5_udp_unwrap(wrapped)
            self.assertEqual((ip, port, pl), ("2001:db8::1", 443, b"x"))

        def test_socks_wrap_domain(self):
            wrapped = socks5_udp_wrap("example.com", 53, b"q")
            ip, port, pl = socks5_udp_unwrap(wrapped)
            self.assertEqual((ip, port, pl), ("example.com", 53, b"q"))

        def test_socks_unwrap_rejects_bad(self):
            self.assertIsNone(socks5_udp_unwrap(b""))
            self.assertIsNone(socks5_udp_unwrap(b"\x01\x00\x00\x01"))
            self.assertIsNone(socks5_udp_unwrap(b"\x00\x00\x01\x01" + b"\x00" * 10))

        def test_stun_parse_ipv4(self):
            port = 5678
            ip = socket.inet_aton("1.2.3.4")
            xport = struct.pack(">H", port ^ 0x2112)
            xip = bytes(b ^ k for b, k in zip(ip, b"\x21\x12\xA4\x42"))
            attr = struct.pack(">HH", 0x0020, 8) + b"\x00\x01" + xport + xip
            pkt = struct.pack(">HHI", 0x0101, len(attr), 0x2112A442) + b"\x00" * 12 + attr
            res = parse_stun(pkt)
            self.assertEqual(res.xor_mapped, ("1.2.3.4", 5678))

        def test_stun_parse_ipv6(self):
            # v3.0.1 fix: XOR với (magic_cookie || txid) = 16 byte
            port = 5678
            ip = socket.inet_pton(socket.AF_INET6, "2001:db8::1")
            txid = b"\x00" * 12
            key = b"\x21\x12\xA4\x42" + txid
            xip = bytes(b ^ k for b, k in zip(ip, key))
            xport = struct.pack(">H", port ^ 0x2112)
            attr = struct.pack(">HH", 0x0020, 20) + b"\x00\x02" + xport + xip
            pkt = struct.pack(">HHI", 0x0101, len(attr), 0x2112A442) + txid + attr
            res = parse_stun(pkt)
            self.assertEqual(res.xor_mapped, ("2001:db8::1", 5678))

        def test_stun_parse_ipv6_random_txid(self):
            # txid không phải 0 — kiểm tra XOR dùng đúng txid
            port = 12345
            ip = socket.inet_pton(socket.AF_INET6, "fe80::abcd")
            txid = os.urandom(12)
            key = b"\x21\x12\xA4\x42" + txid
            xip = bytes(b ^ k for b, k in zip(ip, key))
            xport = struct.pack(">H", port ^ 0x2112)
            attr = struct.pack(">HH", 0x0020, 20) + b"\x00\x02" + xport + xip
            pkt = struct.pack(">HHI", 0x0101, len(attr), 0x2112A442) + txid + attr
            res = parse_stun(pkt)
            self.assertEqual(res.xor_mapped, ("fe80::abcd", port))

        def test_percentile_tracker(self):
            p = PercentileTracker(100)
            for i in range(1, 101):
                p.add(float(i))
            self.assertAlmostEqual(p.pct(50), 50, delta=1)
            self.assertAlmostEqual(p.pct(95), 95, delta=1)
            self.assertAlmostEqual(p.pct(99), 99, delta=1)

        def test_target_parse(self):
            self.assertEqual(parse_target_arg("8.8.8.8"), ("8.8.8.8", 53, "dns-a"))
            self.assertEqual(parse_target_arg("8.8.8.8:53"), ("8.8.8.8", 53, "dns-a"))
            self.assertEqual(parse_target_arg("8.8.8.8:53:stun"), ("8.8.8.8", 53, "stun"))
            self.assertEqual(parse_target_arg("[2001:db8::1]:443"), ("2001:db8::1", 443, "dns-a"))

        def test_target_parse_ipv6_no_bracket_raises(self):
            with self.assertRaises(ValueError):
                parse_target_arg("2001:db8::1:53")

        def test_proxy_parse(self):
            self.assertEqual(parse_proxy_arg("127.0.0.1"), ("127.0.0.1", 1080))
            self.assertEqual(parse_proxy_arg("127.0.0.1:1081"), ("127.0.0.1", 1081))
            self.assertEqual(parse_proxy_arg("[::1]:1080"), ("::1", 1080))
            self.assertEqual(parse_proxy_arg("[::1]"), ("::1", 1080))

        def test_proxy_parse_ipv6_no_bracket_raises(self):
            # v3.0.1 fix: trước đây trả (':', 1) âm thầm
            with self.assertRaises(ValueError):
                parse_proxy_arg("::1")

        def test_yaml_minimal(self):
            txt = """
            # comment
            proxy: 127.0.0.1:1080
            interval: 5.5
            quiet: true
            targets:
              - 8.8.8.8:53
              - 1.1.1.1:53:stun
            """
            cfg = _yaml_minimal(txt)
            self.assertEqual(cfg["proxy"], "127.0.0.1:1080")
            self.assertEqual(cfg["interval"], 5.5)
            self.assertTrue(cfg["quiet"])
            self.assertEqual(cfg["targets"], ["8.8.8.8:53", "1.1.1.1:53:stun"])

        def test_health_transition(self):
            s = Stats()
            for _ in range(10):
                s.recent_oks.append(1)
            s.sent = 10; s.recv = 10
            s.update_health()
            self.assertEqual(s.health, Health.HEALTHY)
            for _ in range(8):
                s.recent_oks.append(0)
            s.update_health(down_pct=50)
            self.assertEqual(s.health, Health.DOWN)

    suite = unittest.TestLoader().loadTestsFromTestCase(T)
    res = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if res.wasSuccessful() else 1


# ══════════════════════════════════════════════════════════════════════
#   CLI
# ══════════════════════════════════════════════════════════════════════

def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="udp.py",
        description=f"UDP keep-alive qua SOCKS5 — v{VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--proxy", action="append", default=[],
                    help="proxy host[:port] (lặp nhiều lần → failover round-robin)")
    ap.add_argument("--host", default=None, help="(v1) đích đơn")
    ap.add_argument("--port", type=int, default=53, help="(v1) port đích")
    ap.add_argument("--stun", action="store_true",
                    help="(v1) shorthand: payload stun tới Google STUN")
    ap.add_argument("--user", default=None)
    ap.add_argument("--password", default=None)

    ap.add_argument("--interval", type=float, default=20.0)
    ap.add_argument("--timeout", type=float, default=5.0)
    ap.add_argument("--jitter", type=float, default=0.15,
                    help="±%% interval (mặc định 0.15)")

    ap.add_argument("--target", action="append", default=[],
                    help="host[:port[:payload]] — lặp nhiều lần")
    ap.add_argument("--targets-file", help="file text, mỗi dòng 1 target")
    ap.add_argument("--payload", default=None,
                    help="dns-a|dns-aaaa|dns-mx|dns-txt|dns-ptr|doh|stun|ntp|"
                         "quic|wireguard|mdns|dhcp|text:STR|hex:HEX|file:PATH")

    ap.add_argument("--output", choices=["text", "json"], default="text")
    ap.add_argument("--log-file", help="ghi CSV mỗi probe")
    ap.add_argument("--json-log-file", help="ghi JSON Lines (có rotate)")
    ap.add_argument("--metrics-port", type=int, help="Prometheus /metrics")

    ap.add_argument("--alert-loss", type=float, default=None,
                    help="cảnh báo khi loss%% cửa sổ 20 probe >= giá trị")
    ap.add_argument("--alert-webhook", default=None,
                    help="URL nhận alert (Slack/Discord/generic JSON POST)")
    ap.add_argument("--alert-cooldown", type=float, default=30.0,
                    help="giây chống spam alert cho cùng key")

    ap.add_argument("--config", help="file JSON/YAML cấu hình (CLI override)")
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--no-concurrent", action="store_true",
                    help="tắt probe song song khi nhiều target")
    ap.add_argument("--concurrency", type=int, default=16)
    ap.add_argument("--no-adaptive", action="store_true",
                    help="tắt tự tăng tần suất khi loss cao")
    ap.add_argument("--dry-run", action="store_true",
                    help="in cấu hình đã resolve rồi thoát (không kết nối)")
    ap.add_argument("--list-payloads", action="store_true")
    ap.add_argument("--validate", action="store_true",
                    help="chỉ validate cấu hình + targets, không chạy")
    ap.add_argument("--selftest", action="store_true",
                    help="chạy self-test in-process (không cần proxy)")
    ap.add_argument("--version", action="version", version=f"udpka {VERSION}")
    return ap


def resolve_args(args: argparse.Namespace) -> argparse.Namespace:
    if args.config:
        try:
            cfg = load_config(args.config)
        except (OSError, ValueError, json.JSONDecodeError) as e:
            print(f"[!] config load fail: {e}", file=sys.stderr)
            sys.exit(2)
        for k, v in cfg.items():
            key = k.replace("-", "_")
            if hasattr(args, key) and getattr(args, key) in (None, [], "", 0, 0.0, False):
                setattr(args, key, v)

    apply_env_overrides(args)

    if not args.target and not args.targets_file:
        if args.stun:
            args.target = ["stun.l.google.com:19302:stun"]
        elif args.host:
            args.target = [f"{args.host}:{args.port}:{args.payload or 'dns-a'}"]
        else:
            args.target = ["8.8.8.8:53:dns-a"]

    if not args.proxy:
        args.proxy = ["127.0.0.1:1080"]

    return args


def build_targets(args: argparse.Namespace) -> list[Target]:
    targets: list[Target] = []
    seen: set[str] = set()

    def add(host: str, port: int, payload: str) -> None:
        key = f"{host}:{port}:{payload}"
        if key in seen:
            return
        seen.add(key)
        targets.append(Target(host=host, port=port, payload=payload))

    for spec in args.target:
        h, p, pay = parse_target_arg(spec)
        add(h, p, args.payload or pay)
    if args.targets_file:
        with open(args.targets_file) as f:
            for ln in f:
                ln = ln.strip()
                if not ln or ln.startswith("#"):
                    continue
                h, p, pay = parse_target_arg(ln)
                add(h, p, args.payload or pay)

    for t in targets:
        if t.payload not in PAYLOADS and not (
            t.payload.startswith("text:") or
            t.payload.startswith("hex:") or
            t.payload.startswith("file:")
        ):
            raise ValueError(f"unknown payload in target {t}: {t.payload}")

    return targets


def main() -> int:
    args = build_parser().parse_args()

    if args.list_payloads:
        print("Available payloads:")
        for k in sorted(PAYLOADS):
            doc = (PAYLOADS[k].__doc__ or "").strip().splitlines()
            doc = doc[0] if doc else ""
            print(f"  {k:<12} {doc}")
        print("\nSpecial forms:")
        print("  text:STR              UTF-8 text payload")
        print("  hex:DEADBEEF          raw bytes from hex")
        print("  file:/path/file.bin   raw bytes from file")
        return 0

    if args.selftest:
        return selftest()

    args = resolve_args(args)

    try:
        proxies = [parse_proxy_arg(p) for p in args.proxy]
        targets = build_targets(args)
    except (ValueError, OSError) as e:
        print(f"[!] invalid config: {e}", file=sys.stderr)
        return 2

    if args.dry_run:
        print("Resolved config:")
        print(f"  version     : {VERSION}")
        print(f"  proxies     : {proxies}")
        print(f"  targets     : {len(targets)}")
        for t in targets:
            print(f"    - {t}  payload={t.payload}")
        print(f"  interval    : {args.interval}s (±{args.jitter*100:.0f}%)")
        print(f"  timeout     : {args.timeout}s")
        print(f"  output      : {args.output}")
        print(f"  concurrent  : {not args.no_concurrent}")
        print(f"  adaptive    : {not args.no_adaptive}")
        print(f"  log-file    : {args.log_file}")
        print(f"  json-log    : {args.json_log_file}")
        print(f"  metrics     : {args.metrics_port}")
        print(f"  alert-loss  : {args.alert_loss}")
        print(f"  alert-hook  : {args.alert_webhook}")
        print(f"  auth        : {'yes' if args.user else 'no'}")
        return 0

    if args.validate:
        print(f"OK — {len(proxies)} proxies, {len(targets)} targets")
        return 0

    ka = UDPKeepAlive(
        proxies=proxies,
        targets=targets,
        interval=args.interval,
        timeout=args.timeout,
        jitter=args.jitter,
        user=args.user,
        password=args.password,
        output=args.output,
        log_file=args.log_file,
        json_log_file=args.json_log_file,
        alert_loss=args.alert_loss,
        alert_webhook=args.alert_webhook,
        alert_cooldown=args.alert_cooldown,
        quiet=args.quiet,
        color=not args.no_color,
        concurrent=not args.no_concurrent,
        concurrency=args.concurrency,
        adaptive=not args.no_adaptive,
    )

    if args.metrics_port:
        try:
            start_metrics_server(args.metrics_port, ka)
            if not args.quiet:
                print(f"[*] Prometheus /metrics: http://127.0.0.1:{args.metrics_port}/metrics")
        except Exception as e:
            print(f"[!] metrics server fail: {e}", file=sys.stderr)

    def on_sig(sig: int, frame: Any) -> None:
        ka.stop = True
        if not ka.quiet:
            print(f"\n[*] nhận signal {sig}, đang dừng...", flush=True)

    signal.signal(signal.SIGINT, on_sig)
    signal.signal(signal.SIGTERM, on_sig)

    ka.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
