#!/usr/bin/env python3
"""
Test SOCKS5 UDP relay — bản đã fix v6.3.6.

Fix so với bản gốc:
  1. recv_exact(): đọc đủ N byte, an toàn với TCP partial-read.
  2. Không NameError khi source IPv6: src_addr/src_port luôn được set.
  3. Header SOCKS5 UDP có độ dài đúng cho IPv6 (22 byte, không phải 10).
  4. UDP client socket chọn family theo BND.ADDR (không hard-code AF_INET).
  5. try/finally đóng cả 2 socket kể cả khi lỗi/timeout.
  6. resolve target bằng getaddrinfo + ipaddress (hỗ trợ IPv4-mapped IPv6).
  7. Parse DNS response đầy đủ — in A/AAAA record (skip Question đúng cách).
  8. Cảnh báo khi BND.ADDR = 0.0.0.0/:: (bug cũ có thể trả giá trị này).
  9. Exit code 0/1 để dùng được trong CI.

Usage:
    python3 test.py
    python3 test.py --proxy-host 127.0.0.1 --proxy-port 1080
    python3 test.py --target 1.1.1.1 --domain cloudflare.com
    python3 test.py --auth user:pass
    python3 test.py --ipv6                    # target = Google DNS IPv6
    python3 test.py --timeout 10
"""
import argparse
import ipaddress
import socket
import struct
import sys

DEFAULT_PROXY_HOST = '127.0.0.1'
DEFAULT_PROXY_PORT = 1080
DEFAULT_TARGET_HOST = '8.8.8.8'
DEFAULT_TARGET_PORT = 53
DEFAULT_DOMAIN = 'example.com'


def recv_exact(sock, n, timeout=5.0):
    """Đọc chính xác n byte từ TCP socket — an toàn với partial-read."""
    sock.settimeout(timeout)
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError(f"EOF sau {len(buf)}/{n} byte")
        buf += chunk
    return buf


def build_dns_query(domain, txid=b'\x12\x34'):
    header = (txid + b'\x01\x00'                    # flags: standard query, RD=1
              + b'\x00\x01'                          # QDCOUNT=1
              + b'\x00\x00\x00\x00\x00\x00')         # AN/NS/AR=0
    qname = b''
    for label in domain.split('.'):
        b = label.encode('ascii')
        if not (1 <= len(b) <= 63):
            raise ValueError(f"DNS label sai độ dài: {label!r}")
        qname += bytes([len(b)]) + b
    qname += b'\x00'
    return header + qname + b'\x00\x01' + b'\x00\x01'  # QTYPE=A, QCLASS=IN


def parse_dns_response(payload, txid=b'\x12\x34'):
    """Trả dict {'valid': bool, ...} hoặc None nếu payload quá ngắn."""
    if len(payload) < 12:
        return None
    if payload[0:2] != txid:
        return {'valid': False, 'reason': 'transaction ID mismatch'}

    flags = struct.unpack('!H', payload[2:4])[0]
    rcode = flags & 0x000F
    qd = struct.unpack('!H', payload[4:6])[0]
    an = struct.unpack('!H', payload[6:8])[0]

    # Skip Question section
    pos = 12
    try:
        for _ in range(qd):
            # NAME
            while True:
                if pos >= len(payload):
                    raise IndexError
                l = payload[pos]
                if l == 0:
                    pos += 1
                    break
                if (l & 0xC0) == 0xC0:
                    pos += 2
                    break
                pos += 1 + l
            pos += 4  # QTYPE + QCLASS
    except IndexError:
        return {'valid': True, 'rcode': rcode, 'ancount': an, 'answers': []}

    answers = []
    for _ in range(an):
        if pos >= len(payload):
            break
        # NAME (có thể là compression pointer hoặc chuỗi label)
        if (payload[pos] & 0xC0) == 0xC0:
            pos += 2
        else:
            while pos < len(payload) and payload[pos] != 0:
                pos += 1 + payload[pos]
            pos += 1
        if pos + 10 > len(payload):
            break
        rtype, rclass, ttl, rdlen = struct.unpack('!HHIH', payload[pos:pos + 10])
        pos += 10
        if pos + rdlen > len(payload):
            break
        rdata = payload[pos:pos + rdlen]
        pos += rdlen
        if rtype == 1 and rdlen == 4:
            answers.append(('A', socket.inet_ntoa(rdata), ttl))
        elif rtype == 28 and rdlen == 16:
            answers.append(('AAAA', socket.inet_ntop(socket.AF_INET6, rdata), ttl))

    return {'valid': True, 'rcode': rcode, 'ancount': an, 'answers': answers}


def resolve_target(host, port):
    """Trả (ip_string, is_ipv6). Hỗ trợ literal IPv4, IPv6, IPv4-mapped, hostname."""
    try:
        ip = ipaddress.ip_address(host)
        if ip.version == 6 and ip.ipv4_mapped is not None:
            return str(ip.ipv4_mapped), False
        return str(ip), ip.version == 6
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)
    except socket.gaierror as e:
        raise ConnectionError(f"Không resolve được {host!r}: {e}")
    if not infos:
        raise ConnectionError(f"Không resolve được {host!r}")
    fam, _, _, _, sa = infos[0]
    return sa[0], (fam == socket.AF_INET6)


def socks5_userpass_auth(tcp, user, password, timeout):
    u = user.encode('utf-8')
    p = password.encode('utf-8')
    if len(u) > 255 or len(p) > 255:
        raise ValueError("Username/password > 255 byte")
    tcp.sendall(b'\x01' + bytes([len(u)]) + u + bytes([len(p)]) + p)
    resp = recv_exact(tcp, 2, timeout)
    return resp[1] == 0x00


def test_udp(proxy_host, proxy_port, target_host, target_port,
             domain, auth, timeout):
    tcp = None
    udp = None
    try:
        # ---------- 1. TCP control ----------
        try:
            tcp = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
        except OSError as e:
            print(f"[-] Không kết nối được proxy {proxy_host}:{proxy_port} — {e}")
            return 1
        proxy_side_ip, proxy_side_port = tcp.getsockname()
        print(f"[*] TCP tới {proxy_host}:{proxy_port} "
              f"(client side {proxy_side_ip}:{proxy_side_port})")

        # Greeting
        methods = b'\x05\x02\x00\x02' if auth else b'\x05\x01\x00'
        tcp.sendall(methods)
        resp = recv_exact(tcp, 2, timeout)
        if resp[0] != 0x05:
            print(f"[-] Version không phải 5: {resp.hex()}")
            return 1
        chosen = resp[1]
        if chosen == 0xFF:
            print("[-] Proxy từ chối tất cả auth method")
            return 1
        if chosen == 0x02:
            if not auth:
                print("[-] Proxy yêu cầu auth nhưng thiếu --auth user:pass")
                return 1
            if not socks5_userpass_auth(tcp, auth[0], auth[1], timeout):
                print("[-] Auth thất bại")
                return 1
            print("[+] Auth OK")
        else:
            print("[+] No-auth OK")

        # ---------- 2. UDP ASSOCIATE ----------
        tcp.sendall(b'\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00')

        head = recv_exact(tcp, 4, timeout)
        ver, rep, _, atyp = head
        if ver != 5:
            print(f"[-] Reply version không phải 5: {ver}")
            return 1
        if rep != 0:
            print(f"[-] UDP ASSOCIATE thất bại rep=0x{rep:02x}")
            return 1

        if atyp == 0x01:
            rest = recv_exact(tcp, 6, timeout)
            bnd_addr = socket.inet_ntoa(rest[:4])
            bnd_port = struct.unpack('!H', rest[4:6])[0]
            bnd_family = socket.AF_INET
        elif atyp == 0x04:
            rest = recv_exact(tcp, 18, timeout)
            bnd_addr = socket.inet_ntop(socket.AF_INET6, rest[:16])
            bnd_port = struct.unpack('!H', rest[16:18])[0]
            bnd_family = socket.AF_INET6
        else:
            print(f"[-] ATYP không hỗ trợ: 0x{atyp:02x}")
            return 1

        print(f"[+] UDP relay: {bnd_addr}:{bnd_port}")

        # ---------- 3. Verify BND.ADDR (fix v6.3.6) ----------
        # Trên loopback, IP client == IP proxy == 127.0.0.1 nên không phân biệt được.
        # Trên LAN/Internet: nếu BND.ADDR != IP proxy mà client thấy, hoặc == 0.0.0.0,
        # thì bug cũ đang tái diễn.
        if bnd_addr in ('0.0.0.0', '::'):
            print("[!] CẢNH BÁO: BND.ADDR = 0.0.0.0/:: — client không biết gửi UDP tới đâu")
        else:
            print("[+] BND.ADDR hợp lệ (không phải 0.0.0.0)")

        # ---------- 4. UDP client ----------
        udp = socket.socket(bnd_family, socket.SOCK_DGRAM)
        udp.settimeout(timeout)

        target_ip, target_is_v6 = resolve_target(target_host, target_port)
        payload = build_dns_query(domain)

        # SOCKS5 UDP header: RSV(2) FRAG(1) ATYP(1) DST.ADDR DST.PORT DATA
        if target_is_v6:
            hdr = b'\x00\x00\x00\x04' + socket.inet_pton(socket.AF_INET6, target_ip)
        else:
            hdr = b'\x00\x00\x00\x01' + socket.inet_aton(target_ip)
        hdr += struct.pack('!H', target_port)

        packet = hdr + payload
        udp.sendto(packet, (bnd_addr, bnd_port))
        print(f"[+] Gửi {len(packet)} bytes UDP → relay "
              f"→ {target_ip}:{target_port} ({domain})")

        # ---------- 5. Nhận phản hồi ----------
        try:
            data, from_addr = udp.recvfrom(4096)
        except socket.timeout:
            print(f"[-] Timeout sau {timeout}s — không nhận UDP reply")
            print("    Kiểm tra: firewall UDP outbound? target block DNS từ bạn?")
            return 1

        if len(data) < 4:
            print(f"[-] Response quá ngắn: {data.hex()}")
            return 1

        src_atyp = data[3]
        if src_atyp == 0x01:
            if len(data) < 10:
                print(f"[-] Response IPv4 quá ngắn: {data.hex()}")
                return 1
            src_addr = socket.inet_ntoa(data[4:8])
            src_port = struct.unpack('!H', data[8:10])[0]
            payload = data[10:]
        elif src_atyp == 0x04:
            if len(data) < 22:
                print(f"[-] Response IPv6 quá ngắn: {data.hex()}")
                return 1
            src_addr = socket.inet_ntop(socket.AF_INET6, data[4:20])
            src_port = struct.unpack('!H', data[20:22])[0]
            payload = data[22:]
        else:
            print(f"[-] Response ATYP không hỗ trợ: 0x{src_atyp:02x}")
            return 1

        print(f"[+] Nhận {len(payload)} bytes từ {src_addr}:{src_port} "
              f"(UDP raw từ {from_addr[0]}:{from_addr[1]})")

        # ---------- 6. Parse DNS ----------
        result = parse_dns_response(payload)
        if result is None:
            print("[?] Payload quá ngắn, không phải DNS")
            return 0
        if not result['valid']:
            print(f"[?] Không phải DNS response ({result.get('reason', '?')})")
            return 0
        if result['rcode'] != 0:
            print(f"[!] DNS RCODE={result['rcode']} (lỗi resolver)")
            return 1
        print(f"[+] DNS hợp lệ: RCODE=0 Answers={result['ancount']}")
        if not result['answers']:
            print("[!] Không có A/AAAA record")
            return 1
        for rtype, addr, ttl in result['answers']:
            print(f"    {rtype:<4} {addr}  (TTL {ttl})")
        print("\n[✅] UDP QUA SOCKS5 HOẠT ĐỘNG HOÀN HẢO!")
        return 0

    except ConnectionError as e:
        print(f"[-] Lỗi kết nối: {e}")
        return 1
    except socket.timeout:
        print("[-] Timeout (handshake)")
        return 1
    except KeyboardInterrupt:
        print("\n[!] Ngắt bởi user")
        return 130
    except Exception as e:
        print(f"[-] Lỗi không mong đợi: {type(e).__name__}: {e}")
        return 1
    finally:
        for s in (udp, tcp):
            if s is not None:
                try: s.close()
                except Exception: pass


def main():
    p = argparse.ArgumentParser(description="Test SOCKS5 UDP relay (v6.3.6)")
    p.add_argument('--proxy-host', default=DEFAULT_PROXY_HOST)
    p.add_argument('--proxy-port', type=int, default=DEFAULT_PROXY_PORT)
    p.add_argument('--target', default=DEFAULT_TARGET_HOST,
                   help='DNS server IP/hostname (mặc định 8.8.8.8)')
    p.add_argument('--target-port', type=int, default=DEFAULT_TARGET_PORT)
    p.add_argument('--domain', default=DEFAULT_DOMAIN)
    p.add_argument('--auth', default=None, help='user:pass nếu proxy yêu cầu')
    p.add_argument('--timeout', type=float, default=5.0)
    p.add_argument('--ipv6', action='store_true',
                   help='Dùng Google DNS IPv6 (2001:4860:4860::8888)')
    args = p.parse_args()

    if args.ipv6:
        args.target = '2001:4860:4860::8888'

    auth = None
    if args.auth:
        u, sep, pw = args.auth.partition(':')
        if not sep:
            print("[-] --auth phải có dạng user:pass")
            return 2
        auth = (u, pw)

    return test_udp(args.proxy_host, args.proxy_port,
                    args.target, args.target_port,
                    args.domain, auth, args.timeout)


if __name__ == '__main__':
    sys.exit(main())
