#!/usr/bin/env python3
import socket
import struct
import sys

PROXY_HOST = '127.0.0.1'
PROXY_PORT = 1080
TARGET_HOST = '8.8.8.8'   # DNS Google
TARGET_PORT = 53

def build_dns_query(domain='example.com'):
    """Tạo DNS query đơn giản cho A record."""
    txid = b'\x12\x34'
    flags = b'\x01\x00'          # standard query, recursion desired
    qdcount = b'\x00\x01'
    ancount = b'\x00\x00'
    nscount = b'\x00\x00'
    arcount = b'\x00\x00'
    header = txid + flags + qdcount + ancount + nscount + arcount

    qname = b''
    for part in domain.split('.'):
        qname += bytes([len(part)]) + part.encode()
    qname += b'\x00'
    qtype = b'\x00\x01'   # A
    qclass = b'\x00\x01'  # IN
    return header + qname + qtype + qclass

def test_udp_through_socks5():
    # 1. TCP control connection tới proxy
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.settimeout(5)
    tcp.connect((PROXY_HOST, PROXY_PORT))

    # Greeting: no auth
    tcp.sendall(b'\x05\x01\x00')
    if tcp.recv(2) != b'\x05\x00':
        print("[-] SOCKS5 handshake thất bại")
        return

    # UDP ASSOCIATE
    req = b'\x05\x03\x00\x01' + struct.pack('!I', 0) + struct.pack('!H', 0)
    tcp.sendall(req)
    resp = tcp.recv(10)

    if len(resp) < 10 or resp[1] != 0x00:
        print(f"[-] UDP ASSOCIATE thất bại: {resp.hex()}")
        return

    atyp = resp[3]
    if atyp == 0x01:  # IPv4
        bnd_addr = socket.inet_ntoa(resp[4:8])
        bnd_port = struct.unpack('!H', resp[8:10])[0]
    elif atyp == 0x04:  # IPv6
        bnd_addr = socket.inet_ntop(socket.AF_INET6, resp[4:20])
        bnd_port = struct.unpack('!H', resp[20:22])[0]
    else:
        print(f"[-] ATYP không hỗ trợ: {atyp}")
        return

    print(f"[+] UDP relay: {bnd_addr}:{bnd_port}")

    # 2. UDP socket gửi dữ liệu qua relay
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.settimeout(5)

    # DNS query
    dns_payload = build_dns_query('example.com')

    # Đóng gói theo SOCKS5 UDP request header:
    # RSV(2) + FRAG(1) + ATYP(1) + DST.ADDR + DST.PORT + DATA
    udp_header = b'\x00\x00' + b'\x00' + b'\x01'
    udp_header += socket.inet_aton(TARGET_HOST)
    udp_header += struct.pack('!H', TARGET_PORT)

    packet = udp_header + dns_payload
    udp.sendto(packet, (bnd_addr, bnd_port))
    print(f"[+] Đã gửi {len(packet)} bytes UDP tới relay")

    # 3. Nhận phản hồi
    try:
        data, addr = udp.recvfrom(4096)
    except socket.timeout:
        print("[-] Timeout: không nhận được phản hồi UDP")
        return

    # Bỏ header SOCKS5 UDP (10 bytes cho IPv4)
    # RSV(2) + FRAG(1) + ATYP(1) + ADDR(4) + PORT(2) = 10
    if len(data) < 10:
        print(f"[-] Response quá ngắn: {data.hex()}")
        return

    src_atyp = data[3]
    if src_atyp == 0x01:
        src_addr = socket.inet_ntoa(data[4:8])
        src_port = struct.unpack('!H', data[8:10])[0]
        payload = data[10:]
    else:
        payload = data[10:]

    print(f"[+] Nhận {len(payload)} bytes từ {src_addr}:{src_port}")
    print(f"[+] DNS response (hex): {payload[:32].hex()}...")

    # Kiểm tra có phải DNS response
    if len(payload) >= 12 and payload[0:2] == b'\x12\x34':
        flags = payload[2:4]
        rcode = flags[1] & 0x0F
        ancount = struct.unpack('!H', payload[6:8])[0]
        print(f"[+] DNS response hợp lệ! RCODE={rcode}, Answers={ancount}")
        if rcode == 0 and ancount > 0:
            print("[✅] UDP QUA SOCKS5 HOẠT ĐỘNG HOÀN HẢO!")
        else:
            print("[!] DNS response có lỗi")
    else:
        print("[?] Không phải DNS response")

    udp.close()
    tcp.close()

if __name__ == '__main__':
    test_udp_through_socks5()
