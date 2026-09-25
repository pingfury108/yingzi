#!/usr/bin/env python3
"""SOCKS5 UDP ASSOCIATE 端到端测试: 经 yz 隧道做一次 UDP DNS 查询。"""
import socket
import struct
import sys

target = sys.argv[1] if len(sys.argv) > 1 else "223.5.5.5"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 53

# 1) TCP 上建立 UDP ASSOCIATE
t = socket.create_connection(("127.0.0.1", 1080), timeout=5)
t.sendall(b"\x05\x01\x00")
assert t.recv(2) == b"\x05\x00", "socks5 greet failed"
t.sendall(b"\x05\x03\x00\x01" + socket.inet_aton("0.0.0.0") + struct.pack("!H", 0))
r = t.recv(10)
assert r[1] == 0, f"associate failed: {r!r}"
relay = (socket.inet_ntoa(r[4:8]), struct.unpack("!H", r[8:10])[0])
print(f"relay = {relay[0]}:{relay[1]}")

# 2) 经 relay 发 UDP 数据报 (SOCKS5 UDP 头 + DNS 查询)
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
u.settimeout(10)
header = b"\x00\x00\x00\x01" + socket.inet_aton(target) + struct.pack("!H", port)
dns = (
    b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    b"\x06google\x03com\x00\x00\x01\x00\x01"
)
u.sendto(header + dns, relay)
try:
    d, frm = u.recvfrom(4096)
except socket.timeout:
    print("FAIL: 超时, 无应答")
    sys.exit(1)

# 3) 解析 SOCKS5 UDP 应答头
assert d[3] == 1, f"bad reply header {d[:12]!r}"
src = socket.inet_ntoa(d[4:8])
sport = struct.unpack("!H", d[8:10])[0]
body = d[10:]
ancount = struct.unpack("!H", body[6:8])[0]
print(f"应答 {len(d)}B, 来源 {src}:{sport}, ANCOUNT={ancount}")
ips = []
i = 12
while body[i] != 0:
    i += body[i] + 1
i += 5
for _ in range(ancount):
    if body[i + 1] == 1 and body[i + 3] == 4:
        ips.append(socket.inet_ntoa(body[i + 4:i + 8]))
        break
    i += 12
print("解析结果:", ips or "(非 A 记录)")
print("PASS: UDP 经 mesh 出口成功" if ancount > 0 else "WARN: 无应答记录")
