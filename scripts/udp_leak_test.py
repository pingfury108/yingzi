#!/usr/bin/env python3
"""UDP ASSOCIATE 泄漏复现测试。

模拟浏览器行为: 反复建立 UDP ASSOCIATE → 发几个目标的包 → 直接关闭 TCP(不通知)。
如果节点存在关联生命周期泄漏, 每轮会泄漏 1(中继)+N(目标) 个 socket。

用法: python3 udp_leak_test.py [轮数=30] [socks5=127.0.0.1:1080]
"""
import socket
import struct
import sys
import time

rounds = int(sys.argv[1]) if len(sys.argv) > 1 else 30
proxy = ("127.0.0.1", 1080)
if len(sys.argv) > 2:
    hp = sys.argv[2].split(":")
    proxy = (hp[0], int(hp[1]))

targets = [("223.5.5.5", 53), ("119.29.29.29", 53), ("1.1.1.1", 53)]
dns = (
    b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    b"\x06google\x03com\x00\x00\x01\x00\x01"
)

for i in range(rounds):
    t = socket.create_connection(proxy, timeout=5)
    t.sendall(b"\x05\x01\x00")
    assert t.recv(2) == b"\x05\x00"
    t.sendall(b"\x05\x03\x00\x01" + socket.inet_aton("0.0.0.0") + struct.pack("!H", 0))
    r = t.recv(10)
    assert r[1] == 0, f"associate failed: {r!r}"
    relay = (socket.inet_ntoa(r[4:8]), struct.unpack("!H", r[8:10])[0])

    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.settimeout(0.2)
    for ip, port in targets:
        pkt = b"\x00\x00\x00\x01" + socket.inet_aton(ip) + struct.pack("!H", port) + dns
        try:
            u.sendto(pkt, relay)  # 不等应答, 模拟真实浏览器的丢弃行为
        except OSError:
            pass
    u.close()
    t.close()  # 直接扔掉 TCP —— 浏览器的典型用法
    time.sleep(0.05)

print(f"{rounds} 轮关联已建立并丢弃 (每轮 3 个目标)")
