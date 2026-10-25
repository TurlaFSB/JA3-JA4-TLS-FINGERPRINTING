#!/usr/bin/env python3
# © Pranav Verma | 2026
"""Writes testdata/synthetic/synthetic-dns-ssh.pcap.

A SYNTHETIC capture, built from scratch by this script: plain DNS lookups
(including failures and one random-looking name) and one SSH connection. It
exists so the DNS page and the SSH rows can be demonstrated and tested without
anybody's real traffic. Nothing in it was observed on a network.

    python3 scripts/make-demo-capture.py
"""
import hashlib
import random
import struct
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "testdata/synthetic/synthetic-dns-ssh.pcap"
rng = random.Random(7)  # fixed seed: the file is reproducible

CLIENTS = ["10.20.0.11", "10.20.0.12", "10.20.0.27"]
RESOLVER = "10.20.0.1"
SSH_SERVER = "203.0.113.50"


def ip(text):
    return bytes(int(x) for x in text.split("."))


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def ipv4(src, dst, proto, payload):
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), rng.randrange(65536), 0x4000, 64, proto, 0, ip(src), ip(dst))
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return header + payload


def ether(payload):
    return bytes.fromhex("020000000001") + bytes.fromhex("020000000002") + b"\x08\x00" + payload


def udp(src, dst, sport, dport, data):
    return ether(ipv4(src, dst, 17, struct.pack("!HHHH", sport, dport, 8 + len(data), 0) + data))


def tcp(src, dst, sport, dport, seq, ack, flags, data=b"", options=b""):
    offset = (20 + len(options)) // 4
    header = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, offset << 4, flags, 64240, 0, 0) + options
    return ether(ipv4(src, dst, 6, header + data))


def qname(name):
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"


def dns_query(txid, name, qtype=1):
    return struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + qname(name) + struct.pack("!HH", qtype, 1)


def dns_response(txid, name, addrs, rcode=0, qtype=1):
    body = struct.pack("!HHHHHH", txid, 0x8180 | rcode, 1, len(addrs), 0, 0) + qname(name) + struct.pack("!HH", qtype, 1)
    for a in addrs:
        body += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + ip(a)
    return body


def ssh_packet(banner, kex, enc, mac):
    def lst(items):
        j = ",".join(items).encode()
        return struct.pack("!I", len(j)) + j

    payload = bytes([20]) + bytes(range(16))
    for items in (kex, ["ssh-ed25519", "rsa-sha2-512"], enc, enc, mac, mac, ["none"], ["none"], [], []):
        payload += lst(items)
    payload += b"\0" + bytes(4)
    pad = 8 - (len(payload) + 1) % 8
    body = bytes([pad]) + payload + bytes(pad)
    return banner.encode() + b"\r\n" + struct.pack("!I", len(body)) + body


NAMES = {
    "www.example.com": ["93.184.216.34"],
    "api.github.com": ["140.82.112.5"],
    "updates.vendor.example": ["198.51.100.20", "198.51.100.21"],
    "cdn.static.example": ["192.0.2.80"],
    "mail.example.org": ["203.0.113.25"],
    "login.microsoftonline.com": ["20.190.151.9"],
}
BAD = ["old-printer.corp.example", "wpad.corp.example", "typo-gogle.example", "vpn-legacy.corp.example"]
RANDOM = ["x7f3k9q2m8z1v5b4n6.tunnel.example", "q9w8e7r6t5y4u3i2o1p0.tunnel.example"]

frames = []
t = 1_700_000_000.0
txid = 0x1000


def add(data, dt=0.05):
    global t
    t += dt
    frames.append((t, data))


for round_ in range(6):
    for client in CLIENTS:
        for name, addrs in NAMES.items():
            if rng.random() < 0.55:
                txid += 1
                port = 30000 + rng.randrange(20000)
                add(udp(client, RESOLVER, port, 53, dns_query(txid, name)), 0.07)
                add(udp(RESOLVER, client, 53, port, dns_response(txid, name, addrs)), 0.01)
        if rng.random() < 0.5:
            name = rng.choice(BAD)
            txid += 1
            port = 30000 + rng.randrange(20000)
            add(udp(client, RESOLVER, port, 53, dns_query(txid, name)), 0.05)
            add(udp(RESOLVER, client, 53, port, dns_response(txid, name, [], rcode=3)), 0.01)
for name in RANDOM:
    txid += 1
    add(udp("10.20.0.27", RESOLVER, 41000, 53, dns_query(txid, name, 16)), 0.2)
    add(udp(RESOLVER, "10.20.0.27", 53, 41000, dns_response(txid, name, [], rcode=3, qtype=16)), 0.01)

# One SSH connection from a client to a server on port 22, SYN included.
c, s = "10.20.0.12", SSH_SERVER
mss = bytes([2, 4, 5, 0xB4, 1, 3, 3, 8, 4, 2, 1, 1])
add(tcp(c, s, 52000, 22, 1000, 0, 0x02, options=mss), 0.3)
add(tcp(s, c, 22, 52000, 5000, 1001, 0x12, options=mss), 0.02)
server = ssh_packet("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13", ["sntrup761x25519-sha512@openssh.com", "curve25519-sha256"], ["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com"], ["umac-128-etm@openssh.com", "hmac-sha2-512-etm@openssh.com"])
client = ssh_packet("SSH-2.0-OpenSSH_9.7", ["sntrup761x25519-sha512@openssh.com", "curve25519-sha256", "ecdh-sha2-nistp256"], ["chacha20-poly1305@openssh.com", "aes128-ctr", "aes256-gcm@openssh.com"], ["umac-128-etm@openssh.com", "hmac-sha2-256-etm@openssh.com"])
add(tcp(s, c, 22, 52000, 5001, 1001, 0x18, server), 0.02)
add(tcp(c, s, 52000, 22, 1001, 5001 + len(server), 0x18, client), 0.02)

with open(OUT, "wb") as f:
    f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for ts, data in frames:
        sec = int(ts)
        f.write(struct.pack("<IIII", sec, int((ts - sec) * 1e6), len(data), len(data)))
        f.write(data)
print(f"{OUT.name}: {len(frames)} frames, sha256 {hashlib.sha256(OUT.read_bytes()).hexdigest()[:16]}")
