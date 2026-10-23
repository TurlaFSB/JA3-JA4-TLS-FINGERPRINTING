#!/usr/bin/env python3
"""Measure tlsfp's single-core throughput on a capture it has not seen.

Repeating a capture byte for byte would measure nothing useful: after the first
copy every flow already exists. This script rewrites the ephemeral ports in each
copy (ports above 1024, in both directions, consistently per copy) so every copy
is a fresh set of flows, then times `tlsfp pcap` with and without the
intelligence and detection stage.

    python3 eval/throughput.py --pcap a.pcap [--pcap b.pcap ...] --copies 300

The input must be a little-endian pcap or pcapng with Ethernet framing and IPv4
TCP or UDP traffic (the lab datasets are). Results depend on the machine and are
therefore printed, never committed or checked in CI. All traffic comes from one
source address, which is the worst case for the correlation rules.
"""
import argparse, os, statistics, struct, subprocess, sys, tempfile, time


PCAP_HEADER = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1)


def read_pcapng(path, data):
    """Enhanced packet blocks of a little-endian pcapng with one Ethernet interface."""
    packets, offset = [], 0
    while offset < len(data):
        kind, length = struct.unpack("<II", data[offset:offset + 8])
        if kind == 1 and struct.unpack("<H", data[offset + 8:offset + 10])[0] != 1:
            sys.exit(f"{path}: only Ethernet interfaces are supported")
        if kind == 6:
            high, low, caplen, origlen = struct.unpack("<IIII", data[offset + 12:offset + 28])
            micros = (high << 32) | low  # assumes the default microsecond resolution
            record = struct.pack("<IIII", micros // 1_000_000, micros % 1_000_000, caplen, origlen)
            packets.append((record, bytearray(data[offset + 28:offset + 28 + caplen])))
        offset += length
    return packets


def read_packets(paths):
    header, packets = None, []
    for path in paths:
        with open(path, "rb") as f:
            data = f.read()
        if data[:4] == b"\x0a\x0d\x0d\x0a":
            header = header or PCAP_HEADER
            packets += read_pcapng(path, data)
            continue
        if data[:4] != b"\xd4\xc3\xb2\xa1":
            sys.exit(f"{path}: need a little-endian pcap or pcapng")
        header = header or data[:24]
        offset = 24
        while offset < len(data):
            caplen = struct.unpack("<I", data[offset + 8:offset + 12])[0]
            end = offset + 16 + caplen
            packets.append((data[offset:offset + 16], bytearray(data[offset + 16:end])))
            offset = end
    return header, packets


def write_copies(path, header, packets, copies):
    with open(path, "wb") as out:
        out.write(header)
        for k in range(copies):
            for record, data in packets:
                frame = bytearray(data)
                if frame[12:14] == b"\x08\x00" and frame[23] in (6, 17):
                    transport = 14 + (frame[14] & 0x0F) * 4
                    for at in (transport, transport + 2):
                        port = struct.unpack(">H", frame[at:at + 2])[0]
                        if port > 1024:
                            frame[at:at + 2] = struct.pack(">H", 1025 + (port - 1025 + k * 131) % 64000)
                out.write(record)
                out.write(frame)


def count(tlsfp, pcap):
    import json, re
    run = subprocess.run([tlsfp, "pcap", pcap], capture_output=True, text=True)
    text = re.sub(r"\x1b\[[0-9;]*m", "", run.stderr)
    return {k: int(v) for k, v in re.findall(r"(frames|tls_handshakes|events|quic_initials|quic_decrypted|udp_datagrams|tcp_segments)=(\d+)", text)}


def timed(args, repeats):
    runs = []
    for _ in range(repeats):
        start = time.perf_counter()
        subprocess.run(args, capture_output=True, check=True)
        runs.append(time.perf_counter() - start)
    return statistics.median(runs)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", action="append", required=True)
    ap.add_argument("--copies", type=int, default=300)
    ap.add_argument("--repeats", type=int, default=3)
    ap.add_argument("--tlsfp", default=os.environ.get("TLSFP", "target/release/tlsfp"))
    args = ap.parse_args()

    header, packets = read_packets(args.pcap)
    with tempfile.TemporaryDirectory() as tmp:
        pcap = os.path.join(tmp, "unique.pcap")
        write_copies(pcap, header, packets, args.copies)
        size = os.path.getsize(pcap)
        counts = count(args.tlsfp, pcap)
        print(f"{size / 1e6:.1f} MB, {counts.get('frames', 0):,} frames "
              f"({counts.get('tcp_segments', 0):,} TCP, {counts.get('udp_datagrams', 0):,} UDP), "
              f"{counts.get('tls_handshakes', 0):,} TLS handshakes, {counts.get('quic_decrypted', 0):,} QUIC Initials decrypted")

        t = timed([args.tlsfp, "pcap", pcap], args.repeats)
        print(f"fingerprinting only:        {t:6.2f} s  {size / t / 1e6:6.0f} MB/s  {counts['frames'] / t:10,.0f} frames/s  {counts['tls_handshakes'] / max(t, 1e-9):9,.0f} handshakes/s")

        db = os.path.join(tmp, "intel.db")
        subprocess.run([args.tlsfp, "intel", "seed", "--db", db], capture_output=True, check=True)
        t = timed([args.tlsfp, "pcap", "--intel", "--detect", "--db", db, pcap], 1)
        print(f"with --intel --detect:      {t:6.2f} s  {size / t / 1e6:6.0f} MB/s  {counts['frames'] / t:10,.0f} frames/s  {counts['tls_handshakes'] / max(t, 1e-9):9,.0f} handshakes/s")


if __name__ == "__main__":
    main()
