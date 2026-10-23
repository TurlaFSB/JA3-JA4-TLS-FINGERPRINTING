#!/usr/bin/env python3
"""Reproducible fingerprint evaluation over a labeled handshake dataset.

Reads <dataset>/manifest.json, runs `tlsfp pcap --json` on each labeled capture,
and measures two properties per fingerprint type (JA3 and JA4):

  stability        how consistently one client maps to one fingerprint:
                   share of its ClientHellos carrying its most common value,
                   and the number of distinct values it produced.
  discriminability how well fingerprints separate different clients:
                   the share of clients whose dominant fingerprint is not shared
                   with any other client, and which clients collide.

Output is deterministic (no timestamps), so it can be diffed and verified in CI:

    python3 eval/evaluate.py --dataset dataset/v0.1 --out eval/results/v0.1
    python3 eval/evaluate.py --dataset dataset/v0.1 --out eval/results/v0.1 --check
"""
import argparse, hashlib, json, os, subprocess, sys
from collections import Counter, defaultdict


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def hellos(tlsfp, pcap):
    run = subprocess.run([tlsfp, "pcap", "--json", pcap], capture_output=True, text=True, check=True)
    out = []
    for line in run.stdout.splitlines():
        ev = json.loads(line)
        if ev.get("kind") == "client_hello":
            out.append({"ja3": ev["ja3"], "ja4": ev["ja4"]["hash"]})
    return out


def analyse(per_label, kind):
    stats, dominant = {}, {}
    for label, events in per_label.items():
        counts = Counter(e[kind] for e in events)
        value, top = counts.most_common(1)[0]
        stats[label] = {"handshakes": len(events), "distinct": len(counts),
                        "dominant": value, "dominant_share": round(top / len(events), 4)}
        dominant[label] = value
    owners = defaultdict(list)
    for label, value in dominant.items():
        owners[value].append(label)
    for label in stats:
        stats[label]["shared_with"] = sorted(set(owners[dominant[label]]) - {label})
    unique = sum(1 for label in stats if not stats[label]["shared_with"])
    return {"per_client": stats,
            "clients": len(stats),
            "clients_with_unique_dominant_fingerprint": unique,
            "mean_distinct_per_client": round(sum(s["distinct"] for s in stats.values()) / len(stats), 3),
            "mean_dominant_share": round(sum(s["dominant_share"] for s in stats.values()) / len(stats), 4)}


def markdown(manifest, results):
    lines = [f"# Fingerprint evaluation: dataset {manifest['dataset_version']}", "",
             f"Environment: {manifest['environment']['os']}, TLS server {manifest['environment']['server_tls']}, "
             f"transport {manifest['environment']['transport']}.", ""]
    for kind in ("ja3", "ja4"):
        r = results[kind]
        lines += [f"## {kind.upper()}", "",
                  f"- clients: {r['clients']}",
                  f"- clients whose dominant fingerprint is unique: {r['clients_with_unique_dominant_fingerprint']}/{r['clients']}",
                  f"- mean distinct fingerprints per client: {r['mean_distinct_per_client']}",
                  f"- mean share of the dominant fingerprint: {r['mean_dominant_share']}", "",
                  "| client | handshakes | distinct | dominant share | shares fingerprint with |", "|---|---|---|---|---|"]
        for label, s in sorted(r["per_client"].items()):
            lines.append(f"| {label} | {s['handshakes']} | {s['distinct']} | {s['dominant_share']} | {', '.join(s['shared_with']) or '-'} |")
        lines.append("")
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--tlsfp", default=os.environ.get("TLSFP", "target/release/tlsfp"))
    ap.add_argument("--check", action="store_true", help="fail if committed results differ from a fresh run")
    args = ap.parse_args()

    with open(os.path.join(args.dataset, "manifest.json")) as f:
        manifest = json.load(f)
    per_label = {}
    for label, entry in sorted(manifest["labels"].items()):
        path = os.path.join(args.dataset, entry["pcap"])
        if sha256(path) != entry["sha256"]:
            sys.exit(f"{path}: checksum differs from manifest; dataset was modified")
        events = hellos(args.tlsfp, path)
        if not events:
            sys.exit(f"{path}: no ClientHello found")
        per_label[label] = events

    results = {"dataset_version": manifest["dataset_version"],
               "ja3": analyse(per_label, "ja3"), "ja4": analyse(per_label, "ja4")}
    rendered = {"results.json": json.dumps(results, indent=2, sort_keys=True) + "\n",
                "results.md": markdown(manifest, results)}
    if args.check:
        for name, text in rendered.items():
            with open(os.path.join(args.out, name)) as f:
                if f.read() != text:
                    sys.exit(f"{name} differs from a fresh evaluation run")
        print("evaluation reproduces committed results")
        return
    os.makedirs(args.out, exist_ok=True)
    for name, text in rendered.items():
        with open(os.path.join(args.out, name), "w") as f:
            f.write(text)
    print(rendered["results.md"])


if __name__ == "__main__":
    main()
