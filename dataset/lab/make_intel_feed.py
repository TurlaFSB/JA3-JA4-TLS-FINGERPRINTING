#!/usr/bin/env python3
"""Derive a labeled intelligence feed from a lab dataset.

Reads <dataset>/manifest.json, fingerprints each labeled capture with `tlsfp`,
and writes crates/tlsfp-intel/seeds/lab-clients.csv in the curated-feed format:

    fp_kind,value,label,category,reference

One row per distinct JA4 a client produced; JA3 rows only for clients whose JA3
is stable (JA3 of a client that randomizes extension order is meaningless as an
identifier). Impersonation frameworks are category `tool`; everything else the
lab ran is a known-good baseline (`benign`).

    python3 dataset/lab/make_intel_feed.py --dataset dataset/v0.2 \
        --out crates/tlsfp-intel/seeds/lab-clients.csv
"""
import argparse, csv, json, os, subprocess, sys
from collections import Counter

LABELS = {
    "curl": "curl (OpenSSL, HTTP/1.1)",
    "curl-tls13": "curl (OpenSSL, TLS 1.3 only)",
    "wget-tls12": "wget (OpenSSL, TLS 1.2 only)",
    "go-http2": "Go net/http (HTTP/2)",
    "java-urlconnection": "Java HttpsURLConnection",
    "openssl-s_client-alpn-h2": "OpenSSL s_client (ALPN h2)",
    "curl-http2": "curl (OpenSSL, HTTP/2)",
    "curl-tls12": "curl (OpenSSL, TLS 1.2 only)",
    "wget": "wget (OpenSSL)",
    "openssl-s_client": "OpenSSL s_client",
    "openssl-s_client-tls12": "OpenSSL s_client (TLS 1.2 only)",
    "python-requests": "Python requests (urllib3)",
    "python-urllib": "Python urllib",
    "python-httpx": "Python httpx",
    "python-aiohttp": "Python aiohttp",
    "go-net-http": "Go net/http",
    "node-https": "Node.js https",
    "java-httpclient": "Java HttpClient",
    "ruby-net-http": "Ruby Net::HTTP",
    "php-stream": "PHP streams",
    "php-curl": "PHP cURL",
    "chromium-headless": "Chromium (headless, Playwright build)",
}

STABLE_JA3_MAX_DISTINCT = 2


def label_for(key):
    if key.startswith("curl_cffi-"):
        return f"curl_cffi impersonating {key.removeprefix('curl_cffi-')}"
    return LABELS.get(key, key)


def category_for(key):
    return "tool" if key.startswith("curl_cffi-") else "benign"


def fingerprints(tlsfp, pcap):
    run = subprocess.run([tlsfp, "pcap", "--json", pcap], capture_output=True, text=True, check=True)
    ja4, ja3 = Counter(), Counter()
    for line in run.stdout.splitlines():
        ev = json.loads(line)
        if ev.get("kind") == "client_hello":
            ja4[ev["ja4"]["hash"]] += 1
            ja3[ev["ja3"]] += 1
    return ja4, ja3


def existing_benign(path):
    """(kind, value) -> label for known-good rows already in the curated feed."""
    good = {}
    with open(path) as f:
        lines = [line for line in f if not line.startswith("#")]
    for row in csv.DictReader(lines):
        if row["category"] in ("benign", "os"):
            good[(row["fp_kind"], row["value"])] = row["label"]
    return good


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--tlsfp", default=os.environ.get("TLSFP", "target/release/tlsfp"))
    ap.add_argument("--existing", default="crates/tlsfp-intel/seeds/curated-c2-intel.csv",
                    help="curated feed; lab rows that contradict it are left out")
    args = ap.parse_args()

    known_good = existing_benign(args.existing)

    with open(os.path.join(args.dataset, "manifest.json")) as f:
        manifest = json.load(f)
    version = manifest["dataset_version"]
    # (kind, value) -> clients that produced it. A fingerprint shared by several
    # clients (curl and PHP cURL share a library) gets one row naming all of them,
    # because the store keeps a single row per value.
    merged = {}
    for key, entry in sorted(manifest["labels"].items()):
        ja4, ja3 = fingerprints(args.tlsfp, os.path.join(args.dataset, entry["pcap"]))
        handshakes = sum(ja4.values())
        kinds = [("ja4", ja4)]
        if len(ja3) <= STABLE_JA3_MAX_DISTINCT:
            kinds.append(("ja3", ja3))
        for kind, counter in kinds:
            for value in sorted(counter):
                merged.setdefault((kind, value), []).append((key, entry, handshakes))

    # A tool profile that reproduces a known-good client's ClientHello is that
    # client as far as any hash of the ClientHello can tell, so none of its
    # fingerprints (JA4 or JA3) may be listed: flagging them would flag every real
    # user of that client.
    shadowed = {
        key
        for (kind, value), owners in merged.items()
        for key, _, _ in owners
        if category_for(key) == "tool" and (kind, value) in known_good
    }

    rows, excluded = [], []
    for (kind, value), owners in sorted(merged.items(), key=lambda item: (item[0][0] != "ja4", item[0][1])):
        kept = [(key, entry, n) for key, entry, n in owners if key not in shadowed]
        if len(kept) < len(owners):
            dropped = ", ".join(sorted(label_for(key) for key, _, _ in owners if key in shadowed))
            excluded.append((kind, value, dropped, f"'{known_good[(kind, value)]}'" if (kind, value) in known_good else "a known-good browser"))
        if not kept:
            continue
        labels = " / ".join(label_for(key) for key, _, _ in kept)
        category = "tool" if any(category_for(key) == "tool" for key, _, _ in kept) else "benign"
        ref = "; ".join(
            f"dataset {version} '{key}': {entry['client_version']} ({n} handshakes)"
            for key, entry, n in kept
        ) + "; Linux x86_64 loopback lab"
        rows.append((kind, value, labels, category, ref))

    with open(args.out, "w", newline="") as f:
        f.write(
            "# tlsfp lab-derived client fingerprints\n#\n"
            f"# Generated by dataset/lab/make_intel_feed.py from dataset {version}. Each row is a\n"
            "# fingerprint observed from a real client run in the project's lab, with the exact\n"
            "# client version in the reference column. Fingerprints are properties of a client\n"
            "# build and its TLS library, so treat labels as 'consistent with', not proof, and\n"
            "# expect drift across versions. curl_cffi rows are impersonation profiles (category\n"
            "# tool): a client that claims to be a browser but matches one is flagged by ua_mismatch.\n"
            "# Do not edit by hand; regenerate.\n"
            + "".join(
                f"# Excluded: {kind} {value} from '{labels}' reproduces the ClientHello of {good}; "
                "not distinguishable from it.\n"
                for kind, value, labels, good in excluded
            ))
        w = csv.writer(f, lineterminator="\n", quoting=csv.QUOTE_MINIMAL)
        w.writerow(["fp_kind", "value", "label", "category", "reference"])
        w.writerows(rows)
    print(f"wrote {len(rows)} rows from {len(manifest['labels'])} clients to {args.out}; "
          f"excluded {len(excluded)} that are identical to known-good fingerprints")


if __name__ == "__main__":
    main()
