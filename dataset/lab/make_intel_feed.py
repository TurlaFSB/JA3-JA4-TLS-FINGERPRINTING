#!/usr/bin/env python3
"""Derive a labeled intelligence feed from a lab dataset.

Reads <dataset>/manifest.json, fingerprints each labeled capture with `tlsfp`,
and writes crates/tlsfp-intel/seeds/lab-clients.csv in the curated-feed format:

    fp_kind,value,label,category,reference

One row per distinct JA4 a client produced; JA3 rows only for clients whose JA3
is stable (JA3 of a client that randomizes extension order is meaningless as an
identifier). Real Chromium builds and ordinary libraries are known-good baselines
(`benign`). Impersonation profiles (curl_cffi) are NEVER listed: measured against
Chromium headless shells of the same era they reproduce the ClientHello exactly,
and differ from full Chrome only in configuration-dependent extensions such as
ECH (see eval/fidelity.py). A profile therefore equals a plausible real browser
configuration, and listing it as a tool would flag real users.

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


def label_for(key, _versions=None):
    return LABELS.get(key, key)


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
    ap.add_argument("--real-dataset", default=None,
                    help="dataset holding real browser builds (chromium-real-*); their fingerprints are listed as benign")
    ap.add_argument("--existing", default="crates/tlsfp-intel/seeds/curated-c2-intel.csv",
                    help="curated feed; lab rows that contradict it are left out")
    args = ap.parse_args()

    known_good = existing_benign(args.existing)  # kept for the reference column wording only
    with open(os.path.join(args.dataset, "manifest.json")) as f:
        manifest = json.load(f)
    version = manifest["dataset_version"]

    # (kind, value) -> clients that produced it. A fingerprint shared by several
    # clients (curl and PHP cURL share a library) gets one row naming all of them,
    # because the store keeps a single row per value.
    merged, omitted = {}, []
    real_ja4 = {}  # ja4 -> real build versions
    sources = [(args.dataset, manifest, version)]
    if args.real_dataset:
        with open(os.path.join(args.real_dataset, "manifest.json")) as f:
            sources.append((args.real_dataset, json.load(f), os.path.basename(os.path.normpath(args.real_dataset))))
    profile_ja4 = {}  # impersonation profile -> ja4 set (for the omission note)
    for dataset, man, ver in sources:
        for key, entry in sorted(man["labels"].items()):
            ja4, ja3 = fingerprints(args.tlsfp, os.path.join(dataset, entry["pcap"]))
            if key.startswith("curl_cffi-"):
                profile_ja4[key.removeprefix("curl_cffi-")] = sorted(ja4)
                continue
            handshakes = sum(ja4.values())
            real = key.startswith("chromium-real-")
            kinds = [("ja4", ja4)]
            if not real and len(ja3) <= STABLE_JA3_MAX_DISTINCT:
                kinds.append(("ja3", ja3))
            for kind, counter in kinds:
                for value in sorted(counter):
                    merged.setdefault((kind, value), []).append((key, entry, handshakes, ver))
                    if real and kind == "ja4":
                        real_ja4.setdefault(value, []).append(key.removeprefix("chromium-real-"))

    for name, values in sorted(profile_ja4.items()):
        twins = sorted({v for ja4 in values for v in real_ja4.get(ja4, [])})
        omitted.append((name, twins))

    rows = []
    for (kind, value), owners in sorted(merged.items(), key=lambda item: (item[0][0] != "ja4", item[0][1])):
        labels = " / ".join(dict.fromkeys(label_for(key, [v for k, _, _, _ in owners if k.startswith("chromium-real-")
                                                              for v in [k.removeprefix("chromium-real-")]])
                                         for key, _, _, _ in owners))
        real_versions = [k.removeprefix("chromium-real-") for k, _, _, _ in owners if k.startswith("chromium-real-")]
        if real_versions:
            labels = "Chromium " + ", ".join(real_versions) + " (headless shell)"
        ref = "; ".join(
            f"dataset {ver} '{key}': {entry['client_version']} ({n} handshakes)"
            for key, entry, n, ver in owners
        ) + "; Linux x86_64 loopback lab"
        if real_versions:
            ref += ("; the same JA4 is emitted by curl_cffi Chrome profiles of this era, so it identifies the "
                    "Chromium family, not a genuine browser")
        rows.append((kind, value, labels, "benign", ref))

    excluded = omitted

    with open(args.out, "w", newline="") as f:
        f.write(
            "# tlsfp lab-derived client fingerprints\n#\n"
            f"# Generated by dataset/lab/make_intel_feed.py from dataset {version}"
            + (f" and real browser builds from {os.path.basename(os.path.normpath(args.real_dataset))}" if args.real_dataset else "")
            + ".\n"
            "# Each row is a fingerprint observed from a real client run in the project's lab, with\n"
            "# the exact client version in the reference column. Fingerprints are properties of a\n"
            "# client build and its TLS library: treat labels as 'consistent with', not proof, and\n"
            "# expect drift across versions.\n"
            "#\n"
            "# Impersonation profiles (curl_cffi / curl-impersonate) are deliberately not listed.\n"
            "# They equal Chromium headless shells of their era and differ from full Chrome only by\n"
            "# configuration-dependent extensions, so a tool entry could be a real browser's\n"
            "# fingerprint and would flag its users.\n"
            "# Do not edit by hand; regenerate.\n"
            + "".join(
                f"# Not listed: curl_cffi {name} profile; "
                + (f"its JA4 equals real Chromium {', '.join(twins)}.\n" if twins
                   else "no real counterpart captured, so it cannot be shown to differ from the browser.\n")
                for name, twins in excluded
            ))
        w = csv.writer(f, lineterminator="\n", quoting=csv.QUOTE_MINIMAL)
        w.writerow(["fp_kind", "value", "label", "category", "reference"])
        w.writerows(rows)
    print(f"wrote {len(rows)} rows to {args.out}; left out {len(excluded)} impersonation profiles")


if __name__ == "__main__":
    main()
