#!/usr/bin/env python3
"""Does the HTTP layer separate real browsers from impersonation tools?

TLS fingerprints cannot (see fidelity.py): curl-impersonate reproduces a real
browser's ClientHello exactly. This script asks the same question one layer up,
using the JA4H fingerprint of the cleartext HTTP requests in a scenario dataset
(dataset/lab/run_scenarios.py), where real Chromium builds and impersonation
profiles each sent requests to the same plain-HTTP server under a non-secure
hostname.

For every scenario it collects the JA4H values and the ordered header names the
sensor saw, then reports which impersonation profiles share a JA4H with a real
build (inseparable at this layer) and which do not.

    python3 eval/crosslayer.py --dataset dataset/v0.5 --out eval/results/v0.5
    python3 eval/crosslayer.py --dataset dataset/v0.5 --out eval/results/v0.5 --check
"""
import argparse, hashlib, json, os, subprocess, sys
from collections import defaultdict


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def http_requests(tlsfp, pcap):
    out = subprocess.run([tlsfp, "pcap", "--json", pcap], capture_output=True, text=True, check=True).stdout
    return [json.loads(l) for l in out.splitlines() if '"http_request"' in l]


def header_names(raw):
    """Ordered header names out of a JA4H raw string (field b)."""
    parts = raw.split("_")
    return parts[1].split(",") if len(parts) > 1 and parts[1] else []


def evaluate(tlsfp, dataset):
    with open(os.path.join(dataset, "manifest.json")) as f:
        manifest = json.load(f)
    per = {}
    for label, entry in sorted(manifest["labels"].items()):
        path = os.path.join(dataset, entry["pcap"])
        if sha256(path) != entry["sha256"]:
            sys.exit(f"{path}: checksum differs from manifest")
        reqs = http_requests(tlsfp, path)
        if not reqs:
            continue
        ja4h = sorted({r["ja4h"]["hash"] for r in reqs})
        names = sorted({",".join(header_names(r["ja4h"]["raw"])) for r in reqs})
        per[label] = {"client": entry["client"], "client_class": entry["client_class"], "ua_claim": entry["ua_claim"],
                      "requests": len(reqs), "ja4h": ja4h, "header_orders": names}

    browsers = {k: v for k, v in per.items() if v["client_class"] == "browser"}
    profiles = {k: v for k, v in per.items() if v["client_class"] == "impersonation"}
    real_ja4h = {h for v in browsers.values() for h in v["ja4h"]}
    real_orders = {o for v in browsers.values() for o in v["header_orders"]}

    groups = defaultdict(lambda: {"browsers": [], "impersonation": [], "libraries": []})
    for label, v in per.items():
        bucket = {"browser": "browsers", "impersonation": "impersonation", "library": "libraries"}.get(v["client_class"])
        if bucket is None:
            continue  # the adaptive-attacker scenarios belong to eval/scenarios.py
        if v["client_class"] == "library" and v["ua_claim"] != "native":
            continue  # a spoofed User-Agent does not change the library's own header order
        for h in v["ja4h"]:
            groups[h][bucket].append(v["client"])
    for g in groups.values():
        for k in g:
            g[k] = sorted(set(g[k]))

    return {
        "dataset_version": manifest["dataset_version"],
        "scenarios_with_http": len(per),
        "real_browser_builds": len(browsers),
        "impersonation_profiles": len(profiles),
        "profiles_sharing_ja4h_with_a_real_build": sorted(v["client"] for v in profiles.values()
                                                          if set(v["ja4h"]) & real_ja4h),
        "profiles_separable_by_ja4h": sorted(v["client"] for v in profiles.values()
                                             if not set(v["ja4h"]) & real_ja4h),
        "profiles_sharing_header_order_with_a_real_build": sorted(v["client"] for v in profiles.values()
                                                                  if set(v["header_orders"]) & real_orders),
        "real_ja4h_values": len(real_ja4h),
        "per_scenario": {k: v for k, v in per.items()
                         if v["client_class"] in ("browser", "impersonation") or (v["client_class"] == "library" and v["ua_claim"] == "native")},
        "ja4h_groups": {k: v for k, v in sorted(groups.items())},
    }


def markdown(r):
    lines = [f"# HTTP-layer separation: dataset {r['dataset_version']}", "",
             "Cleartext HTTP requests from real Chromium builds and curl-impersonate profiles, served from one plain-HTTP "
             "server under a non-secure hostname. JA4H fingerprints the request: method, version, header order, cookies, "
             "language.", "",
             f"- real browser builds with HTTP traffic: {r['real_browser_builds']}; impersonation profiles: {r['impersonation_profiles']}",
             f"- profiles sharing a JA4H with a real build (inseparable here): {len(r['profiles_sharing_ja4h_with_a_real_build'])}",
             f"- profiles whose JA4H matches no real build: {len(r['profiles_separable_by_ja4h'])}"
             + (f" ({', '.join(r['profiles_separable_by_ja4h'])})" if r["profiles_separable_by_ja4h"] else ""), "",
             "## JA4H groups", "", "| JA4H | real browsers | impersonation profiles | libraries |", "|---|---|---|---|"]
    for h, g in r["ja4h_groups"].items():
        lines.append(f"| `{h}` | {', '.join(g['browsers']) or '-'} | {', '.join(g['impersonation']) or '-'} | {', '.join(g['libraries']) or '-'} |")
    lines += ["", "## Header order per client", "", "| client | class | requests | header order |", "|---|---|---|---|"]
    for label, v in sorted(r["per_scenario"].items()):
        for order in v["header_orders"]:
            lines.append(f"| {v['client']} | {v['client_class']} | {v['requests']} | {order} |")
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--tlsfp", default=os.environ.get("TLSFP", "target/release/tlsfp"))
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    result = evaluate(args.tlsfp, args.dataset)
    rendered = {"crosslayer.json": json.dumps(result, indent=2, sort_keys=True) + "\n", "crosslayer.md": markdown(result)}
    if args.check:
        for name, text in rendered.items():
            with open(os.path.join(args.out, name)) as f:
                if f.read() != text:
                    sys.exit(f"{name} differs from a fresh evaluation run")
        print("cross-layer evaluation reproduces committed results")
        return
    os.makedirs(args.out, exist_ok=True)
    for name, text in rendered.items():
        with open(os.path.join(args.out, name), "w") as f:
            f.write(text)
    print(rendered["crosslayer.md"])


if __name__ == "__main__":
    main()
