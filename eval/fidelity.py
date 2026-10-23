#!/usr/bin/env python3
"""How faithfully do impersonation profiles reproduce real browser ClientHellos?

Compares the JA4 values of real Chromium builds (`chromium-real-<version>`) with
curl_cffi (curl-impersonate) Chrome profiles in the same dataset. A JA4 identical
to a real browser's means no ClientHello hash can separate the tool from the
browser, so a fingerprint feed must never list that profile as a tool.

JA3 is not compared: real Chrome shuffles extension order, so its JA3 differs on
every connection by design.

    python3 eval/fidelity.py --dataset dataset/v0.4 --out eval/results/v0.4
    python3 eval/fidelity.py --dataset dataset/v0.4 --out eval/results/v0.4 --check
"""
import argparse, hashlib, json, os, re, subprocess, sys
from collections import defaultdict


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def ja4_set(tlsfp, pcap):
    out = subprocess.run([tlsfp, "pcap", "--json", pcap], capture_output=True, text=True, check=True).stdout
    return sorted({json.loads(l)["ja4"]["hash"] for l in out.splitlines() if '"client_hello"' in l})


def major(label):
    m = re.search(r"(\d+)", label.split("-", 2)[-1] if label.startswith("chromium-real") else label)
    return int(m.group(1)) if m else None


def evaluate(tlsfp, dataset):
    with open(os.path.join(dataset, "manifest.json")) as f:
        manifest = json.load(f)
    sets = {}
    for label, entry in sorted(manifest["labels"].items()):
        path = os.path.join(dataset, entry["pcap"])
        if sha256(path) != entry["sha256"]:
            sys.exit(f"{path}: checksum differs from manifest")
        sets[label] = ja4_set(tlsfp, path)
    real = {k: v for k, v in sets.items() if k.startswith("chromium-real-")}
    profiles = {k: v for k, v in sets.items() if k.startswith("curl_cffi-chrome") or k.startswith("curl_cffi-edge")}

    by_ja4 = defaultdict(lambda: {"real": [], "profiles": []})
    for label, values in real.items():
        for v in values:
            by_ja4[v]["real"].append(label.removeprefix("chromium-real-"))
    for label, values in profiles.items():
        for v in values:
            by_ja4[v]["profiles"].append(label.removeprefix("curl_cffi-"))

    nearest = {}
    for label, values in sorted(real.items()):
        rv = major(label)
        candidates = sorted((abs(major(p) - rv), p) for p in profiles if p.startswith("curl_cffi-chrome") and "android" not in p)
        close = candidates[0][1] if candidates else None
        nearest[label.removeprefix("chromium-real-")] = {
            "ja4": values,
            "nearest_profile": close.removeprefix("curl_cffi-") if close else None,
            "nearest_profile_ja4": profiles[close] if close else None,
            "identical_to_nearest_profile": bool(close) and set(values) & set(profiles[close]) != set(),
            "profiles_sharing_a_ja4": sorted({p.removeprefix("curl_cffi-") for v in values for p in
                                              [x for x, vs in profiles.items() if v in vs]}),
        }
    shared_with_real = sorted(p.removeprefix("curl_cffi-") for p, vs in profiles.items()
                              if any(v in {x for rv in real.values() for x in rv} for v in vs))
    return {
        "dataset_version": manifest["dataset_version"],
        "real_builds": len(real), "profiles": len(profiles),
        "real_builds_identical_to_nearest_profile": sum(1 for v in nearest.values() if v["identical_to_nearest_profile"]),
        "profiles_with_ja4_identical_to_a_real_build": shared_with_real,
        "profiles_with_no_real_counterpart": sorted(p.removeprefix("curl_cffi-") for p in profiles
                                                    if p.removeprefix("curl_cffi-") not in shared_with_real),
        "per_real_build": nearest,
        "ja4_groups": {k: v for k, v in sorted(by_ja4.items())},
    }


def markdown(r):
    lines = [f"# Impersonation fidelity: dataset {r['dataset_version']}", "",
             f"{r['real_builds']} real Chromium builds against {r['profiles']} curl-impersonate Chrome and Edge profiles. "
             "A profile whose JA4 equals a real build's cannot be separated from that browser by any ClientHello hash.", "",
             f"- real builds whose JA4 equals their nearest-version profile's: **{r['real_builds_identical_to_nearest_profile']} of {r['real_builds']}**",
             f"- profiles whose JA4 equals some real build's: {len(r['profiles_with_ja4_identical_to_a_real_build'])} of {r['profiles']}",
             f"- profiles with no real counterpart in this dataset: {', '.join(r['profiles_with_no_real_counterpart']) or 'none'}", "",
             "## JA4 groups", "", "| JA4 | real builds | profiles |", "|---|---|---|"]
    for ja4, g in r["ja4_groups"].items():
        lines.append(f"| `{ja4}` | {', '.join(g['real']) or '-'} | {', '.join(g['profiles']) or '-'} |")
    lines += ["", "## Real build against nearest profile", "",
              "| real build | JA4 | nearest profile | identical |", "|---|---|---|---|"]
    for build, v in r["per_real_build"].items():
        lines.append(f"| {build} | {', '.join('`' + x + '`' for x in v['ja4'])} | {v['nearest_profile']} | "
                     f"{'yes' if v['identical_to_nearest_profile'] else 'no'} |")
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--tlsfp", default=os.environ.get("TLSFP", "target/release/tlsfp"))
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    result = evaluate(args.tlsfp, args.dataset)
    rendered = {"fidelity.json": json.dumps(result, indent=2, sort_keys=True) + "\n", "fidelity.md": markdown(result)}
    if args.check:
        for name, text in rendered.items():
            with open(os.path.join(args.out, name)) as f:
                if f.read() != text:
                    sys.exit(f"{name} differs from a fresh evaluation run")
        print("fidelity evaluation reproduces committed results")
        return
    os.makedirs(args.out, exist_ok=True)
    for name, text in rendered.items():
        with open(os.path.join(args.out, name), "w") as f:
            f.write(text)
    print(rendered["fidelity.md"])


if __name__ == "__main__":
    main()
