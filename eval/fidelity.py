#!/usr/bin/env python3
"""How faithfully do impersonation profiles reproduce real browser ClientHellos?

Compares the JA4 values of real Chrome builds (`chrome-real-<major>` from Chrome
for Testing, `chromium-real-<version>` headless shells) with curl_cffi
(curl-impersonate) Chrome and Edge profiles in the same dataset, and for every
real build says exactly which extensions or cipher suites differ from the
nearest-version profile.

A JA4 identical to a real build's means no ClientHello hash can separate the
tool from the browser. A JA4 that differs means it can, until the profile is
updated. JA3 is not compared: real Chrome shuffles extension order, so its JA3
differs on every connection by design.

    python3 eval/fidelity.py --dataset dataset/v0.6 --out eval/results/v0.6
    python3 eval/fidelity.py --dataset dataset/v0.6 --out eval/results/v0.6 --check
"""
import argparse, hashlib, json, os, re, subprocess, sys
from collections import defaultdict

REAL_PREFIXES = ("chrome-real-", "chromium-real-")
PROFILE_PREFIXES = ("curl_cffi-chrome", "curl_cffi-edge")

EXTENSIONS = {
    "0000": "server_name", "0005": "status_request", "000a": "supported_groups", "000b": "ec_point_formats",
    "000d": "signature_algorithms", "0010": "alpn", "0012": "signed_certificate_timestamp", "0015": "padding",
    "0017": "extended_master_secret", "001b": "compress_certificate", "0023": "session_ticket",
    "0029": "pre_shared_key", "002b": "supported_versions", "002d": "psk_key_exchange_modes", "0033": "key_share",
    "4469": "alps (legacy codepoint 0x4469)", "44cd": "alps (new codepoint 0x44cd)", "fe0d": "encrypted_client_hello",
    "ff01": "renegotiation_info", "ca34": "trust_anchors", "0022": "delegated_credentials", "7550": "token_binding",
}
# Present only when a client resumes a session; ignored when comparing hello shapes.
RESUMPTION = {"0029"}


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def hellos(tlsfp, pcap):
    out = subprocess.run([tlsfp, "pcap", "--json", pcap], capture_output=True, text=True, check=True).stdout
    return [json.loads(l)["ja4"] for l in out.splitlines() if '"client_hello"' in l]


def parts(raw):
    a, b, c, d = raw.split("_")
    return a, set(b.split(",")), set(c.split(",")), d


def name(code):
    return EXTENSIONS.get(code, f"0x{code}")


def major(label):
    m = re.search(r"(\d+)", re.sub(r"^(chrome-real-|chromium-real-|curl_cffi-)", "", label))
    return int(m.group(1)) if m else None


def evaluate(tlsfp, dataset):
    with open(os.path.join(dataset, "manifest.json")) as f:
        manifest = json.load(f)
    seen = {}
    for label, entry in sorted(manifest["labels"].items()):
        path = os.path.join(dataset, entry["pcap"])
        if sha256(path) != entry["sha256"]:
            sys.exit(f"{path}: checksum differs from manifest")
        seen[label] = (entry["client_version"], hellos(tlsfp, path))

    real = {k: v for k, v in seen.items() if k.startswith(REAL_PREFIXES)}
    profiles = {k: v for k, v in seen.items() if k.startswith(PROFILE_PREFIXES) and "android" not in k}

    def hashes(entry):
        return sorted({h["hash"] for h in entry[1]})

    real_hashes = {x for v in real.values() for x in hashes(v)}
    groups = defaultdict(lambda: {"real": [], "profiles": []})
    for k, v in real.items():
        for h in hashes(v):
            groups[h]["real"].append(re.sub(r"^(chrome-real-|chromium-real-)", "", k))
    for k, v in profiles.items():
        for h in hashes(v):
            groups[h]["profiles"].append(k.removeprefix("curl_cffi-"))

    per_real = {}
    for label, entry in sorted(real.items(), key=lambda kv: major(kv[0])):
        rm = major(label)
        chromes = sorted((abs(major(p) - rm), -major(p), p) for p in profiles if p.startswith("curl_cffi-chrome"))
        nearest = chromes[0][2] if chromes else None
        diffs = None
        identical = False
        if nearest:
            prof_hashes = set(hashes(profiles[nearest]))
            identical = bool(set(hashes(entry)) & prof_hashes)
            real_ext = set().union(*[parts(h["raw"])[2] for h in entry[1]]) - RESUMPTION
            prof_ext = set().union(*[parts(h["raw"])[2] for h in profiles[nearest][1]]) - RESUMPTION
            real_ciph = set().union(*[parts(h["raw"])[1] for h in entry[1]])
            prof_ciph = set().union(*[parts(h["raw"])[1] for h in profiles[nearest][1]])
            real_sig = {parts(h["raw"])[3] for h in entry[1]}
            prof_sig = {parts(h["raw"])[3] for h in profiles[nearest][1]}
            diffs = {
                "extensions_only_in_real": sorted(name(x) for x in real_ext - prof_ext),
                "extensions_only_in_profile": sorted(name(x) for x in prof_ext - real_ext),
                "ciphers_equal": real_ciph == prof_ciph,
                "signature_algorithms_equal": real_sig == prof_sig,
            }
        per_real[label] = {
            "client_version": entry[0], "ja4": hashes(entry),
            "nearest_profile": nearest.removeprefix("curl_cffi-") if nearest else None,
            "nearest_profile_ja4": hashes(profiles[nearest]) if nearest else None,
            "identical_to_nearest_profile": identical, "differences_from_nearest_profile": diffs,
        }

    profile_summary = {k.removeprefix("curl_cffi-"): {"ja4": hashes(v), "equals_a_real_build": bool(set(hashes(v)) & real_hashes)}
                       for k, v in sorted(profiles.items())}
    full = [k for k in real if k.startswith("chrome-real-")]
    return {
        "dataset_version": manifest["dataset_version"],
        "real_builds": len(real), "real_full_chrome_builds": len(full), "profiles": len(profiles),
        "real_builds_identical_to_nearest_profile": sum(1 for v in per_real.values() if v["identical_to_nearest_profile"]),
        "profiles_with_ja4_identical_to_a_real_build": sorted(k for k, v in profile_summary.items() if v["equals_a_real_build"]),
        "profiles_matching_no_real_build": sorted(k for k, v in profile_summary.items() if not v["equals_a_real_build"]),
        "per_real_build": per_real, "per_profile": profile_summary,
        "ja4_groups": {k: v for k, v in sorted(groups.items())},
    }


def markdown(r):
    lines = [f"# Impersonation fidelity: dataset {r['dataset_version']}", "",
             f"{r['real_builds']} real browser builds ({r['real_full_chrome_builds']} full Chrome) against {r['profiles']} "
             "curl-impersonate Chrome and Edge profiles. A profile whose JA4 equals a real build's cannot be separated "
             "from it by any ClientHello hash; one that differs can, until the profile is updated.", "",
             f"- real builds whose JA4 equals their nearest-version profile's: **{r['real_builds_identical_to_nearest_profile']} of {r['real_builds']}**",
             f"- profiles whose JA4 equals some real build's: **{len(r['profiles_with_ja4_identical_to_a_real_build'])} of {r['profiles']}**"
             + (f" ({', '.join(r['profiles_with_ja4_identical_to_a_real_build'])})" if r["profiles_with_ja4_identical_to_a_real_build"] else ""),
             f"- profiles matching no real build: {len(r['profiles_matching_no_real_build'])}"
             + (f" ({', '.join(r['profiles_matching_no_real_build'])})" if r["profiles_matching_no_real_build"] else ""), "",
             "## Each real build against the nearest-version profile", "",
             "| real build | nearest profile | identical | only in the real browser | only in the profile |", "|---|---|---|---|---|"]
    for label, v in r["per_real_build"].items():
        d = v["differences_from_nearest_profile"] or {}
        lines.append(f"| {label} ({v['client_version'].split()[-1]}) | {v['nearest_profile']} | {'yes' if v['identical_to_nearest_profile'] else 'no'} | "
                     f"{', '.join(d.get('extensions_only_in_real', [])) or '-'} | {', '.join(d.get('extensions_only_in_profile', [])) or '-'} |")
    lines += ["", "## JA4 groups", "", "| JA4 | real builds | profiles |", "|---|---|---|"]
    for ja4, g in r["ja4_groups"].items():
        lines.append(f"| `{ja4}` | {', '.join(g['real']) or '-'} | {', '.join(g['profiles']) or '-'} |")
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
        for fname, text in rendered.items():
            with open(os.path.join(args.out, fname)) as f:
                if f.read() != text:
                    sys.exit(f"{fname} differs from a fresh evaluation run")
        print("fidelity evaluation reproduces committed results")
        return
    os.makedirs(args.out, exist_ok=True)
    for fname, text in rendered.items():
        with open(os.path.join(args.out, fname), "w") as f:
            f.write(text)
    print(rendered["fidelity.md"])


if __name__ == "__main__":
    main()
