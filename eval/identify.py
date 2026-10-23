#!/usr/bin/env python3
"""How well does `tlsfp identify` name the client family from the ClientHello alone?

Every labelled capture is read with an EMPTY intelligence database, so no exact
match can help: what is measured is the heuristic in `crates/tlsfp-intel/src/infer.rs`
(ALPS means Chromium, record_size_limit with delegated_credentials means Firefox,
and so on). Ground truth is the client name in the dataset manifest.

Two numbers matter:
  * family accuracy on browsers and on impersonation profiles of browsers, and
  * the rate at which a plain library (curl, Python, Go, Java, Node, ...) is
    wrongly called a browser.

    python3 eval/identify.py --dataset dataset/v0.3 --dataset dataset/v0.6 --out eval/results/identify
    python3 eval/identify.py ... --check
"""
import argparse, hashlib, json, os, subprocess, sys, tempfile
from collections import Counter, defaultdict

BROWSER_FAMILIES = {"chromium", "firefox", "safari_like"}


def expected(label):
    """The family a client should be named as, or 'non_browser' for libraries."""
    n = label.lower()
    if n.startswith(("chrome-real-", "chromium", "curl_cffi-chrome", "curl_cffi-edge")):
        return "chromium"
    if n.startswith(("curl_cffi-firefox", "curl_cffi-tor")):
        return "firefox"
    if n.startswith("curl_cffi-safari"):
        return "safari_like"
    return "non_browser"


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def identify(tlsfp, db, path):
    out = subprocess.run([tlsfp, "identify", "--json", "--db", db, path], capture_output=True, text=True, check=True).stdout
    return json.loads(out.splitlines()[0])


def evaluate(tlsfp, datasets):
    rows = []
    with tempfile.TemporaryDirectory() as tmp:
        db = os.path.join(tmp, "empty.db")
        for dataset in datasets:
            with open(os.path.join(dataset, "manifest.json")) as f:
                manifest = json.load(f)
            for label, entry in sorted(manifest["labels"].items()):
                path = os.path.join(dataset, entry["pcap"])
                if sha256(path) != entry["sha256"]:
                    sys.exit(f"{path}: checksum differs from manifest")
                summary = identify(tlsfp, db, path)
                clients = summary["clients"]
                if not clients:
                    continue  # a build that produced no handshake is a data gap
                # Every distinct ClientHello shape in the capture, not only the busiest.
                families = sorted({c["guess"]["family"] for c in clients})
                head = summary["headline"]
                rows.append({
                    "dataset": os.path.basename(dataset.rstrip("/")), "client": label, "expected": expected(label),
                    "headline_family": next((c["guess"]["family"] for c in clients if c["ja4"] == head["ja4"]), "unknown"),
                    "families_seen": families,
                })
    return rows


def summarise(rows):
    browsers = [r for r in rows if r["expected"] in BROWSER_FAMILIES]
    libs = [r for r in rows if r["expected"] == "non_browser"]
    correct = [r for r in browsers if r["headline_family"] == r["expected"]]
    by_family = defaultdict(lambda: Counter())
    for r in browsers:
        by_family[r["expected"]][r["headline_family"]] += 1
    wrong_libs = [r for r in libs if r["headline_family"] in BROWSER_FAMILIES]
    return {
        "captures": len(rows),
        "browser_or_profile_captures": len(browsers),
        "named_with_the_right_family": len(correct),
        "family_confusion": {k: dict(sorted(v.items())) for k, v in sorted(by_family.items())},
        "library_captures": len(libs),
        "libraries_called_a_browser": [f"{r['dataset']}/{r['client']} -> {r['headline_family']}" for r in wrong_libs],
        "misnamed_browsers": [f"{r['dataset']}/{r['client']}: expected {r['expected']}, got {r['headline_family']}" for r in browsers if r["headline_family"] != r["expected"]],
    }


def markdown(s, datasets):
    lines = ["# Client family inference", "",
             f"Datasets: {', '.join(os.path.basename(d.rstrip('/')) for d in datasets)}. Read with an empty intelligence database, so only the "
             "ClientHello's shape is used. Ground truth is the client name in each manifest.", "",
             f"- captures with at least one handshake: {s['captures']}",
             f"- browsers and browser impersonation profiles: {s['browser_or_profile_captures']}; named with the right family: **{s['named_with_the_right_family']}**",
             f"- plain libraries and command line tools: {s['library_captures']}; wrongly called a browser: **{len(s['libraries_called_a_browser'])}**"
             + (f" ({'; '.join(s['libraries_called_a_browser'])})" if s["libraries_called_a_browser"] else ""), "",
             "## Expected family against the family named", "", "| expected | named as |", "|---|---|"]
    for expected_family, counts in s["family_confusion"].items():
        lines.append(f"| {expected_family} | {', '.join(f'{k}: {v}' for k, v in counts.items())} |")
    if s["misnamed_browsers"]:
        lines += ["", "## Misnamed", ""] + [f"- {m}" for m in s["misnamed_browsers"]]
    lines += ["", "**This is a regression check, not an out-of-sample accuracy.** The rules were written after reading the extension lists of these "
              "same captures, so perfect scores here are expected. The real test is a browser version the rules have not seen; the field "
              "captures in `docs/FIELD_OBSERVATIONS.md` (Brave and Edge, which send ALPS; Firefox 158, whose extension hash equals the "
              "profile's) agree with the rules but are three data points, not a measurement.", "",
              "A browser-family answer never proves a real browser: curl-impersonate and uTLS reproduce the markers the rules read, "
              "which is why the profiles above are named as browsers. See `docs/FIELD_OBSERVATIONS.md`.", ""]
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", action="append", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--tlsfp", default=os.environ.get("TLSFP", "target/release/tlsfp"))
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    rows = evaluate(args.tlsfp, args.dataset)
    s = summarise(rows)
    rendered = {"identify.json": json.dumps({"summary": s, "per_capture": rows}, indent=2, sort_keys=True) + "\n",
                "identify.md": markdown(s, args.dataset)}
    if args.check:
        for name, text in rendered.items():
            with open(os.path.join(args.out, name)) as f:
                if f.read() != text:
                    sys.exit(f"{name} differs from a fresh evaluation run")
        print("identify evaluation reproduces committed results")
        return
    os.makedirs(args.out, exist_ok=True)
    for name, text in rendered.items():
        with open(os.path.join(args.out, name), "w") as f:
            f.write(text)
    print(rendered["identify.md"])


if __name__ == "__main__":
    main()
