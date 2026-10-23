#!/usr/bin/env python3
"""Evaluate the cross-layer rules (`ua_mismatch`, `os_mismatch`) on scenario captures.

Each scenario capture (dataset built by dataset/lab/run_scenarios.py) holds one
client's HTTPS handshakes and cleartext HTTP requests from one address. The
sensor is run on it with a freshly seeded database and the alerts are compared
with ground truth derived from the manifest and the captured traffic itself:

  ua lie  = the client is not a browser (a library or an impersonation tool) and
            its observed User-Agent claims a browser
  os lie  = the observed User-Agent claims Windows while the host is Linux

Counts are per scenario: a scenario is "alerted" when the rule fired at least
once in its capture. Output is deterministic.

    python3 eval/scenarios.py --dataset dataset/v0.4 --out eval/results/v0.4
    python3 eval/scenarios.py --dataset dataset/v0.4 --out eval/results/v0.4 --check
"""
import argparse, hashlib, json, os, re, subprocess, sys, tempfile
from collections import Counter, defaultdict

BROWSER_TOKENS = re.compile(r"(chrome|chromium|firefox|safari|edg/|edga/|fxios|crios|opr/)", re.I)


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def run(tlsfp, db, pcap):
    subprocess.run([tlsfp, "intel", "seed", "--db", db], capture_output=True, check=True)
    out = subprocess.run([tlsfp, "pcap", "--intel", "--detect", "--json", "--db", db, pcap],
                         capture_output=True, text=True, check=True).stdout
    return [json.loads(line) for line in out.splitlines()]


def claims_browser(ua):
    return bool(ua) and ua.startswith("Mozilla/") and bool(BROWSER_TOKENS.search(ua))


def claims_windows(ua):
    return bool(ua) and "Windows NT" in ua


def evaluate(tlsfp, dataset):
    with open(os.path.join(dataset, "manifest.json")) as f:
        manifest = json.load(f)
    rows = {}
    with tempfile.TemporaryDirectory() as tmp:
        for label, entry in sorted(manifest["labels"].items()):
            path = os.path.join(dataset, entry["pcap"])
            if sha256(path) != entry["sha256"]:
                sys.exit(f"{path}: checksum differs from manifest")
            events = run(tlsfp, os.path.join(tmp, f"{label}.db"), path)
            uas = sorted({e.get("user_agent", "") for e in events if e["kind"] == "http_request" and e.get("user_agent")})
            rules = Counter()
            for e in events:
                for a in e.get("alerts") or []:
                    rules[a["rule"]] += 1
            ua_lie = entry["client_class"] != "browser" and any(claims_browser(u) for u in uas)
            os_lie = any(claims_windows(u) for u in uas)
            rows[label] = {
                "client": entry["client"], "client_class": entry["client_class"], "ua_claim": entry["ua_claim"],
                "user_agents": uas, "truth": {"ua_lie": ua_lie, "os_lie": os_lie},
                "alerted": {"ua_mismatch": rules["ua_mismatch"] > 0, "os_mismatch": rules["os_mismatch"] > 0},
                "alerts": dict(sorted(rules.items())),
            }
    return manifest, rows


def confusion(rows, rule, truth_key, subset=None):
    tp = fp = fn = tn = 0
    for r in rows.values():
        if subset and not subset(r):
            continue
        truth, fired = r["truth"][truth_key], r["alerted"][rule]
        tp += truth and fired
        fn += truth and not fired
        fp += (not truth) and fired
        tn += (not truth) and not fired
    return {"tp": tp, "fn": fn, "fp": fp, "tn": tn,
            "recall": None if tp + fn == 0 else round(tp / (tp + fn), 3),
            "false_positive_rate": None if fp + tn == 0 else round(fp / (fp + tn), 3)}


def summarise(rows):
    groups = {
        "all scenarios": None,
        "library, honest User-Agent": lambda r: r["client_class"] == "library" and r["ua_claim"] == "native",
        "library, lying User-Agent": lambda r: r["client_class"] == "library" and r["ua_claim"] != "native",
        "impersonation profile": lambda r: r["client_class"] == "impersonation",
        "real browser": lambda r: r["client_class"] == "browser",
    }
    return {name: {"ua_mismatch": confusion(rows, "ua_mismatch", "ua_lie", sub),
                   "os_mismatch": confusion(rows, "os_mismatch", "os_lie", sub),
                   "scenarios": sum(1 for r in rows.values() if sub is None or sub(r))}
            for name, sub in groups.items()}


def markdown(manifest, rows, summary):
    lines = [f"# Cross-layer rule evaluation: dataset {manifest['dataset_version']}", "",
             "Each scenario is one client sending HTTPS (its TLS fingerprint) and cleartext HTTP (its claimed "
             "User-Agent) from one address. `ua lie` = a non-browser claiming a browser; `os lie` = a Windows "
             "claim from a Linux host.", "",
             "| group | scenarios | ua_mismatch: caught / lies | false alarms / honest | os_mismatch: caught / lies | false alarms / honest |",
             "|---|---|---|---|---|---|"]
    for name, s in summary.items():
        u, o = s["ua_mismatch"], s["os_mismatch"]
        lines.append(f"| {name} | {s['scenarios']} | {u['tp']} / {u['tp'] + u['fn']} | {u['fp']} / {u['fp'] + u['tn']} | "
                     f"{o['tp']} / {o['tp'] + o['fn']} | {o['fp']} / {o['fp'] + o['tn']} |")
    lines += ["", "## Per scenario", "",
              "| scenario | class | ua lie | ua_mismatch | os lie | os_mismatch | user agent |", "|---|---|---|---|---|---|---|"]
    for label, r in sorted(rows.items()):
        ua = (r["user_agents"][0][:48] + "...") if r["user_agents"] else "-"
        lines.append(f"| {label} | {r['client_class']} | {'yes' if r['truth']['ua_lie'] else 'no'} | "
                     f"{'ALERT' if r['alerted']['ua_mismatch'] else '-'} | {'yes' if r['truth']['os_lie'] else 'no'} | "
                     f"{'ALERT' if r['alerted']['os_mismatch'] else '-'} | {ua} |")
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--tlsfp", default=os.environ.get("TLSFP", "target/release/tlsfp"))
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    manifest, rows = evaluate(args.tlsfp, args.dataset)
    summary = summarise(rows)
    result = {"dataset_version": manifest["dataset_version"], "summary": summary, "per_scenario": rows}
    rendered = {"scenarios.json": json.dumps(result, indent=2, sort_keys=True) + "\n",
                "scenarios.md": markdown(manifest, rows, summary)}
    if args.check:
        for name, text in rendered.items():
            with open(os.path.join(args.out, name)) as f:
                if f.read() != text:
                    sys.exit(f"{name} differs from a fresh evaluation run")
        print("scenario evaluation reproduces committed results")
        return
    os.makedirs(args.out, exist_ok=True)
    for name, text in rendered.items():
        with open(os.path.join(args.out, name), "w") as f:
            f.write(text)
    print(rendered["scenarios.md"])


if __name__ == "__main__":
    main()
