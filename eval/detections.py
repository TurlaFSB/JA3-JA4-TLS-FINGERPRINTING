#!/usr/bin/env python3
"""Evaluate intelligence verdicts and detection rules on a labeled dataset.

For every labeled capture, `tlsfp pcap --intel --detect --json` is run against a
freshly seeded database, so each client is judged as if it had an address to
itself. A second pass feeds every capture into ONE database, which models many
clients behind a single address (a NAT gateway, a jump host, a developer
workstation) and shows how the correlation rules behave there.

Ground truth comes from the dataset manifest: a client named curl_cffi-* is an
impersonation tool (expected: flagged as a tool, never vouched for as a
browser); every other client is a known-good baseline (expected: never
suspicious or malicious). A client is "known" when the bundled lab feed was
built from it; evaluating on a dataset captured separately from the feed's
source is what makes the numbers a held-out measurement.

    python3 eval/detections.py --dataset dataset/v0.3 --feed-dataset dataset/v0.2 \
        --out eval/results/v0.3
    python3 eval/detections.py ... --check
"""
import argparse, hashlib, json, os, subprocess, sys, tempfile
from collections import Counter, defaultdict


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def is_tool(key):
    return key.startswith("curl_cffi-")


def run_capture(tlsfp, db, pcap):
    run = subprocess.run([tlsfp, "pcap", "--intel", "--detect", "--json", "--db", db, pcap],
                         capture_output=True, text=True, check=True)
    return [json.loads(line) for line in run.stdout.splitlines()]


def seed(tlsfp, db):
    subprocess.run([tlsfp, "intel", "seed", "--db", db], capture_output=True, check=True)


def client_hellos(events):
    for ev in events:
        if ev.get("kind") == "client_hello":
            yield ev


def summarise_client(events):
    verdicts, strengths, labels = Counter(), Counter(), Counter()
    for ev in client_hellos(events):
        reports = [r for r in (ev.get("intel") or []) if r["kind"] == "ja4"]
        if not reports:
            verdicts["none"] += 1
            continue
        report = reports[0]
        verdicts[report["verdict"]] += 1
        if report["hits"]:
            top = max(report["hits"], key=lambda h: {"exact": 2, "cipher_and_prefix": 1, "cipher_only": 0}[h["strength"]])
            strengths[top["strength"]] += 1
            if top["strength"] == "exact":
                labels[top["label"]] += 1
    alerts = Counter()
    for ev in events:
        for alert in ev.get("alerts") or []:
            alerts[alert["rule"]] += 1
    return {"handshakes": sum(verdicts.values()), "verdicts": dict(sorted(verdicts.items())),
            "best_match": dict(sorted(strengths.items())), "exact_labels": dict(sorted(labels.items())),
            "alerts": dict(sorted(alerts.items()))}


def ja4_set(events):
    return sorted({ev["ja4"]["hash"] for ev in client_hellos(events)})


def evaluate(tlsfp, dataset, feed_dataset):
    with open(os.path.join(dataset, "manifest.json")) as f:
        manifest = json.load(f)
    known = set()
    for source in feed_dataset or []:
        with open(os.path.join(source, "manifest.json")) as f:
            known |= set(json.load(f)["labels"])

    per_client, events_by_client = {}, {}
    with tempfile.TemporaryDirectory() as tmp:
        for key, entry in sorted(manifest["labels"].items()):
            path = os.path.join(dataset, entry["pcap"])
            if sha256(path) != entry["sha256"]:
                sys.exit(f"{path}: checksum differs from manifest")
            db = os.path.join(tmp, f"{key}.db")
            seed(tlsfp, db)
            events = run_capture(tlsfp, db, path)
            events_by_client[key] = events
            summary = summarise_client(events)
            summary["class"] = "tool" if is_tool(key) else "benign"
            summary["in_feed_source"] = key in known
            per_client[key] = summary

        # One address, every client: the correlation rules under NAT.
        shared = os.path.join(tmp, "shared.db")
        seed(tlsfp, shared)
        nat_alerts = Counter()
        for key, entry in sorted(manifest["labels"].items()):
            for ev in run_capture(tlsfp, shared, os.path.join(dataset, entry["pcap"])):
                for alert in ev.get("alerts") or []:
                    nat_alerts[(alert["rule"], alert["severity"])] += 1

    return manifest, per_client, events_by_client, nat_alerts


def pct(num, den):
    return None if den == 0 else round(100.0 * num / den, 1)


def aggregate(per_client):
    def total(keys, verdict):
        return sum(per_client[k]["verdicts"].get(verdict, 0) for k in keys)

    def handshakes(keys):
        return sum(per_client[k]["handshakes"] for k in keys)

    benign = [k for k, v in per_client.items() if v["class"] == "benign"]
    tools = [k for k, v in per_client.items() if v["class"] == "tool"]
    tools_known = [k for k in tools if per_client[k]["in_feed_source"]]
    tools_unseen = [k for k in tools if not per_client[k]["in_feed_source"]]
    benign_known = [k for k in benign if per_client[k]["in_feed_source"]]
    benign_unseen = [k for k in benign if not per_client[k]["in_feed_source"]]

    def block(keys):
        n = handshakes(keys)
        return {"clients": len(keys), "handshakes": n,
                **{v: pct(total(keys, v), n) for v in ("benign", "suspicious", "malicious", "unknown", "none")}}

    return {
        "benign_clients_seen_by_feed": block(benign_known),
        "benign_clients_unseen_by_feed": block(benign_unseen),
        "impersonation_profiles_seen_by_feed": block(tools_known),
        "impersonation_profiles_unseen_by_feed": block(tools_unseen),
        "benign_clients_with_any_suspicious_or_malicious_verdict": sorted(
            k for k in benign if total([k], "suspicious") + total([k], "malicious") > 0),
        "impersonation_profiles_vouched_benign": sorted(k for k in tools if total([k], "benign") > 0),
        "benign_clients_raising_non_info_alerts": sorted(
            k for k in benign if any(rule != "first_seen" for rule in per_client[k]["alerts"])),
    }


def stability(dataset, others, events_by_client, tlsfp):
    """JA4 sets of clients captured in both datasets: do they reproduce?"""
    if not others:
        return None
    other = others[0]
    with open(os.path.join(other, "manifest.json")) as f:
        other_manifest = json.load(f)
    same, differ = [], []
    with tempfile.TemporaryDirectory() as tmp:
        for key, entry in sorted(other_manifest["labels"].items()):
            if key not in events_by_client:
                continue
            db = os.path.join(tmp, "x.db")
            seed(tlsfp, db)
            theirs = ja4_set(run_capture(tlsfp, db, os.path.join(other, entry["pcap"])))
            (same if theirs == ja4_set(events_by_client[key]) else differ).append(key)
    return {"compared": len(same) + len(differ), "identical_ja4_sets": len(same), "different": differ}


def markdown(manifest, per_client, agg, nat, stab, feed_dataset):
    version = manifest["dataset_version"]
    lines = [f"# Detection evaluation: dataset {version}", "",
             f"Intelligence feed built from: {', '.join(feed_dataset) if feed_dataset else 'n/a'}.", "",
             "Each client is judged in isolation against a freshly seeded database.", ""]
    if stab:
        lines += ["## Reproducibility of fingerprints across lab runs", "",
                  f"{stab['identical_ja4_sets']} of {stab['compared']} clients present in both runs produced identical JA4 sets."
                  + (f" Differing: {', '.join(stab['different'])}." if stab["different"] else ""), ""]
    lines += ["## Verdicts on client handshakes (percent of handshakes)", "",
              "| group | clients | handshakes | benign | suspicious | malicious | unknown | no match |",
              "|---|---|---|---|---|---|---|---|"]
    names = [("benign_clients_seen_by_feed", "known-good clients, in the feed's source run"),
             ("benign_clients_unseen_by_feed", "known-good clients, not in the feed"),
             ("impersonation_profiles_seen_by_feed", "impersonation profiles, in the feed's source run"),
             ("impersonation_profiles_unseen_by_feed", "impersonation profiles, not in the feed")]
    for key, label in names:
        b = agg[key]
        lines.append(f"| {label} | {b['clients']} | {b['handshakes']} | {b['benign']} | {b['suspicious']} | "
                     f"{b['malicious']} | {b['unknown']} | {b['none']} |")
    lines += ["",
              f"- known-good clients with any suspicious or malicious verdict: {agg['benign_clients_with_any_suspicious_or_malicious_verdict'] or 'none'}",
              f"- impersonation profiles vouched for as benign: {agg['impersonation_profiles_vouched_benign'] or 'none'}",
              f"- known-good clients raising alerts other than first_seen (isolated): {agg['benign_clients_raising_non_info_alerts'] or 'none'}",
              "", "## Per client", "",
              "| client | class | in feed source | handshakes | verdicts | best match | exact label | alerts (isolated) |",
              "|---|---|---|---|---|---|---|---|"]
    for key, v in sorted(per_client.items()):
        lines.append(
            f"| {key} | {v['class']} | {'yes' if v['in_feed_source'] else 'no'} | {v['handshakes']} | "
            f"{v['verdicts']} | {v['best_match'] or '-'} | {'; '.join(v['exact_labels']) or '-'} | {v['alerts'] or '-'} |")
    lines += ["", "## All clients behind one address", "",
              "Every capture replayed into a single database, as a NAT gateway or shared workstation would present.", "",
              "| rule | severity | alerts |", "|---|---|---|"]
    for (rule, severity), n in sorted(nat.items()):
        lines.append(f"| {rule} | {severity} | {n} |")
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", required=True)
    ap.add_argument("--feed-dataset", nargs="+", help="dataset(s) the bundled lab feed was generated from; the first is also the reproducibility reference")
    ap.add_argument("--out", required=True)
    ap.add_argument("--tlsfp", default=os.environ.get("TLSFP", "target/release/tlsfp"))
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    manifest, per_client, events, nat = evaluate(args.tlsfp, args.dataset, args.feed_dataset)
    agg = aggregate(per_client)
    stab = stability(args.dataset, args.feed_dataset, events, args.tlsfp)
    nat_json = [{"rule": r, "severity": s, "alerts": n} for (r, s), n in sorted(nat.items())]
    result = {"dataset_version": manifest["dataset_version"], "feed_datasets": args.feed_dataset,
              "aggregate": agg, "stability": stab, "per_client": per_client, "single_address": nat_json}
    rendered = {"detections.json": json.dumps(result, indent=2, sort_keys=True) + "\n",
                "detections.md": markdown(manifest, per_client, agg, nat, stab, args.feed_dataset)}
    if args.check:
        for name, text in rendered.items():
            with open(os.path.join(args.out, name)) as f:
                if f.read() != text:
                    sys.exit(f"{name} differs from a fresh evaluation run")
        print("detection evaluation reproduces committed results")
        return
    os.makedirs(args.out, exist_ok=True)
    for name, text in rendered.items():
        with open(os.path.join(args.out, name), "w") as f:
            f.write(text)
    print(rendered["detections.md"])


if __name__ == "__main__":
    main()
