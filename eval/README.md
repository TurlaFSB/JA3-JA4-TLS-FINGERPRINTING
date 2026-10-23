# Evaluation

`evaluate.py` measures how well JA3 and JA4 identify clients in a labeled dataset (`dataset/`). It is deterministic and checked in CI against the committed results, so any change to the parser, the fingerprint code, or the dataset that alters the numbers is visible in review.

```bash
cargo build --release
python3 eval/evaluate.py --dataset dataset/v0.1 --out eval/results/v0.1           # regenerate
python3 eval/evaluate.py --dataset dataset/v0.1 --out eval/results/v0.1 --check   # verify
```

## Metrics

- **Stability** for a client: the share of its handshakes carrying its most frequent fingerprint, and how many distinct fingerprints it produced.
- **Discriminability**: the number of clients whose most frequent fingerprint is not shared with any other client.

These are properties of the fingerprint functions on this dataset. They are not detection accuracy; precision, recall and false-positive rate of the detection rules are a separate, planned experiment.

## Results on dataset v0.1

Full tables: [`results/v0.1/results.md`](results/v0.1/results.md).

| | JA3 | JA4 |
|---|---|---|
| Clients with a unique dominant fingerprint | 7 / 9 | 9 / 9 |
| Mean distinct fingerprints per client | 1.78 | 1.11 |
| Chromium: distinct fingerprints in 8 handshakes | 8 | 2 |

Observations:

1. **JA3 is unstable for Chromium.** Every one of 8 Chromium handshakes produced a different JA3, because Chromium shuffles extension order. JA4 sorts extensions before hashing and collapses them to two values.
2. **The two JA4 values are explained by session resumption.** The 17-extension variant carries `pre_shared_key` (`0x0029`), sent when Chromium resumes a session; the 16-extension variant is a full handshake. One browser therefore has two JA4 values, which a rule or database must allow for.
3. **JA3 cannot tell curl's HTTP/1.1 and HTTP/2 modes apart.** They share a JA3 but differ in JA4, because JA4 includes the ALPN value.
4. All other clients were perfectly stable (one fingerprint across 20 handshakes) under both functions.

Caveats are in `dataset/README.md`; with 9 clients on one host, treat these as a demonstration of method and of known JA3/JA4 behaviour, not as a population estimate.
