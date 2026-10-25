# Synthetic captures

These files are **not** recordings of any network. `scripts/make-demo-capture.py`
builds them from scratch with a fixed random seed, so they are reproducible and
contain nobody's traffic. They exist to demonstrate and test protocols for which
the vendored real captures in `../pcap/` have no sample.

| File | Contents | SHA-256 |
|---|---|---|
| `synthetic-dns-ssh.pcap` | 136 plain DNS messages from three made-up clients (successful lookups, NXDOMAIN, two random-looking names) and one SSH connection (OpenSSH-style client and server) on `203.0.113.0/24` and `10.20.0.0/24` | `e508994bab9a7d18ad6e48c284cba6353899a4edc0314df23ef3491c1c3f79d5` |

Regenerate and check:

```
python3 scripts/make-demo-capture.py
sha256sum testdata/synthetic/synthetic-dns-ssh.pcap
```

Anything measured on these files (counts, hashes) is a property of the
generator, not evidence about real networks.
