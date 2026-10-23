# Contributing

Thanks for your interest. This is a research project; correctness and reproducibility matter more than feature count.

## Getting started

```bash
sudo apt-get install -y libpcap-dev     # or your platform's equivalent
cargo build --workspace --all-targets
cargo test --workspace
```

## Before opening a pull request

All of these must pass; CI runs them:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo audit
```

## Guidelines

- Parsing code must treat input as hostile: no panics, no unbounded allocation, no `unsafe` in `tlsfp-core`. Add a property test or a vendored capture for any new parser path.
- A new or changed fingerprint needs a known-answer test against a published vector, and an entry in `learn/CONFORMANCE.md`.
- New captures in `testdata/` need provenance (source, licence, what they contain) in `testdata/pcap/PROVENANCE.md`. Never commit captures containing real user traffic.
- Detection changes must report their effect on the evaluation in `eval/` (precision, recall, false-positive rate), not only on a single example.
- Keep commits focused, with messages that say what and why.

## Licensing

Contributions are accepted under AGPL-3.0, the project licence. Fingerprint algorithms keep the third-party terms in `NOTICE.md`. By submitting a contribution you confirm you have the right to license it.

## Reporting security issues

See `SECURITY.md`. Do not file them as public issues.
