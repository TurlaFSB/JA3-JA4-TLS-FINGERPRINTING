# Changes from upstream

Base: upstream commit `bf9ac5d6eecd7743bf488602a5de4c27cf72a4d8` of https://github.com/CarterPerez-dev/Cybersecurity-Projects (`PROJECTS/intermediate/ja3-ja4-tls-fingerprinting`), AGPL-3.0. See `NOTICE.md`.

## Import
- CI: removed monorepo path filter and working directory.
- Removed upstream demo links and the upstream `curl | bash` installer instructions from the README.
- `learn/00-OVERVIEW.md`: removed monorepo `cd`.

## Audit week 1 (see `AUDIT.md`)
- README rewritten for this project; credit moved to a Credits section and `NOTICE.md`.
- `Cargo.lock`: `anyhow` 1.0.102 to 1.0.104, `spin` 0.9.8 to 0.9.9 (advisory and yanked release).
- CI: added `cargo audit` job.
- Tests: added `crates/tlsfp-core/tests/robustness.rs` (arbitrary and mutated input for QUIC, HTTP, SSLv2, certificate list, and pipeline).

## Project documents and installer
- Added `SECURITY.md`, `docs/THREAT_MODEL.md`, `CONTRIBUTING.md`, `CITATION.cff`.
- Rewrote `install.sh` to build from the local checkout (the upstream script cloned the upstream repository).
- `.gitignore`: stopped ignoring `docs/`.

## Dataset and evaluation
- Added `dataset/lab/run_lab.py` and dataset `v0.1` (9 clients, ground-truth labels, checksums).
- Added `eval/evaluate.py`, committed results, and a CI job verifying they reproduce.

## Fixes
- `tlsfp pcap` no longer prints an error and stack trace when its output is piped to a program that exits early (`| head`); regression test added.

- CI: fixed `rustup --component` usage that failed every build, test and lint job on current runners.

## Planned
Dataset lab, evaluation harness, impersonation classifier, drift detection, robustness study.
