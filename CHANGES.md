# Changes from upstream

Upstream: https://github.com/CarterPerez-dev/Cybersecurity-Projects (`PROJECTS/intermediate/ja3-ja4-tls-fingerprinting`), AGPL-3.0. Imported without upstream commit history.

## Import
- CI: removed monorepo path filter and working directory.
- Removed upstream demo links and the upstream `curl | bash` installer instructions from the README.
- `learn/00-OVERVIEW.md`: removed monorepo `cd`.

## Audit week 1 (see `AUDIT.md`)
- README rewritten for this project; credit moved to a Credits section and `NOTICE.md`.
- `Cargo.lock`: `anyhow` 1.0.102 to 1.0.104, `spin` 0.9.8 to 0.9.9 (advisory and yanked release).
- CI: added `cargo audit` job.
- Tests: added `crates/tlsfp-core/tests/robustness.rs` (arbitrary and mutated input for QUIC, HTTP, SSLv2, certificate list, and pipeline).

## Planned
Dataset lab, evaluation harness, impersonation classifier, drift detection, robustness study.
