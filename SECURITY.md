# Security policy

## Supported versions

Only the latest commit on `main` and the most recent tagged release receive security fixes.

## Reporting a vulnerability

Please do not open a public issue for a security problem.

Report it privately through GitHub: **Security → Report a vulnerability** on
https://github.com/TurlaFSB/JA3-JA4-TLS-FINGERPRINTING (GitHub private vulnerability reporting).

Include the affected version or commit, a description of the impact, and steps or a capture file that reproduces it. For a parser crash, a minimal pcap is the most useful report.

What to expect:
- acknowledgement within 7 days;
- an initial assessment within 14 days;
- a fix or mitigation, and credit to the reporter if they want it, before any public disclosure. The default coordinated-disclosure window is 90 days.

## Scope

In scope: memory-safety or panic bugs in packet and handshake parsing, unbounded resource use triggered by crafted traffic, flaws in the HTTP API or dashboard, SQL handling in the intelligence store, and unsafe defaults in the shipped container files.

Out of scope: weaknesses of the fingerprinting technique itself (a client that spoofs a fingerprint is documented in `docs/THREAT_MODEL.md`), and the web API being unauthenticated when deliberately exposed beyond localhost.

## Upstream issues

This project derives from an upstream sensor (see `NOTICE.md`). A bug that also exists upstream will be reported there as well, after the reporter agrees.
