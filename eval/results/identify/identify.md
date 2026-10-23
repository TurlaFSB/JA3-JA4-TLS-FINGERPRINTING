# Client family inference

Datasets: v0.3, v0.6. Read with an empty intelligence database, so only the ClientHello's shape is used. Ground truth is the client name in each manifest.

- captures with at least one handshake: 95
- browsers and browser impersonation profiles: 74; named with the right family: **74**
- plain libraries and command line tools: 21; wrongly called a browser: **0**

## Expected family against the family named

| expected | named as |
|---|---|
| chromium | chromium: 64 |
| firefox | firefox: 5 |
| safari_like | safari_like: 5 |

**This is a regression check, not an out-of-sample accuracy.** The rules were written after reading the extension lists of these same captures, so perfect scores here are expected. The real test is a browser version the rules have not seen; the field captures in `docs/FIELD_OBSERVATIONS.md` (Brave and Edge, which send ALPS; Firefox 158, whose extension hash equals the profile's) agree with the rules but are three data points, not a measurement.

A browser-family answer never proves a real browser: curl-impersonate and uTLS reproduce the markers the rules read, which is why the profiles above are named as browsers. See `docs/FIELD_OBSERVATIONS.md`.
