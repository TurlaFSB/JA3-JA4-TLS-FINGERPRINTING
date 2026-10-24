# Extending the intelligence feed

The bundled feed (309 fingerprints, see the README) is a baseline: a snapshot of the abuse.ch SSLBL JA3 list (frozen by its publisher in 2021), Salesforce's benign JA3 list, 21 curated rows, and fingerprints of real client builds the project captured itself. It is not coverage of current malware, and no claim is made that it is. This page is how to make it better for your own use.

## Add the ja4db.com database

ja4db.com is a community database of JA4+ fingerprints with application labels. It is not bundled, because its terms are not stated clearly enough to redistribute and some of its records are malformed. Download it yourself and import it:

```
curl -o ja4db.json https://ja4db.com/api/read/
tlsfp intel import ja4db.json
```

Every record is validated for its fingerprint type; rejected rows are counted and reported, not hidden. ja4db describes applications, so its records import as benign unless a record classifies itself as malicious. Check the site's terms before you redistribute a database that contains it. Do not commit `ja4db.json` or an intelligence database built from it to this repository.

## Name a fingerprint yourself

The **Intel** page lists the client fingerprints this sensor has seen that the feed cannot name, with the shape-based guess and the evidence. If you know what one is (a browser build released last week, your own software), name it:

```
tlsfp intel label ja4 t13d1516h2_8daaf6152771_aaaaaaaaaaaa --label "Brave 1.62 on Windows"
tlsfp intel labels            # what you have added
tlsfp intel unlabel ja4 t13d1516h2_8daaf6152771_aaaaaaaaaaaa
```

Labels live in their own feed (`local labels`, licence `operator`), are matched exactly like any other, and never overwrite a bundled or imported entry. The default category is `benign`; use `tool`, `os`, `c2` or `malware` where they apply (`c2` and `malware` raise `known_bad`). A label is your claim, not evidence: another client with the same fingerprint gets the same name.

## Add your own fingerprints in bulk

The lab feed is generated from labelled captures by `dataset/lab/make_intel_feed.py` (see `dataset/README.md`), which is the way to turn a client you control into a labelled, reproducible entry. For a one-off, add a row to a copy of `crates/tlsfp-intel/seeds/curated-c2-intel.csv` (`fp_kind,value,label,category,reference`), rebuild, and run `tlsfp intel seed`. Give every row a reference that says where it came from.

## What the verdicts mean

- A *benign* verdict needs an **exact** match. A fingerprint shared with a tool is still listed as benign if a real client has it, which is why fingerprints that an impersonation profile reproduces exactly (current Brave and Edge, see `docs/FIELD_OBSERVATIONS.md`) are deliberately **not** in the feed: the sensor reports them as unknown.
- A partial match (same cipher list) is a similarity hint, never a verdict.
- Field-observed rows (Firefox 158 on Windows 10) record one machine on one day. A different build or operating system can produce a different fingerprint.

## Licensing of what is bundled

Each source and its licence are in `crates/tlsfp-intel/seeds/PROVENANCE.md` and the README. Two public lists that carry client fingerprints (Trisul's JA3 list and the tls-fingerprinting project's JSON) were looked at and left out because no licence is stated for them.
