# ADS: Hash signatures

## Goal
Identify files whose exact content is already known to be malicious, by
cryptographic digest, with the threat name the database lists.

## Categorization
No ATT&CK technique: a hash names a sample, not a behaviour. Pyramid of
Pain: hash values. Tier: MALICIOUS.

## Strategy Abstract
MD5, SHA-1 and SHA-256 are computed in one streaming pass over the file and
looked up in `signatures/hashes.txt`, SHA-256 first. A hit is definitive:
the fusion lattice never downgrades it.

## Technical Context
The database is pipe-delimited text validated on load (type, hex, exact
length per type, no duplicates, conflicts kept at the first entry and
reported). The reported signature count is the number of entries that can
actually match. `cau add-hash` appends through the same validation. Phase 4
of the plan replaces hand-typed entries with MalwareBazaar / MISP /
LOLDrivers intake.

## Blind Spots and Assumptions
A single flipped byte defeats it. It assumes the database is current and
that the sample was seen before. It cannot see inside archives or packed
layers.

## False Positives
None by construction when the database is correct; a mislabeled entry is a
content error, which is why synthetic filler was removed and a test fails on
invalid or synthetic entries.

## Validation
`corpus/smoke/malicious/hash_only.bin` against `corpus/smoke/hashes.txt`
must be MALICIOUS on every run (`make eval`). `cau scan --file <sample> --db
<db>` reproduces a hit by hand.

## Priority
High: a hit is a known sample. `--fail-on malicious` (the default) acts on it.

## Response
Quarantine the file; pivot on the SHA-256 in the fleet (the console's job);
check the fuzzy database for near relatives with `cau hash` and `cau cluster`.
