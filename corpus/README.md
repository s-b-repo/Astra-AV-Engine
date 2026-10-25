# Corpora

A corpus is a directory of labelled samples described by a `manifest.json`.
The evaluation harness (`internal/eval`) never infers anything from file names
or directory layout: if it is not in the manifest, it is not in the corpus.

```
corpus/
  README.md
  smoke/                 # synthetic, committed, safe
    manifest.json
    hashes.txt           # signature DB with the hash-only sample's SHA-256
    malicious/*.bin      # text files that trip rules/rule_list.yar
    malicious/*.md       # prose with stray zero-width codepoints (stego pass)
    malicious/*.bin      # also one synthetic ELF with a dropper's structure (static pass)
    benign/*             # true negatives: an empty file, a script with a URL, emoji
                         # joiners, Persian and Hindi text, a BOM, UTF-16 — legitimate
                         # uses of the codepoints the stego pass looks for — and a
                         # synthetic clean ELF
  <name>/                # real corpora live outside git (see below)
```

## Manifest format (`schema_version` "1")

```json
{
  "schema_version": "1",
  "name": "smoke",
  "description": "free text",
  "root": "optional base dir; defaults to the manifest's directory",
  "defaults": { "label": "", "family": "", "source": "synthetic", "license": "MIT" },
  "samples": [
    {
      "id": "mal-wannacry_strings",
      "path": "malicious/wannacry_strings.bin",
      "label": "wannacry",
      "family": "wannacry",
      "sha256": "67752ad7…",
      "tags": ["optional"],
      "notes": "optional",
      "provenance": { "source": "malwarebazaar", "url": "https://…", "license": "CC-BY-SA-4.0", "retrieved": "2026-10-24T00:00:00Z" }
    }
  ]
}
```

Unknown fields are rejected. Paths are relative to the root and must not
escape it. `cau eval validate` runs `Manifest.Validate` and refuses to measure
a corpus with any error-severity issue.

## Labels

- `clean` (aliases: benign, good, negative, safe) is the only benign label.
- Every other label is a malware family and counts as a positive. `family`
  defaults to the label. Use lowercase family names consistently; per-family
  recall is keyed on them.
- A sample without a label and without `defaults.label` is an error, never a
  guess.

## Provenance

Malware samples should record where they came from (`provenance.source` and
`url`) and under which licence. A missing source is a warning by default and an
error under `--require-provenance`. Benign samples should come from a
verifiable build (a distro package, a signed release, something you compiled):
"clean" must be known, not assumed.

## Hashes

Declare `sha256` for every sample. `--verify-hashes` recomputes them and fails
on drift, because a corpus whose bytes changed under a stable manifest produces
numbers nobody can reproduce.

## Adding real samples safely

- Never commit live malware. Real corpora live outside the repository (or in
  an encrypted, access-controlled store) and are referenced by a manifest that
  *is* committed, with `root` pointing at the local checkout of the samples.
- Reference every sample by SHA-256 and a retrieval URL (MalwareBazaar,
  VirusShare, a vendor drop) so anyone with access can rebuild the corpus
  byte-for-byte.
- Keep samples non-executable on disk (`chmod 0400`) and scan from an isolated
  VM. The harness only reads bytes; it never executes anything.
- Add benign samples in the same proportion you expect in production. A corpus
  that is 95% malware makes every detector look precise.

## The smoke corpus

`smoke/` is synthetic: plain-text files carrying the strings that the shipped
rules look for, one file that no rule matches and that is detected only
through `smoke/hashes.txt`, one Markdown file with stray zero-width codepoints
between its words (nothing is encoded in them; the fixture exercises presence
detection), and benign controls that use the same invisible codepoints
legitimately (emoji sequences, Persian ZWNJ, Devanagari ZWJ, a byte-order
mark, UTF-16 text), plus two ELF images that `scanner/static`'s
`TestWriteELFFixtures` regenerates byte-for-byte: a clean PIE and a file with
a dropper's structure (RWX packed code, a program interpreter under `/tmp`,
`dlopen`/`dlsym`-only imports) whose bytes are pseudo-random and run nothing.
With `rules/rule_list.yar` and `smoke/hashes.txt` the engine must reach 100%
recall and 0 false positives on it; the test in
`internal/eval/scannerbridge` enforces that, and the harness's own tests check
that the manifest validates with hash verification on.

`make baseline` records the current report as `baselines/smoke.json`;
`make eval` fails when a change regresses against it under
`baselines/policy.json` (no recall drop, no new false positive, no new error).
The `fusion` detector in the baseline counts only verdicts reached by
corroboration, so its row is the lattice's own contribution.
