# Evaluation harness

Nothing about detection should change without a number. `cau eval` runs a
labelled corpus through the detectors and reports precision, recall,
false-positive rate, per-detector, per-family and per-rule breakdowns, the
exact files on the wrong side of the line, and a performance profile. A
**policy** turns the comparison with a baseline into a CI gate.

```sh
cau eval validate --corpus corpus/smoke/manifest.json --verify-hashes
cau eval run      --corpus corpus/smoke/manifest.json --rules rules --out report.json
cau eval diff     baselines/smoke.json report.json
cau eval gate     --baseline baselines/smoke.json --candidate report.json --policy baselines/policy.json
cau eval policy
```

`make eval` runs validate → run → gate against the committed baseline and CI
runs it on every push. `make baseline` re-records `baselines/smoke.json`;
review the diff before committing it.

## Corpora

A corpus is a directory of samples described by a `manifest.json`. The
harness never infers anything from file names or directory layout: if it is
not in the manifest, it is not in the corpus.

```json
{
  "schema_version": "1",
  "name": "smoke",
  "description": "free text",
  "root": "optional base directory; defaults to the manifest's directory",
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

- Unknown fields are rejected; paths are relative to the root and must not
  escape it.
- `clean` (aliases benign, good, negative, safe) is the only benign label.
  Every other label is a malware family and counts as a positive; `family`
  defaults to the label.
- A sample without a label and without a default label is an error, never a
  guess.
- Declare `sha256` for every sample; `--verify-hashes` recomputes them and
  fails on drift, because a corpus whose bytes changed under a stable manifest
  produces numbers nobody can reproduce.
- Malware samples should record provenance (source, URL, licence). A missing
  source is a warning by default and an error with `--require-provenance`.
  Benign samples should come from a verifiable build: "clean" must be known,
  not assumed.

### Real samples

Never commit live malware. Real corpora live outside the repository (or in an
encrypted, access-controlled store) and are referenced by a manifest that
*is* committed, with `root` pointing at the local checkout. Reference every
sample by SHA-256 and a retrieval URL so anyone with access can rebuild the
corpus byte-for-byte, keep samples non-executable on disk, and scan from an
isolated VM. The harness only reads bytes; it never executes anything. Add
benign samples in the proportion you expect in production: a corpus that is
95 % malware makes every detector look precise.

### The smoke corpus

`corpus/smoke` is synthetic and committed: plain-text files carrying the
strings the shipped rules look for, one file detected only through
`corpus/smoke/hashes.txt`, one Markdown file with stray zero-width codepoints
between its words (nothing is encoded in them), and benign controls that use
the same invisible codepoints legitimately (emoji sequences, Persian ZWNJ,
Devanagari ZWJ, a byte-order mark, UTF-16 text). The engine must reach 100 %
recall and 0 false positives on it; a test enforces that. It proves the
plumbing; recall numbers against it are not detection-quality numbers.

## Reports

A run produces a JSON report (`--out`) with the run metadata (tool, corpus,
detectors, concurrency, error mode), one entry per sample with its verdict
and the signals that fired (detector, rule, family, detail), the confusion
matrix and the derived ratios, per-detector statistics (true and false
positives, recall, FPR, and how many detections were *exclusive* to that
detector), per-family recall, per-rule fires with their false positives, the
lists of false positives, false negatives, errors and skipped samples, and a
performance profile (total and per-sample scan time, p50 / p95 / max,
throughput, the slowest samples). `cau eval report` renders a saved report
as text or JSON.

Signals are the unit of attribution. A detector that returns SUSPICIOUS
without naming a rule contributes to the confusion matrix but nothing to the
triage lists, and the composite "engine" detector reports per-detector
attribution on top of the overall verdict.

## Diff and gate

`cau eval diff` reports the change between two reports: recall and precision
in points, false positives and negatives before and after, per-detector and
per-family deltas, and scan-time change. `cau eval gate` applies a policy to
that diff and exits 1 on a violation. The built-in policy
(`cau eval policy`):

```json
{
  "max_recall_drop": 0,
  "max_fpr_increase": 0,
  "max_new_false_positives": 0,
  "max_error_increase": 0,
  "perf": { "max_total_duration_increase_pct": 50 }
}
```

Performance rules are skipped when the baseline run is shorter than one
second (`perf.min_baseline_duration_ms`), because millisecond runs are noise.
Per-detector and per-family rules can be added to a policy file passed with
`--policy`. Example gate output when YARA is disabled by mistake:

```
recall -60.00 pt, precision +0.00 pt, false positives 0 → 0, false negatives 0 → 3
gate: FAIL (1 violation(s))
  ✗ [overall] max_recall_drop: dropped 60.00 pt, at most 0.00 pt allowed (baseline 100.00%, candidate 40.00%)
```

## Detectors in the harness

| Name | Fires when | Signals |
|---|---|---|
| `hash` | a signature matches | the threat name, family from its first word |
| `yara` | a rule matches | the rule, its `family` meta, tags and threat level |
| `heuristic` | the score reaches the threshold | `heuristic/score` plus one `heuristic/<category>` per category |
| `static` | the static score reaches the threshold | `static/score`, one `static/<class>` per scored anomaly, `static/fuzzy/<type>` per similarity match |
| `stego` | the stego score reaches the threshold | `stego/score` plus one `stego/<class>` per scored finding |
| `fusion` | the fused verdict is suspicious **by corroboration only** | `fusion/corroborated` plus `fusion/agreed/<source>` |

The fusion detector runs the whole engine but reports nothing a single
detector would have reported itself, so its per-detector row is exactly what
the lattice adds.

## Measurements so far

Numbers quoted in the documentation and where they come from:

| Claim | Set | Result |
|---|---|---|
| heuristic retune | 349 files, `/usr/share/windows-resources` | detections 60 → 28; plink 24 → 5, vncviewer 11 → 4, dbghelp.dll 13 → 4; credential dumpers and injectors kept |
| static weights | 49 PE files in the same set | 43 score 0; UPX-packed `wget.exe` 7, ASPack-packed `klogger.exe` 6, both below the threshold with the packer named |
| static throughput | 1.3 MB binary | 44 MB/s with fuzzy hashing, 180 MB/s without |
| stego false positives | 70,102 benign text artifacts under `/usr/share/doc` and `/usr/lib/python3/dist-packages` | 70 detections (0.10 %), 348 legitimate uses excused; 0 of 294 text files in the Windows tool set |
| fusion | 349 files, the Windows tool set | 0 fused-only detections, 0 new false positives |
| bundled YARA rules | the Windows tool set and `/usr/bin` | fire on mimikatz, wce, PowerSploit and `ophcrack`, nothing else |

The honest caveat on all of these: they are fixture-derived numbers from one
machine's package set. Field false-positive rates need the real corpus that
Phase 1 of the plan still lists as open.
