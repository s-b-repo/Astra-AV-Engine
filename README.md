# CAU EDR — Certs Are Useless

> A transparent, open-source malware detection engine in Go. Hash signatures,
> YARA, string/API heuristics, machine-readable reports, CI exit codes, and an
> evaluation harness so every detection change ships with a measured number.

CAU is the engine half of a two-part design: this repository (MIT) is the
scanner, detection content, and evaluation tooling meant for analysts,
developers and CI. Fleet state, response and policy live in a separate control
plane. See [PLAN.md](PLAN.md) for the roadmap and the reasoning behind the split.

This project started as a fork of the Astra AV Engine educational series. The
episode structure is kept below because the series is the best explanation of
*why* each detector exists; the implementation has since been reworked for
correctness and measurability.

---

## What it does

| Detector | How | Output |
|---|---|---|
| **Hash signatures** | MD5 / SHA-1 / SHA-256 of every file against a validated, de-duplicated signature database | `MALICIOUS` with the threat name |
| **YARA** | Rules compiled once at startup with libyara (in-process, no `yara` binary, no per-file process spawn) and matched in memory with a per-file timeout | rule, real namespace, tags, `meta:` block, matched strings with absolute offsets |
| **Heuristics** | Suspicious Windows API imports and strings, scored once per pattern with per-category caps so repeated indicators cannot inflate the score | `SUSPICIOUS` with a score, the categories that contributed, and example strings |

Every file is read **once**: the same buffer is hashed, scanned by libyara and
handed to the heuristics. Files over the in-memory limit (64 MiB by default)
are streamed and memory-mapped instead of loaded.

## Install

Requirements: Go 1.24+, libyara 4.3+ with headers, pkg-config.

```sh
# Debian / Ubuntu / Kali
sudo apt install libyara-dev pkg-config
# macOS
brew install yara pkg-config

git clone https://github.com/cau-edr/cau.git
cd cau
make build            # -> ./cau
sudo make install     # -> /usr/local/bin/cau + /usr/local/share/cau/{rules,signatures}
```

Without root, `scripts/dev-env.sh` shows how to point the build at a
user-local libyara.

The binary finds its signature database and rules automatically: next to the
binary, `<prefix>/share/cau`, `/usr/share/cau`, or the current directory.
Override with `--db` / `--rules` or the `CAU_SIGNATURES` / `CAU_RULES`
environment variables.

## Scan

```sh
cau scan --file suspicious.exe
cau scan --dir ./downloads
cau scan ./build ./dist --format json --output report.json
cau scan --dir . --format sarif --output cau.sarif --fail-on none   # for code scanning upload
cau scan --dir / --jobs 16 --no-heuristics --quiet
```

Useful flags:

| Flag | Meaning |
|---|---|
| `--format text\|json\|sarif` | human output, a versioned JSON document, or SARIF 2.1.0 |
| `--fail-on none\|malicious\|heuristic\|clean` | which finding level makes the exit code 1 (default `malicious`) |
| `--no-fail-on-scan-error` | do not exit 2 when some files could not be read |
| `--jobs N` | files scanned concurrently (default: CPUs) |
| `--heuristic-threshold N` | retune the heuristic score threshold (default 7) |
| `--yara-timeout 30s` | per-file YARA budget; an adversarial sample cannot hang the scanner |
| `--max-in-memory MiB` | larger files are streamed and skip heuristics |
| `--follow-symlinks` | scan symlinked files (directory symlinks are never followed) |
| `--quiet` | no banner or progress on stderr |

The banner and progress always go to **stderr**; the report goes to stdout or
`--output`, so `--format json` is safe to pipe.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | nothing at or above the `--fail-on` level |
| 1 | findings at or above the `--fail-on` level |
| 2 | some files could not be scanned (an unscanned file must never look clean) |
| 3 | the run itself failed (bad database, rules that do not compile); a JSON/SARIF document is still written |
| 4 | usage error |

### Example

```
$ cau scan --file corpus/smoke/malicious/mimikatz_strings.bin --db corpus/smoke/hashes.txt
 [!] DETECTED (YARA) — corpus/smoke/malicious/mimikatz_strings.bin
     Verdict   : MALICIOUS
     [YARA] default::mimikatz_strings
            author=CAU threat_level=5 in_the_wild=true desc="Mimikatz module and command strings"
            $m1 @ 0x48 : "sekurlsa::logonpasswords"
            $m3 @ 0x61 : "lsadump::sam"
            $m5 @ 0x37 : "privilege::debug"

 [!] DETECTED (Heuristics) — corpus/smoke/malicious/mimikatz_strings.bin
     Verdict   : SUSPICIOUS
     Score     : 8 / 7 threshold
     [Credential Access]
       [String]       sekurlsa::logonpasswords
       [String]       lsadump::sam
------------------------------------------------------------
 Files scanned         : 1
 YARA detections       : 1
 Heuristic detections  : 1
 Exit code             : 1 (exit 1: 1 file(s) matched a hash signature or YARA rule)
------------------------------------------------------------
```

## Signature database

`signatures/hashes.txt` is pipe-delimited: `HASH_TYPE|HASH|THREAT_NAME`.
Loading validates every line (known type, hexadecimal, exact length for the
type) and rejects duplicates; a digest re-listed under a different name is
reported as a conflict and the first entry is kept. Rejected lines are
printed as warnings, never silently dropped or silently overwritten. The
shipped file is covered by a test that fails on invalid or synthetic entries.

```sh
cau add-hash --hash <sha256> --name "WannaCry Ransomware"   # type inferred from the length
cau add-hash --type md5 --hash 84c82835a5d21bbcf75a61706d8ab549 --name "WannaCry Ransomware"
```

## YARA rules

Put `.yar` / `.yara` files in `rules/` (walked recursively, compiled in sorted
order). A rule file that does not compile is reported with file, line and
column and **skipped**; the rest of the ruleset still loads. A ruleset with no
usable rule is a hard error. Compiler warnings (slow strings, dead rules) are
shown, not suppressed.

The bundled `rules/rule_list.yar` covers WannaCry, Mimikatz, LokiBot,
shellcode prologues, PowerShell download cradles and ransomware notes. Text
strings carry `ascii wide` so they match UTF-16 strings inside Windows
binaries, which the original rules did not. Measured over Kali's
`/usr/share/windows-resources` and `/usr/bin`, the bundled rules fire on
mimikatz, wce and PowerSploit and on one dual-use tool (`ophcrack`, which
embeds mimikatz command strings), and on nothing else.

For production coverage pull from
[Neo23x0/signature-base](https://github.com/Neo23x0/signature-base),
[Yara-Rules/rules](https://github.com/Yara-Rules/rules) or the
[MalwareBazaar YARA export](https://bazaar.abuse.ch/export/yara/).

## Heuristics

The heuristic detector scores PE import names and extracted strings. The
scoring model (see the header of `scanner/heuristics.go`):

1. a pattern scores **once per file**, no matter how many strings contain it;
2. every category has a cap;
3. the "weak" categories (networking, timers, file deletion, discovery, temp
   paths) share a budget of 2 points in total, so ordinary program behaviour
   never adds up to a detection;
4. an API credited from the import table is not scored again as a string.

Measured on 349 files from Kali's Windows tool set, this cut heuristic
detections from 60 to 28. Benign tools dropped below the threshold (plink
24 → 5, vncviewer 11 → 4, dbghelp.dll 13 → 4); credential dumpers, injectors
and PowerSploit stayed above it. OllyDbg still scores 11: a debugger has
exactly the import profile of a process injector, and the report says which
imports were responsible. `scanner/heuristics_test.go` pins these fixtures.

## Evaluation harness

Nothing about detection should change without a number. `cau eval` runs a
labelled corpus and reports precision, recall, FPR, per-detector, per-family
and per-rule breakdowns, the exact files on the wrong side of the line, and a
performance profile. A **policy** turns a baseline comparison into a CI gate.

```sh
cau eval validate --corpus corpus/smoke/manifest.json --verify-hashes
cau eval run      --corpus corpus/smoke/manifest.json --rules rules --out report.json
cau eval diff     baselines/smoke.json report.json
cau eval gate     --baseline baselines/smoke.json --candidate report.json --policy baselines/policy.json
cau eval policy   # print the default policy
```

`make eval` does validate → run → gate against the committed baseline, and CI
runs it on every push. `make baseline` re-records the baseline; review the
diff before committing it.

The corpus format (a JSON manifest with ids, labels, families, SHA-256 and
provenance per sample) is documented in [corpus/README.md](corpus/README.md).
`corpus/smoke` is a committed set of harmless text files that exercise every
detector; real samples are referenced by hash and retrieval URL and are never
committed.

Example gate output when YARA is disabled by mistake:

```
recall -60.00 pt, precision +0.00 pt, false positives 0 → 0, false negatives 0 → 3
gate: FAIL (1 violation(s))
  ✗ [overall] max_recall_drop: dropped 60.00 pt, at most 0.00 pt allowed (baseline 100.00%, candidate 40.00%)
```

## Development

```sh
source scripts/dev-env.sh   # only for a user-local Go / libyara
make lint                   # gofmt + go vet
make test-race
make bench                  # YARA load/scan and heuristics benchmarks
make ci                     # what GitHub Actions runs
```

Layout:

```
main.go, cmd_eval.go, resources.go   CLI, eval subcommands, resource discovery
scanner/                             engine (single-pass), hash DB, YARA (go-yara), heuristics
internal/report/                     text / JSON / SARIF reporters and the exit-code policy
internal/eval/                       corpus manifest, runner, metrics, diff, regression policy
internal/eval/scannerbridge/         adapts the scanner to the harness
rules/, signatures/                  bundled detection content
corpus/smoke/, baselines/            committed smoke corpus, baseline report, gate policy
```

## Series roadmap

| Episode | Feature | Status |
|---|---|---|
| 1 | Hash-based detection (MD5, SHA-1, SHA-256) | ✅ |
| 2 | YARA rule scanning | ✅ (in-process libyara) |
| 3 | String & API heuristics | ✅ (rescored, measured) |
| — | JSON / SARIF output, exit codes, concurrency, eval harness | ✅ |
| 4 | PE header & section analysis | planned |
| 5 | Entropy analysis (packed/encrypted file detection) | planned |
| 6 | Fuzzy hashing (ssdeep/TLSH) | planned |
| 7 | Malware evasion — defeating the engine | planned |

### Limitations (by design)

Hash detection dies to a single flipped byte. YARA rules are only as good as
what they cover, and an author who knows the ruleset renames strings or
encrypts payloads. Heuristics measure *capability*, so a debugger looks like
an injector. The evasion episode will demonstrate all three against this
engine; the evaluation harness exists so the demonstration can be measured.

## Disclaimer

For educational and research use. Only analyze files and systems you own or
are authorised to analyze. Handle real malware samples in isolated
environments and never commit them to this repository.

## License

MIT, see [LICENSE](LICENSE).
