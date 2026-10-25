# CAU EDR — Certs Are Useless

> A transparent, open-source malware detection engine in Go. Hash signatures,
> YARA, string/API heuristics, static structure, invisible-codepoint
> steganography, a fusion lattice that joins them, machine-readable reports,
> CI exit codes, and an evaluation harness so every detection change ships
> with a measured number.

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
| **Static structure** | Entropy (whole file and sliding window), TLSH / ssdeep / imphash digests, and a bounds-checked PE pass: sections, entry point, packer identification, Rich header checksum, Authenticode chain, overlay, TLS callbacks, timestamps — each anomaly a labeled class with an ATT&CK mapping, scored with per-category caps | `SUSPICIOUS` with a score, the anomaly classes that fired, the PE anatomy, the digests and any similarity match with its distance |
| **Stego** | Invisible Unicode codepoints in text and code artifacts: zero-width characters (the carrier of README dead-drop channels), bidirectional overrides (Trojan Source), TAG characters and data-carrying variation selectors — presence-based, with a closed list of context exceptions for emoji, joining scripts, spaceless scripts, right-to-left text and byte-order marks | `SUSPICIOUS` with the codepoints, counts, first line, an example rendering the invisibles, and the context rules that excused the rest |
| **Fusion** | The lattice over every detector above: each source is normalised to score/threshold, the strongest counts in full and every other source at or above a floor corroborates at half weight, so two detectors each below their own threshold can still add up to a verdict | the tier, the fused score, which sources agreed in which role, and the union of their ATT&CK / NOVEL ids; a `corroborated` flag marks the detections only fusion found |

Every file is read **once**: the same buffer is hashed, scanned by libyara and
handed to the heuristics and the static pass. Files over the in-memory limit
(64 MiB by default) are streamed and memory-mapped instead of loaded.

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
cau help              # every command and flag
```

Without root, `scripts/dev-env.sh` shows how to point the build at a
user-local libyara.

The binary finds its signature database, YARA rules and fuzzy database
automatically: next to the binary, `<prefix>/share/cau`, `/usr/share/cau`, or
the current directory. Override with `--db` / `--rules` / `--fuzzy-db` or the
`CAU_SIGNATURES` / `CAU_RULES` / `CAU_FUZZY` environment variables.

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
| `--static-threshold N`, `--stego-threshold N` | retune the static (default 8) and stego (default 4, presence-based) thresholds |
| `--no-static`, `--no-stego`, `--no-fusion` | turn a pass off |
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
$ cau scan --quiet --file corpus/smoke/malicious/mimikatz_strings.bin --db corpus/smoke/hashes.txt
 [!] DETECTED (YARA) — corpus/smoke/malicious/mimikatz_strings.bin
     Verdict   : MALICIOUS
     [YARA] default::mimikatz_strings
            author=CAU threat_level=5 in_the_wild=true desc="Mimikatz module and command strings (binary or script carrier)"
            $m1 @ 0x48 : "sekurlsa::logonpasswords"
            $m3 @ 0x61 : "lsadump::sam"
            $m5 @ 0x37 : "privilege::debug"
     Scan time : 1ms

 [!] DETECTED (Heuristics) — corpus/smoke/malicious/mimikatz_strings.bin
     Verdict   : SUSPICIOUS
     Score     : 8 / 7 threshold

     [Credential Access]  (T1003)
       [String]       sekurlsa::logonpasswords
       [String]       lsadump::sam

 [+] Fusion — corpus/smoke/malicious/mimikatz_strings.bin
     Verdict   : MALICIOUS (fused 1.14 / 1.00, high confidence)
     Agreed    : yara, heuristic
     Techniques: T1003
     [yara] definitive
       yara/default/mimikatz_strings      Mimikatz module and command strings (binary or script carrier)
     [heuristic] 8/7, ratio 1.14, corroborating
       heuristic/credential-access        Credential Access 8/8  (T1003)

------------------------------------------------------------
 Scan complete         : 1ms
 Files scanned         : 1
 Hash detections       : 0
 YARA detections       : 1
 Heuristic detections  : 1
 Static detections     : 0
 Stego detections      : 0
 Fused-only detections : 0
 Errors                : 0
 Exit code             : 1 (exit 1: 1 file(s) matched a hash signature or YARA rule)
------------------------------------------------------------
```

### Output formats

The text format above is for people. `--format json` writes one
self-describing document per run and `--format sarif` writes SARIF 2.1.0 for
GitHub code scanning, GitLab, Azure DevOps and DefectDojo. Both are written
even when the run fails, so a pipeline always gets a document; the banner and
progress lines never enter them.

**JSON** (`schema_version` `1.2.0`; additive changes bump the minor version,
consumers should ignore unknown fields):

| Field | Content |
|---|---|
| `summary` | files scanned, per-detector detection counts (`hash_detections`, `yara_detections`, `heuristic_detections`, `static_detections`, `stego_detections`, `fusion_detections` for corroborated-only verdicts), the thresholds in force, the overall verdict, `fail_on`, `exit_code` and `exit_reason` |
| `files[].verdict` | `clean`, `suspicious`, `malicious` or `error` |
| `files[].hashes`, `hash_match` | MD5 / SHA-1 / SHA-256 and the signature that matched |
| `files[].yara[]` | rule, namespace, tags, the full `meta:` block, matched strings with absolute offsets (hex, bounded, with the original length) |
| `files[].heuristics` | score, threshold, categories with raw and applied points and an ATT&CK `technique`, every indicator with examples |
| `files[].static` | entropy, TLSH / ssdeep / imphash, the PE anatomy (sections, entry point, imports, packer, Rich header, Authenticode chain, overlay, debug directory), labeled anomalies with techniques, similarity matches with distances |
| `files[].stego` | encoding, counts scored / excused / informational, every invisible codepoint with count, first line and offset, the context rules that excused occurrences, bounded examples, and the scored findings with `technique` and `novel` |
| `files[].fusion` | tier, fused score and threshold, confidence, `agreed`, `techniques`, `novel`, `corroborated`, a one-line explanation, and every source with its role, ratio, weight and evidence |

Every string that came from a scanned file is length-bounded and HTML-escaped
before it reaches the document.

**SARIF** rule ids are stable: `hash/<threat>`, `yara/<namespace>/<rule>`,
`heuristic/score`, `static/score`, `stego/zero-width`, `stego/bidi-control`,
`stego/tag`, `stego/variation-selector`, `fusion/corroborated` and
`scan/error`. Hash and YARA results are `error` level, the SUSPICIOUS tier is
`note`, scan errors are `warning` (`WithSARIFLevels` changes that for library
users). Stego results carry a byte-offset region with the line number so a
code-scanning UI points at the first hidden codepoint; every result carries a
`sha256/v1` partial fingerprint so the same file is recognised when it moves.

**`--fail-on`** picks the exit-code level: `malicious` (hash or YARA, the
default), `heuristic` (also a heuristic, static or stego breach, or a
corroborated fused verdict), `clean` (also any sub-threshold observation), or
`none`.

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

## Static structure

The static detector (`scanner/static`) asks a different question from the
other three: not "is this content known" or "does it name suspicious
capabilities", but "is this file *built* like something that is hiding".

- **Entropy** for every file type: whole-file Shannon entropy plus a 256-byte
  sliding window, so a compressed tail inside an otherwise ordinary file shows.
- **Fuzzy digests**: TLSH and ssdeep for every file, imphash for PE files
  (pefile-compatible, including the ws2_32 / wsock32 / oleaut32 ordinal
  tables). `cau hash <file>` prints them.
- **PE anatomy** from an own parser that checks every offset against the
  buffer (the standard library's `debug/pe` drops ordinal imports and trusts
  header sizes): sections with permissions and entropy, entry-point placement,
  import profile, delay imports, exports, debug directory, TLS callbacks,
  overlay (with the certificate table separated out), Rich header with its
  checksum, and the Authenticode certificate chain.
- **Anomalies** are labeled classes — `section.rwx`, `packer.upx`,
  `rich.checksum-invalid`, `authenticode.vendor-name-self-signed`,
  `header.timestamp-future`, `fuzzy.tlsh`, … — each with a weight, a category
  cap and an ATT&CK technique where one applies. The score reaches the
  threshold (8 by default, `--static-threshold`) only when several independent
  things are wrong at once.

Honesty rules baked into the output:

- **Packed is not malicious.** A recognised packer scores less than an
  unrecognised packed profile; the report names it. On the Kali Windows tool
  set the UPX-packed GNU `wget.exe` scores 7 and renders as *low suspicion*
  with `packer.upx` named, below the threshold.
- **Signature presence is not validity.** The Authenticode blob is parsed and
  the chain inspected for implausibility (self-signed signer, a vendor's name
  on a self-signed certificate, no code-signing EKU, file linked outside the
  certificate's validity with no countersignature). Nothing is verified
  against a trust store, `verified` is always `false`, and the JSON carries the
  note and the name the chain ends at (real chains are usually cross-signed
  and end at an external root).
- **Similarity is evidence, not identity.** A TLSH distance ≤ 30 or an ssdeep
  score ≥ 70 to an entry in `signatures/fuzzy.txt` reaches the threshold on
  its own, but in the SUSPICIOUS tier with the distance attached, never as a
  MALICIOUS verdict. The shipped fuzzy database is empty on purpose.
- Delphi's constant 1992 timestamp, kernel drivers' RWX `INIT` section,
  MinGW's `msvcrt.dll` and reproducible builds are explicit non-findings; each
  was a false positive on the first measurement pass and is now a test.

Weights were measured on the 49 PE files in `/usr/share/windows-resources`:
43 score 0, nothing crosses the threshold, and `scanner/static/static_test.go`
pins that alongside synthetic UPX, forged-signature and tampered-header
fixtures built in the test itself (no real samples are committed).

```sh
cau hash plink.exe                                   # sha256, imphash, tlsh, ssdeep
cau cluster --dir ./samples                          # group PE files by import similarity
cau add-fuzzy --file sample.bin --name "Example Family"   # TLSH + ssdeep + imphash entries
cau scan --no-static ./build                         # turn the pass off
cau scan --no-fuzzy ./build                          # keep the PE pass, skip TLSH/ssdeep
```

`cau cluster` groups files by exact imphash and by MinHash/LSH similarity of
their import sets (Jaccard floor `--min-similarity`, default 0.6). On the
fixture set every x86/x64 pair of the same tool lands in one cluster.

## Invisible codepoints (stego)

`scanner/stego` looks at every text artifact (valid UTF-8, or UTF-16 with a
byte-order mark; binary content is skipped and the reason recorded) for
codepoints that have no glyph: ZERO WIDTH SPACE / JOINER / NON-JOINER, WORD
JOINER and the invisible operators, the bidirectional embeddings, overrides
and isolates, Unicode TAG characters, and variation selectors. These are the
carriers of zero-width steganography (a command channel hidden between the
words of a README), of Trojan Source (source that compiles differently from
how it is displayed), of TAG-character text smuggling and of
variation-selector byte encoding. This is the engine half of the plan's
NOVEL-001 / NOVEL-002 rows.

Detection is **presence-based**: density thresholds are the first thing an
encoder drops below. What keeps it usable is a closed list of context rules,
each named in the report when it applies: a BOM at offset 0, a joiner inside
an emoji sequence, a joiner next to a script that uses joiners (Arabic,
Persian, the Indic scripts, ...), a ZERO WIDTH SPACE next to a script written
without inter-word spaces (Khmer, Thai, Lao, Myanmar, Tibetan), a directional
control on a line that holds right-to-left text, a presentation selector
after an emoji, a variation selector after a CJK ideograph, and TAG
characters inside a subdivision-flag emoji. Directional *marks* and the soft
hyphen are recorded but never scored. Two modifiers raise the score without
being findings: a run of eight or more consecutive invisible codepoints
(payloads have length) and codepoints whose visible neighbours on both sides
are ASCII (the dead-drop carrier pattern). The default threshold (4) is
reached by any scored class; `--stego-threshold 8` requires a modifier too.

Measured on 70,102 benign text artifacts (every text file under Kali's
`/usr/share/doc` and `/usr/lib/python3/dist-packages`) the pass fires on 70,
a 0.10 % false-positive rate, and on none of the 294 text files in
`/usr/share/windows-resources`. The remaining false positives are the two
classes the package documentation names: a stray ZERO WIDTH SPACE pasted into
documentation or a translation file (one or two occurrences, which the report
shows as exactly that), and source files that enumerate Unicode categories
(regular-expression libraries, identifier tables) and so contain one of every
invisible codepoint. The 348 legitimate uses the context rules excused
(emoji, flags, Khmer, Arabic and Hebrew translations, BOMs) are listed in the
JSON with the rule that applied.

## Fusion

Each detector's threshold is tuned so that it alone stays quiet on ordinary
software. The cost is that a file scoring 5/7 on the heuristics and 6/8 on the
structural pass used to be CLEAN, although two detectors with uncorrelated
error modes both saw something. `scanner/fusion` makes that corroboration
count:

- every scored source becomes a ratio score/threshold, capped at 1.5 so one
  loud detector is still one detector;
- the strongest source counts in full; every other source at or above 0.4 of
  its own threshold corroborates at half weight; weaker evidence (one `Sleep`
  import) is listed but does not count;
- the fused score reaches 1.0 when a detector crosses alone, exactly as
  before, or when corroboration adds up to the same thing;
- a hash or YARA hit is definitive and is never downgraded; the lattice still
  says whether anything else corroborated it.

The verdict lists every source with its role (`definitive`, `primary`,
`corroborating`, `below-floor`, `silent`, `skipped`), carries the evidence
labels and ATT&CK / NOVEL ids through, and sets `corroborated` when the
suspicious tier was reached only through the lattice. Those are the detections
fusion adds, and they are what the `fusion` eval detector, the
`fusion/corroborated` SARIF rule and the "Fused-only detections" summary line
count. Heuristic categories now carry an ATT&CK technique as well, so a fused
verdict can say "T1055 + T1027.002" rather than "two scores".

Measured on the 349 files of `/usr/share/windows-resources` with the shipped
constants: zero fused-only detections and zero new false positives; the
nearest benign file (the UPX-packed `wget.exe`, static 7/8) has no second
source above the floor. The constants are published in the package and pinned
by tests that include a monotonicity check: raising any input never lowers the
fused score or tier.

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
detector (including a prose file with stray zero-width codepoints and benign
controls with emoji joiners, Persian and Hindi text, a BOM and UTF-16); real
samples are referenced by hash and retrieval URL and are never committed. The
`fusion` eval detector reports only what corroboration adds, so its row in the
per-detector table is the lattice's own contribution.

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
scanner/static/, scanner/stego/      structural pass; invisible-codepoint pass
scanner/fusion/                      the detection fusion lattice
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
| 4 | PE header & section analysis | ✅ (`scanner/static`: sections, entry point, packers, Rich header, Authenticode chain, overlay) |
| 5 | Entropy analysis (packed/encrypted file detection) | ✅ (whole-file + sliding window) |
| 6 | Fuzzy hashing (ssdeep/TLSH) | ✅ (+ imphash, fuzzy database, import clustering) |
| — | Zero-width / invisible-codepoint detection (NOVEL-001), detection fusion lattice | ✅ (`scanner/stego`, `scanner/fusion`) |
| 7 | Malware evasion — defeating the engine | planned |

### Limitations (by design)

Hash detection dies to a single flipped byte; fuzzy hashes survive that and
die to a repack. YARA rules are only as good as what they cover, and an author
who knows the ruleset renames strings or encrypts payloads. Heuristics measure
*capability*, so a debugger looks like an injector. The static pass measures
*structure*, so a packed benign tool looks packed and an unpacked credential
dumper looks ordinary. The stego pass is presence-based, so a stray zero-width
space pasted into a README is reported as exactly that. Fusion raises the cost
of evasion from one detector to several at once; it does not create evidence,
so a file that is silent on every detector stays clean. The evasion episode
will demonstrate all of this against this engine; the evaluation harness
exists so the demonstration can be measured.

## Disclaimer

For educational and research use. Only analyze files and systems you own or
are authorised to analyze. Handle real malware samples in isolated
environments and never commit them to this repository.

## License

MIT, see [LICENSE](LICENSE).
