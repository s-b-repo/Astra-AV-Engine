# Changelog

All notable changes to CAU EDR. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project has not
cut a tagged release yet, so everything is under Unreleased.

## Unreleased

### Added
- Documentation set under `docs/` (installation, CLI reference, detectors,
  output formats, detection content, evaluation, library usage, architecture,
  limitations, contributing); the README is now the landing page.
- **Detection fusion lattice** (`scanner/fusion`): every detector's result is a
  source with evidence labels and ATT&CK / NOVEL ids; the strongest counts in
  full, sources at or above 0.4 of their own threshold corroborate at half
  weight, hash and YARA hits are never downgraded. Rendered in text, JSON
  (`fusion`), SARIF (`fusion/corroborated`) and the exit policy; a `fusion`
  eval detector reports only corroborated-only verdicts. Measured: 0 fused-only
  detections and 0 new false positives on the 349-file Kali Windows tool set.
- **Invisible-codepoint detector** (`scanner/stego`, NOVEL-001/002):
  zero-width characters, bidirectional overrides (Trojan Source), TAG
  characters and data-carrying variation selectors in UTF-8 / UTF-16 text and
  code, presence-based with named context exceptions (BOM, emoji sequences,
  joining and spaceless scripts, right-to-left lines, CJK variation sequences,
  flag sequences). `--no-stego`, `--stego-threshold`; SARIF `stego/<class>`
  rules with byte-offset regions. Measured: 0.10 % false positives on 70,102
  benign text artifacts.
- ATT&CK technique on every heuristic category (`scanner.CategoryTechnique`,
  `scanner.Categories`), rendered in text and JSON.
- **Static structural pass** (`scanner/static`): own bounds-checked PE parser,
  Shannon entropy (whole file and sliding window), TLSH / ssdeep / imphash,
  section / entry-point / header / import / packer / overlay / Authenticode
  anomalies as labeled classes with ATT&CK mapping, fuzzy-hash database
  (`signatures/fuzzy.txt`), import clustering. New commands `cau hash`,
  `cau cluster`, `cau add-fuzzy`; `--no-static`, `--static-threshold`,
  `--fuzzy-db`, `--no-fuzzy`.
- Evaluation harness (`cau eval validate|run|report|diff|gate|policy`,
  `internal/eval`), committed smoke corpus, baseline and regression policy;
  `make eval` in CI.
- JSON (schema 1.2.0) and SARIF 2.1.0 output, `--fail-on` exit-code policy,
  `--jobs` concurrency, resource discovery relative to the install prefix.

### Changed
- Remaining "Astra" naming in the plan, layout and ignore rules renamed to
  CAU, and the GitHub repository is renamed to `s-b-repo/cau` (the old name
  redirects); only the historical origin keeps the Astra name.
- YARA runs in-process through go-yara with a per-scan timeout; rules are
  compiled once; rule meta, namespaces and warnings are kept.
- Heuristics score once per pattern with category caps and a weak-category
  budget; threshold retuned to 7 on the Kali Windows tool set (60 → 28
  detections, credential tools still detected).
- Bundled rules carry `ascii wide`; two rules that could never fire were
  rewritten; the loose ransomware-extension rule requires a ransom-note name.
- Signature database loading validates type, hex and length, rejects
  duplicates and conflicting re-labels; synthetic filler entries removed.

### Removed
- Shelling out to the `yara` binary.
