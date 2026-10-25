# Detection content

The engine ships with three content files, all plain text, all validated on
load. Nothing in them is trusted: malformed lines are warnings, duplicates
are refused, and every string they contain is bounded before it reaches a
report.

## Hash signatures (`signatures/hashes.txt`)

Pipe-delimited, one entry per line, `#` comments:

```
HASH_TYPE|HASH|THREAT_NAME
SHA256|0e05a72c8edfeb9ed20174dee7160b3dd4c91d3c27dc70ff14a951ce31dd8d48|Example Family
MD5|84c82835a5d21bbcf75a61706d8ab549|WannaCry Ransomware
```

Rules enforced by `scanner.LoadSignatures` and the tests:

- type is MD5, SHA1 or SHA256 (spellings such as `sha-256` are normalised);
- the digest is hexadecimal and exactly the length for its type, and the
  error names the type the length *does* fit when it is wrong;
- a duplicate digest is skipped with a warning; a digest re-listed under a
  different name is a conflict and the first entry is kept;
- the threat name contains no `|` or line breaks.

`cau add-hash` appends after the same validation. The shipped file contains
real hashes only; the synthetic filler the original project carried was
removed, and a test fails on invalid or synthetic entries.

The planned intake (PLAN.md, Phase 4) replaces hand-typed hashes with
MalwareBazaar / MISP / LOLDrivers feeds and signed release-channel updates.

## YARA rules (`rules/`)

Put `.yar` or `.yara` files in the rules directory; it is walked recursively
and compiled in sorted order into one ruleset. Conventions the bundled
`rules/rule_list.yar` follows and that the reports rely on:

| Convention | Why |
|---|---|
| text strings carry `ascii wide` | they match both the narrow strings in scripts and the UTF-16LE strings in Windows binaries; the original rules were ASCII-only and never fired on mimikatz.exe |
| byte patterns are hex strings | a rule matching the *text* `"0x89,0x00"` can never fire on bytes; two such rules were rewritten |
| `meta.threat_level` 1–5 | shown in reports and SARIF properties |
| `meta.family` | the family the rule claims, used for per-family recall in the evaluation harness |
| `meta.mitre_attack` (optional) | the ATT&CK technique id; the fusion lattice carries it into fused verdicts |
| `meta.description`, `meta.author`, `meta.in_the_wild` | rendered in the text report and the SARIF rule |

The bundled rules cover WannaCry, Mimikatz, LokiBot, shellcode prologues,
PowerShell download cradles and ransomware notes. Measured over Kali's
`/usr/share/windows-resources` and `/usr/bin`, they fire on mimikatz, wce and
PowerSploit, on one dual-use tool (`ophcrack`, which embeds mimikatz command
strings), and on nothing else.

For production coverage, point `--rules` at
[Neo23x0/signature-base](https://github.com/Neo23x0/signature-base),
[Yara-Rules/rules](https://github.com/Yara-Rules/rules) or the
[MalwareBazaar YARA export](https://bazaar.abuse.ch/export/yara/). Compile
warnings from large rule sets are printed, not suppressed; a file that does
not compile is skipped with its position and the rest still loads.

## Fuzzy-hash database (`signatures/fuzzy.txt`)

```
TYPE|DIGEST|THREAT_NAME
TLSH|T1...70 hex characters...|Example Family
SSDEEP|blocksize:hash1:hash2|Example Family
IMPHASH|32 hex characters|Example Family
```

Each digest is validated for its type; duplicates and conflicting re-labels
are refused with the existing entry named. Matching thresholds are published
constants: TLSH distance ≤ 30, ssdeep score ≥ 70; an imphash matches exactly.
A match is SUSPICIOUS-tier evidence carrying the distance and the entry's
name, never a MALICIOUS verdict. `IMPHASH` entries are PE import hashes
(pefile-compatible); the ELF import-set hash that `cau hash` prints is a
clustering key for `cau cluster` and is not looked up here. TLSH and ssdeep
entries apply to every file type.

The shipped database is empty on purpose: fuzzy content arrives through the
same measured intake as hashes, never hand-typed. `cau add-fuzzy --file`
computes every digest a sample yields and appends them.

## Content changes are measured

Every change to these files runs through the evaluation harness in CI
(`make eval`): the smoke corpus must keep 100 % recall and 0 false positives
against the committed baseline. See [Evaluation](evaluation.md).
