# Detection engineering

How the engine's practice maps onto the public detection-engineering
frameworks, and where the tooling for each one lives. The references are the
ones collected in
[awesome-detection-engineering](https://github.com/infosecB/awesome-detection-engineering);
this page says what the engine actually does about each, not what it could.

## Every detection is documented (ADS)

Each detector has an [Alerting and Detection Strategy](ads/README.md) in the
Palantir ADS format: goal, ATT&CK categorization, strategy abstract,
technical context, blind spots and assumptions, false positives, validation,
priority, response. The blind-spot and false-positive sections are the
measured ones from [Limitations](limitations.md), not aspirations; the
validation section names the fixtures and the harness command that prove
the detection still works.

## Every finding maps to ATT&CK, and the gaps are published

Every heuristic category, static anomaly class, stego finding class and
bundled YARA rule carries an ATT&CK technique id, or is listed as unmapped.
`cau coverage` derives the matrix from the content itself (there is no
hand-typed coverage table anywhere in the repository) and renders it as
text, JSON, an [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
layer (`make coverage` writes `eval-out/attack-navigator.json`; load it in
the Navigator to see the heat map) or a SARIF 2.1.0 log
(`eval-out/attack-coverage.sarif`) that renders one result per technique so a
code-scanning dashboard shows the map and flags the planned gaps.

The matrix is also a gate. `baselines/attack-coverage.txt` declares every
covered technique and every known gap; CI runs `cau coverage --expect` and
fails on any difference, in either direction. A detector change that drops a
technique is a regression; a rule that adds one has to be recorded on
purpose. Each technique carries one of four states: detected (content maps to it),
partial (content maps but the coverage is acknowledged incomplete, as the
discovery command-pattern analytics are), planned (a declared gap on the
roadmap: T1027.013, T1140, T1564.001) and none (no content and none planned
because the sensor or console owns it). The planned gaps are rendered in the
Navigator layer in grey and as SARIF warnings rather than left blank, which
is the DETT&CT principle of scoring visibility honestly instead of implying
coverage.

## Where each detector sits on the Pyramid of Pain

| Source | Level | Why |
|---|---|---|
| hash signatures | hash values | one flipped byte and the indicator is gone |
| similarity (TLSH, ssdeep, imphash) | hash values | survives trivial edits, dies to a rebuild |
| YARA | tools | rules describe a tool or family by its strings; the author recompiles with new ones |
| heuristics | tools | the import profile and strings a capability needs; hidden by dynamic resolution |
| static structure | TTPs | packing, forged build records, implausible signers, loader hijacks are techniques, whatever the sample |
| invisible codepoints | TTPs | the carrier alphabet of a technique, presence-based |

A file scanner never reaches the IP-address or domain-name layers. The
matrix prints the level next to each source so a reader can tell a hash hit
from a structural one without reading the detector docs.

## Rules are linted before they ship

`cau rules lint` applies the checks a rule needs before it is content
(the Zen of Security Rules, reduced to what a file scanner can verify): it
compiles without warnings, it says what it detects and how bad a hit is, it
names the technique it is evidence for, its strings can match bytes (hex
written as text is the dead-rule class that shipped in the original
project), and its condition is not trivially true. `make lint-rules` runs
in CI; the `generic` profile lints third-party sets such as
[signature-base](https://github.com/Neo23x0/signature-base) or the
[Elastic YARA signatures](https://github.com/elastic/protections-artifacts)
before they are pointed at with `--rules`.

## Content is measured before it is promoted

Every change to a detector, weight, threshold or content file runs through
the [evaluation harness](evaluation.md): the smoke corpus must keep its
recall and false-positive numbers against the committed baseline, and the
real-binary populations the existing numbers were measured on are the bar
for anything that touches scoring. This is the "detection development
lifecycle" step that most frameworks describe and the one that is enforced
here by `make eval` rather than by review.

## Findings land in a lake without a parser

`--format ocsf` writes [OCSF](https://ocsf.io) 1.3.0 Detection Findings for
Matano, Amazon Security Lake and anything else OCSF-native; `--format sarif`
feeds code-scanning dashboards; JSON is the native, versioned schema. The
mapping is in [Output formats](output-formats.md).

## Maturity, honestly

Against the detection-maturity models on the list (Stillions' DML, the
Elastic and Snowflake matrices), the engine sits where a static file scanner
can: it detects at the level of tools and techniques for file content, it
measures itself, and it publishes its gaps. It has no telemetry, no
behavioural analytics and no response; those belong to the sensor and
console described in [PLAN.md](../PLAN.md), and nothing here claims
otherwise.
