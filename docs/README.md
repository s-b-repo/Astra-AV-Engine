# CAU EDR documentation

CAU EDR ("Certs Are Useless") is an open-source malware detection engine
written in Go. These pages are the reference; the repository
[README](../README.md) is the overview.

| Page | What it covers |
|---|---|
| [Installation](installation.md) | requirements, building, installing, release tarballs, where resources are found |
| [Command-line reference](cli.md) | every command and flag, exit codes, CI recipes |
| [Detectors](detectors.md) | hash signatures, YARA, heuristics, static structure, invisible codepoints, the fusion lattice |
| [Output formats](output-formats.md) | the text report, the JSON document (schema 1.3.0), SARIF 2.1.0, the `--fail-on` policy |
| [Detection content](detection-content.md) | signature databases, YARA rule conventions, the fuzzy-hash database, external rule sets |
| [Evaluation harness](evaluation.md) | corpora, manifests, baselines, regression policies, the measurements behind every number |
| [Library usage](library.md) | using the engine from Go |
| [Architecture](architecture.md) | the single-read pipeline, verdict tiers, design rules, repository layout |
| [Limitations](limitations.md) | what each detector cannot do, the documented false-positive classes |
| [Contributing](contributing.md) | development environment, tests, the measure-or-don't-ship rule, corpus policy |

Roadmap and design reasoning live in [PLAN.md](../PLAN.md); release notes in
[CHANGELOG.md](../CHANGELOG.md).
