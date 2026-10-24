# Astra AV — v2 Plan

## Agent scope note (for human and AI contributors)

This repo is a detection program. Technique knowledge exists here only as detection
requirements: per-technique analytics (Phases 10/11), coverage states, and synthetic
fixtures. The rules, in priority order:

- Implement the detection rows; never implement the techniques themselves — no implant
  code, weaponization, or payload work, and no evasion engineering in any framing.
- Detection analytics are written from public technique definitions, never from the
  internal corpus's bypass notes; those notes stay in the internal program tracker and
  are never mirrored here.
- Fixtures are synthetic and generated at eval time; never built from real samples or
  from internal offensive documents.
- When a task straddles the boundary (partly detection, partly bypass), the part that
  crosses is refused, not split off and shipped.

## Product shape

Two artifacts, two audiences, two licenses.

| | `astrav2` (this repo) | `astra-console` (proprietary) |
|---|---|---|
| License | MIT | Commercial, per protected host |
| What it is | The **engine**: detection content, scanning library, MCP server, evaluation harness | The **control plane**: fleet management, policy, detection lifecycle, response, model registry, dashboard |
| Persona | Analyst / developer / CI | Operator / SOC / platform team |
| Deploy | Anywhere, air-gapped | Fleet of agents + web console |

The split is persona-based, not crippled-features-based. The OSS engine stays genuinely
useful standalone so it gets adopted; the console is sold because fleet state, response
authority, and governance are inherently stateful and cannot live in a scanner.

---

## Phase 0 — Unblock the fork (blocking) — DONE 2026-10-24

All findings were verified against `0f0c000` in `s-b-repo/Astra-AV-Engine` and
every item below is closed. Notes on what was actually measured:

- Heuristics retune, measured on 349 files in Kali's `/usr/share/windows-resources`:
  detections 60 → 28; plink 24 → 5, vncviewer 11 → 4, dbghelp.dll 13 → 4;
  mimikatz / wce / pwdump / shellter stay detected. OllyDbg (11) remains a
  documented false positive: a debugger has an injector's import profile.
- Bundled rules were ASCII-only and never fired on `mimikatz.exe` (wide
  strings). Now `ascii wide`; the loose ransomware-extension rule, which hit
  18 Go binaries in `/usr/bin`, requires a ransom-note name alongside extensions.
- `exec.CommandContext` is moot: nothing shells out any more; libyara gets a
  per-scan timeout instead (`--yara-timeout`, default 30s, 0 rejected).
- Tags + releases: the CI workflow builds a release tarball on `v*` tags; no
  tag has been cut yet.

**Dependency**
- [x] Switch to `github.com/hillu/go-yara/v4` bindings. Declared in `go.mod:5`, imported
      nowhere, no `go.sum`. Remove all `exec.Command("yara", ...)` in `scanner/yara.go`.
- [x] Compile the ruleset once at startup; scan in memory. Kills
      O(files x rules) process spawning (`yara.go:78-91`) and the per-sample rules-dir
      re-walk (`yara.go:71`). `Neo23x0/signature-base` is ~3k rules — current code spawns
      3k processes per sample.
- [x] `exec.CommandContext` everywhere YARA / external tools run. No timeout = adversarial
      sample hangs the scanner permanently.

**Correctness**
- [x] Per-rule-file error isolation. `yara.go:89` returns mid-loop and discards already
      collected matches; one broken rule silently turns a sample CLEAN.
- [x] Capture rule `meta` + real namespace (`yara -p -g -m -e -s`). Today `threat_level`,
      `author`, `in_the_wild` in `rule_list.yar` are parsed and discarded.
- [x] Stop suppressing rule warnings (`-w`). Rule authors need to see dead rules.
- [x] `AddSignature` / `LoadSignatures`: validate hex + exact length per type, reject
      duplicates, detect cross-type collisions.
- [x] Fix signature DB. 53 entries → 51 unique; 2 duplicates silently overwrite via
      `entries[hash] = sig` (`scanner.go:92`); 10 entries have invalid 63-char SHA256s
      (lines 17, 34, 37, 42, 46, 56, 57, 65, 66, 101); ~38 are synthetic filler
      (`a1b2c3d4e5f6…`, `f0e1d2c3b4a5…`, `2d4f6a8c0e2b…`). Only ~15 are real.
- [x] `db.Count()` returns map size, not entry count — under-reports at load.

**Heuristics**
- [x] Fix score inflation. `heuristics.go:255` dedups on `pattern|extractedString`, so
      each distinct string containing `http://` scores +1 → 200 URLs = score 200 vs
      threshold 3. Collapse to per-pattern caps.
- [x] Retune weights. `Sleep` / `connect` / `GetTickCount` in the IAT of ordinary
      networked software. Threshold 3 is unshippable as-is.
- [x] Size cap before `os.ReadFile` (`heuristics.go:164`) — 4 GB file currently OOMs.
- [x] `main.go:249` re-reads and re-parses every file including already-matched and
      errored ones. Single-pass file access.

**Interface**
- [x] Exit codes (`--fail-on`). Currently always 0 — useless in CI.
- [x] JSON + SARIF output. Text banner cannot be consumed by anything.
- [x] Concurrency for `--dir`.
- [x] Resource defaults relative to the binary break on install to `/usr/bin`; and
      `--rules` defaults empty so YARA is off despite the README advertising it.

**Hygiene**
- [x] Tests (0 exist). CI. Makefile. `.gitignore`. Tags + releases.
- [x] README is stale: roadmap still marks Episode 3 planned (it's implemented), structure
      lists `rules/malware_generic.yar` (actual `rule_list.yar`) and omits
      `heuristics.go`, example output says v0.2.0, clone URL points at upstream.
- [x] Module path is still `ASTRA-LabsHQ` — `go get` on the fork yields upstream code.
- [x] Two rules can never fire: `highly_sus_shellcode` and `obfuscated_powershell` match
      the *text* `"0x89,0x00,0x00,0x00,0x60,0x89"`, i.e. comma-hex rendering, not bytes.

---

## Phase 1 — Evaluation harness (blocking for everything after) — DONE 2026-10-24

`cau eval validate|run|report|diff|gate|policy`, `internal/eval`, the committed
`corpus/smoke` plus `baselines/smoke.json` and `baselines/policy.json`, and
`make eval` in CI. Still open within this phase: a *real* corpus. The smoke
corpus proves the plumbing; recall numbers against it are not detection
quality numbers. Next: a manifest referencing MalwareBazaar samples by hash
(fetched at eval time into an isolated directory, never committed) and a
benign set built from Debian/Chocolatey package provenance.

- [x] Corpus format + loader (public malware with handling rules, benign set by build
      provenance so "clean" is actually verified, not assumed)
- [x] Deterministic metric runner: FP/FN/precision/recall per detector, per rule, per
      family; confusion matrix; regression gate vs. `main` baseline
- [x] Report diffing — "this PR adds 0.4% recall and 3x the false positives"
- [x] Performance budget gate (throughput, memory, no timeout regressions)

---

## Phase 2 — Episodes 4/5/6, done properly

All cheap. All measurable against Phase 1.

- [ ] imphash + import clustering (nearest-neighbour family grouping from flat hashes)
- [ ] TLSH + ssdeep fuzzy hashing (Episode 6) — survives the trivial single-byte flip
- [ ] Shannon entropy overall + per section + sliding window; packer/overlay detection
- [ ] Rich header, timestamp-vs-Rich anomaly, Authenticode chain + signer implausibility
- [ ] Section anomalies: rwx, name mismatch, size/entropy outliers, TLS callbacks
- [ ] Packer detection (UPX, Themida, VMProtect) via entrypoint + section signatures

---

## Phase 3 — MCP server (OSS)

Highest differentiation per line of code. No competitor ships an AV *engine* as MCP —
`revula`, `Reversecore_MCP`, `NexusCore_MCP` are RE/debugging toolchains.

```
cmd/astra-mcp/          # stdio primary, streamable-HTTP optional
internal/mcp/           # tools / resources / prompts registry
internal/mcp/sandbox.go # path allowlist, size caps, timeouts, TOCTOU guards
```

**Tools**: `scan_file`, `scan_dir`, `scan_hash`, `explain_verdict` (which rule, which
score, which offset), `yara_test_rule` (against corpus, returns FP/FN), `generate_yara_rule`,
`list_signatures`, `add_signature`, `mitre_coverage`, `evasion_report`.

**Resources**: `astra://rules/{name}`, `astra://signatures`, `astra://corpus/{sample}/report`,
`astra://model/{name}/card`.

**Prompts**: `triage_sample`, `rule_review` (FP risk of a proposed rule), `evasion_assessment`.

**Non-negotiables**
- Bounded, summarized results. Raw YARA offset dumps blow out agent context.
- Path confinement. This is a scanner pointed at `/` by an agent sooner or later.
- Sampling runs in a sandboxed worker (`read_only`, `cap_drop: ALL`, no network) — never
  the agent's own host filesystem.
- Structured JSON only.

---

## Phase 4 — Intelligence & detection content

- [ ] STIX/TAXII + MalwareBazaar sync; replaces the hand-typed `hashes.txt` — MISP is the
  canonical EU sync protocol (see intake table)
- [ ] Release-channel hash updates: `cau update` fetches the latest signed
  `signatures/hashes.txt` asset from GitHub Releases on a pinned repo
  (`s-b-repo/Astra-AV-Engine`), and the CI release job publishes that asset per tag.
  Verification is fail-closed: detached signature checked against the package-pinned key
  (Phase 7 #1) before install, DB version and min-engine-version parsed, atomically
  replaces the live DB with a rollback copy. Never phones home silently at startup —
  explicit command, or opt-in periodic in config. No network available keeps the current
  DB with a loud warning. Offline/air-gap deployments receive the identical payload
  through the Phase 7 #10 signed bundle instead of a fetch.
- [ ] YARA rule linter — catches the dead rules already shipped in `rule_list.yar`
- [ ] Content test-before-promote: every rule change runs against Phase 1 corpus with
      measured regression, blocks merge on FP regression
- [ ] ATT&CK mapping on rules + a coverage matrix that reports techniques with **no**
      rule. This is the honest counterfactual to what CrowdStrike sells.
- [ ] Bind EU alternatives to the matrix so mapping never hinges on a single US registry:
      Unified Kill Chain (Fox-IT / P. Pols, NL) mapped phase-wise alongside ATT&CK as the
      sequencing view, MISP galaxy-cluster IDs (CIRCL, Luxembourg) for actor/family
      tagging, Malpedia IDs (Fraunhofer FKIE, Germany) as the family-naming record, ENISA
      Threat Landscape taxonomy (EU) for the strategic dashboard layer, CERT-EU's ATT&CK
      community mappings as external review. Report findings carry a `frameworks` object
      (ATT&CK id, UKC phase, MISP cluster, Malpedia family) so consumers pick their scheme.

**LOTL intake (the lolol.farm meta-catalog)** — lolol.farm indexes ~30 community catalogs.
Ingest the upstream machine-readable sources on GitHub, never hand-typed; lolol.farm is
the discovery index and the weekly drift check that nothing we consume has gone quiet:

| Catalog | Feeds |
|---|---|
| LOLDrivers | known-malicious driver SHA256s + signing intel; first real corpus to replace synthetic `hashes.txt` filler |
| MalAPI / LOLAPI | cross-check and extend the hand-typed `suspiciousAPIs` table; ATT&CK mapping per API comes free |
| LOLBAS / GTFOBins / GTFOArgs / LOLGlobs / ArgFuscator | command patterns for string heuristics + obfuscation variants as eval corpora for the Phase 6 evasion suite |
| HijackLibs | DLL-sideload candidates for a PE rule pack, alongside the Phase 2 section work |
| lolcerts (WithSecure, FI) | abused code-signing certificates — feeds Phase 2 signer-implausibility; the ground truth behind the "Certs Are Useless" thesis |
| LOTS / LOLC2 / LOT Webhooks / LOT Tunnels / LOLFSaaS | exfil/C2 string + domain patterns for the network heuristics; attenuation handled by prevalence (Phase 7 #5) |
| WTFBins / LoFP | binaries that behave like malware but are innocent, plus generated FP rule sets — seeds the benign corpus for weak-category retuning |
| LOLRMM / FileSec / Bootloaders / Persistence-Info / LOLSkills | RMM-tool abuse lists, delivery-file extensions, UEFI loaders, persistence-mechanism cross-checks, and YARA over AI agent skill bundles (ties into Phase 3 MCP scanning) |

- [ ] Intake lives in `internal/intake/`: fetchers, parsers, fixture tests, weekly CI run.
      Every consumed record carries source, retrieved-at and confidence fields. Nothing
      from a feed auto-promotes into shipped detection content — every item still runs the
      Phase 1 gates before promotion. Feeds cut bookkeeping cost, never undermine FP gates.

---

## Phase 5 — ML ladder

Static engines lose to packing. Each tier earns its place only where the previous fails.

| Tier | Approach | Cost | Reality |
|---|---|---|---|
| 0 | imphash + TLSH | ~0 | Beats exact hashes on modified/packed samples |
| 1 | LightGBM on PE header/section/byte-histogram (EMBER-class) | ms | Reference static baseline; the pragmatic workhorse |
| 2 | CFG → GNN (GraphSAGE / GIN) | 100ms–s | Needs angr/CFGFast. MalAOI evades at 93.7% avg, 99.2% on GAT |
| 3 | LLM static analyst over FLOSS/decompiled output | s | Best ROI on obfuscated samples; also the rule-generation engine |
| 4 | Dynamic API-call graph → GNN/transformer | sandbox | The only tier that survives packing. GraphShield-class: 99.5% F1 @ <1% FPR |

- [ ] ONNX Runtime sidecar over gRPC from the Go core. Do not do inference in Go.
- [ ] Adversarial training mandatory — reduces evasion, does not remove it.
- [ ] **Temporal generalization as a hard CI gate.** Train on period A, score on period B,
      fail on AUC drop. TESSERACT / Arp et al.: temporal snooping is the field's most
      widespread evaluation flaw. Flat-feature models look best in-distribution and are
      among the worst across a time boundary — a conventional benchmark would reject
      message passing entirely. Making this a gate is a differentiator.
- [ ] Model registry with signed artifacts, SBOM, model cards, promote/rollback.

---

## Phase 6 — Episode 7: the evasion suite (OSS, flagship)

The credibility engine. Nobody ships this, and it is defensible purely on being honest.

- [ ] `astra evasion-report --file X` → minimum patch set that flips the verdict, per
      detector, with evasion distance.
- [ ] Adversarial harness implementing the published state of the art:
      XAI-guided function-call replacement via integrated gradients (94–100% success),
      MalAOI-style RL active-opcode insertion (93.7%), PhantomCall FCG dummy-function
      injection (85–100%, +95 pts over prior SOTA).
- [ ] Benchmark every detector against the suite. A detector that cannot be attacked has
      not been tested.

---

## Phase 7 — Getting past CrowdStrike (10 bets)

Do not out-build them — 10k engineers and a decade of Threat Graph telemetry are not
beaten symmetrically. Every bet below is asymmetric: it is something they structurally
cannot publish, price, or install. Each item lands on top of an asset Phase 1/6 already
builds (the eval harness, the evasion suite, the sensor fleet).

### Organized publication (what they will never publish)

**1. Signature provenance + per-rule model cards, in the public repo.**
Every threshold, indicator weight and YARA rule ships with: corpus hit/FP counts from
Phase 1, ATT&CK mapping, last-measured date, and a signed manifest (SLSA attestations on
the release). A competitor's detection layer is a black box by definition; being able to
fork, diff and audit detection content is the analyst-facing wedge.

**2. Continuous public multi-vendor benchmark.**
Automate the same public-corpus run against VirusTotal's multi-engine results on
identical samples (VT API, hash-referenced manifests — raw samples never committed):
place Astra next to Falcon in the same table, with evasion distance and method
disclosure, published weekly. The market has ATT&CK Evaluations (slow, vendor-approved,
closed method) and marketing decks; it has no open one. The *methodology* being published
is what makes it defensible.

**3. MITRE ATT&CK Evaluations enrollment.**
Register for the enterprise rounds instead of only maintaining an internal matrix
(Phase 4 keeps its scope). Participation is a procurement shortcut: vendors with no
evaluation record are excluded from shortlists regardless of quality, and this plan's
boldness only counts if it is externally checked.

**4. Published pricing + public TCO calculator.**
Per-sensor list price, volume tiers, and the agent matrix (sensors metered, analysis
agents unmetered — already decided in pricing mechanics) as a public page sourced from a
checked-in `pricing.toml`. Falcon's pricing is opaque per-host licensing and procurement
teams compare against list prices. Give them a downloadable TCO model with the honest
assumption rows.

### Sensor capability (what their scale can't discount)

**5. Fleet-derived prevalence scoring.**
Global file prevalence (SHA256, imphash-cluster, TCM) computed from sensor + scan-node
telemetry — but bootstrapped from SBOM/provenance imports (Debian, Chocolatey, npm,
Hackage) so a *new* engine has ground-truth benign prevalence before the fleet itself
populates it. Prevalence is the single strongest FP suppressor and the reason Falcon's
cloud decisioning feels precise. Deliverable: `internal/prevalence`, exposed as a metric
in every verdict ("seen on 0.0004% of hosts; signed by Debian").

**6. Behavior engine (IOBs) on the sensor.**
Static tiers lose to packing; the behavior layer does not. Sensor-side process-behavior
scoring over the existing event subscriptions (API sequences, ETW/AMSI anomalies,
file-less staging, RWX staging) emitted as ATT&CK-mapped behavioral indicators — the
Episodes 8+ work, formalized: rules live in `internal/behavior`, measured per technique
with the same FP/FN harness as the static content, gated in CI.

**7. eBPF Linux sensor.**
Linux dominates servers and CI, which is exactly where the OSS engine already deploys as
scan nodes. An eBPF-CO-RE collector (`cmd/astra-sensor-ebpf`) yields endpoint telemetry
without a kernel driver — the position CrowdStrike cannot copy into an MIT engine and
their Linux agent's weight makes the agent-footprint numbers a real sales point. Feeds
the behavior engine (#6) and the Threat Graph (#8).

### Console capability (their actual moat)

**8. Threat Graph: cross-host lineage and pivoting.**
The control-plane work that makes incidents *track*: file→process→child→network→
persistence nodes (signed hashes as keys) stored server-side, ATT&CK technique nodes,
pivot queries ("what else from this imphash cluster"), process-tree rendering as Falcon
RTR does. Without it, Console incidents are per-sensor event lists; with it, incident
response becomes navigation. Deliverable: `internal/controlplane/graph`, part of Console
Phase A/B.

**9. Standards-native event plane.**
Sensor/console events emitted natively as STIX 2.1 bundles and CAR-shaped objects, with
SIEM sinks (Splunk HEC, Sentinel, Elastic) and OTLP as first-class outputs. Their SaaS
wants the event stream *inside* NG-SIEM; offering the same data to whatever the SOC
already runs removes the main objection to adopting a new console.

**10. Air-gapped-first architecture.**
Fully offline detection updates (signed bundle + manifest, revocation chain), console as
a single on-prem binary, no cloud dependency in any detection path — CI runs an actual
network-isolated integration test. Falcon's disconnected mode is a constrained concession;
for regulated/government buyers, air-gap parity is a hard requirement, and it is a
requirement this architecture was born with.

### FOSS SIEM sink matrix (extends #9)

One event model in, N formats out: every console/sensor sink serializes the same
internal findings object; per-SIEM payload differences are profiles, not divergent
schemas. Drift between them is a CI failure.

- [ ] Wazuh — RFC 5424 syslog + CEF, decoder-compatible fielding
- [ ] Security Onion — ECS-JSON syslog + a STIX 2.1/TAXII feed
- [ ] OpenSearch Security Analytics — OTLP and ECS bulk over HTTP
- [ ] OSSIM — CEF/LEEF over syslog
- [ ] Matano — OCSF-JSON (Apache-2.0, the youngest of the five)
- License-honesty footnote: Graylog (SSPL) and Elastic Security (Elastic License 2.0)
  are widely deployed and supported as sinks, but are not OSI-FOSS — the marketing
  never calls them open source, and the matrix above is what the word means here.
- [ ] Conformance fixtures per standard ship with the schemas: one RFC 5424 frame, one
  CEF event, one GELF message, one ECS doc, one OCSF object, one OTLP batch — each
  round-trip-parsed in CI so a sink update cannot silently break ingestion.

---

### OpenEDR gap analysis — the open benchmark, and the traps not to repeat

OpenEDR (Comodo's open-source EDR) is the only complete open-source EDR codebase
worth benchmarking against. It earns credit for publishing the agent at all — and its
own public surfaces (README architecture, issue #56, issue #40) document gaps that
double as both the wedge list for this plan and the acceptance-criteria traps an
open EDR must not repeat, this one included. Facts stay class-level:

| Gap | Public evidence | Astra's owning row |
|---|---|---|
| Windows-only agent | single-agent docs, no Linux/macOS/CI sensor | Linux-first scope plus the platform rows — the surface no one covers |
| User-mode injection architecture | README: "Injected DLL … hooks API calls", plus a driver-borne "Loader for Injected DLL" into each new process | eBPF/LSM-first sensor with a no-injection pledge — injection primitives in a sensor are its own attack class |
| Public privilege-boundary disclosures | tracker #56: LPE, RCE, DoS/bugcheck, SYSTEM-exec, and telemetry-bypass classes | exploit-attempt ledger + anti-tamper + parser-fuzzing gates — those same classes are our fixture requirements |
| Injector-module risk | tracker #40: "Vulnerabilities in the DLL injector module" | the no-injection design closes this class by construction |
| Self-protection unresolved in public | community asks how an admin is prevented from stopping the service; no prominent public answer | no-silent-kill + self-heal + hardware-anchored identity |
| Raw base-event shipping to ES, local-file policy | telemetry via filebeat to locally/cloud-hosted Elasticsearch; policy from a local file with client-side patterns | one-event model, FOSS SIEM sink matrix, Phase 1 gates, `cau coverage` honesty artifacts |
| Fuzzy self-host boundary | deployments assemble ES/filebeat themselves and ask which parts need registration | the free persona is complete by design; no fake caps (licensing rows) |
| Content without contracts | "standard rules" shipped, no model cards/provenance manifests on detections | the standards program's detection-evidence contract |

- [ ] Same-report parity test: every public OpenEDR vulnerability class — LPE, RCE,
  bugcheck, SYSTEM-exec, telemetry-bypass — maps into the exploit-attempt ledger as a
  fixture requirement. If the same class exists in this sensor, the anti-tamper and
  fuzzing gates must catch it, and the coverage render states the pairing explicitly.
- [ ] No-injection build gate: the sensor ships zero injection primitives; CI greps
  the sensor source for injection-pattern APIs as a build gate — the pledge is
  enforced by the build, not by prose.
- [ ] Measured rivalry: when the third-party scoring gate lands, OpenEDR's policy and
  pattern artifacts run through the same Phase 1 fixtures alongside Astra's own —
  published numbers, not opinions.
- [ ] Fork-lineage audit: whatever the Phase 0 cleanup carried over from the original
  engine, every trap above gets an explicit acceptance-criteria checkbox in the fork's
  follow-up list — inherit the code, never the class of flaw.
- [ ] Respect note: OpenEDR published a working agent when almost nobody would. The
  benchmark's value cuts both ways, and the plan says so rather than dunking.

---

## Phase 8 — Firmware & boot-chain scanning (the shared blind spot)

Everything above scans what lives on the disk and stops at the OS boundary. Firmware
persistence survives disk wipes, ransomware and bootkits already treat the boot chain as
part of their estate (LoJax, MoonBounce, BlackLotus), and no major EDR publishes its
firmware-scanning layer. This is a wedge, not a parity bet — and honesty about boundaries
is part of the deliverable.

- [ ] `internal/uefi` — firmware-volume parser (UEFITool-style FFS/sections; as an
  in-tree Go port or a sidecar binary over the Phase 5 gRPC runtime). Every executable
  section feeds the same YARA ruleset; reports are bounded structured JSON under the
  Phase 3 context-budget rules.
- [ ] UEFI anomaly surfaces: option ROM inventory, WPBT/ACPI table scan (WPBT is a
  vendor-approved injection primitive), EFI boot-order/entry tampering (where BlackLotus
  lives), efivarfs read-only inventory, DBX/SBAT/MOK revocation state checked against
  current UEFI Forum revocation releases.
- [ ] `cau boot-scan` — OSS, strictly read-only: local ESP scan + firmware capsule/EFIVAR
  inventory, MBR/VBR/GPT sanity check (Petya-class bootkit coverage). Hard boundary: the
  engine never images or flashes live chips; SPI/eSPI work stays with opt-in operator
  tooling (chipsec-class), documented but not automated.
- [ ] Firmware-image bulk scanning at the scan node: router/NAS/IoT/vendor images with
  binwalk-style unpack (squashfs, jffs2, cramfs) recursed into the normal detectors —
  LOLDrivers, HijackLibs and bootloaders.io intake already supply the hashes and rules.
- [ ] Sensor surface (console side): efivarfs watch, kernel-taint and
  `module.sig_enforce` state as behavior-engine telemetry; persistence-info catalog as
  the cross-check list.
- [ ] Fixture corpus with the Phase 1 gates intact: public UEFI/BIOS implant fixtures and
  rule packs (LoJax/MoonBounce-class), measured for FP/FN like any other detection
  content. Firmware rules have a small-n truth set — say so in their model cards rather
  than inflating recall claims.

## Phase 9 — Blind-spot sweep (what this plan had been missing)

- [ ] Linux-native ELF detection — the top non-firmware gap. The engine today is a
  PE-only engine behind a Linux CLI: `debug/elf` heuristics (.init_array hooking, export
  table oddities, syscall-stub templates, SSH/cron tamper patterns), kernel-module
  signature state, autostart paths. GTFOBins/GTFOArgs intake is behavior content, not
  binary content — without this, the eBPF sensor (#Phase 7-7) is telemetry with no local
  verifier.
- [ ] Document & archive vectors: OLE (VBA, macro stomping, remote templates), PDF, LNK,
  CHM, ISO; nested-decompression budget with bomb caps. These are the top delivery paths
  and none are parsed today. OLE semantics go through the Phase 5 sidecar runtime if Go
  ports lag — the corpus harness decides, not convenience.
- [ ] Quarantine + canary primitives in the OSS engine: quarantine DB with
  integrity-checked restore, decoy/canary files as cheap ground truth for the behavior
  engine. The console ships full response by design; OSS analysts still need an honest
  quarantine, and today the engine has nowhere to put found files.
- [ ] Container/OCI registry scanning at the scan node: registry-native pull scanning +
  a Kubernetes admission hook. A large share of the market's code ships inside images;
  the engine currently sees that content only after unpack, if ever.
- [ ] Post-quantum signature chain (ML-DSA or hybrid) for air-gapped update bundles +
  reproducible builds and SBOMs for released artifacts. Extends Phase 7 items 1 and 10
  before cryptography forces the migration, not after.
- [ ] Parser fuzzing gate: OSS-Fuzz/libFuzzer harnesses for every shipped parser (PE,
  ELF, UEFI, OLE, archives). A scanner that dies on a malformed sample is a
  time-of-scanning liability; fuzz failures block releases with the same honesty as the
  Phase 1 gates.
- [ ] macOS decision, explicitly: Mach-O scanner plus the LOOBins content already
  ingested. Scope is set at the end of Phase 2 — OSS engine only, or console sensor
  surface. The one thing not accepted is drifting half-committed for two releases.

---

## Phase 10 — Novel-technique detections (ahead of ATT&CK)

A detection-first catalog of techniques observed in the ArcticFox research corpus that
have no MITRE mapping *(fittingly, no detection analytic either)* — the standard EDR
blind-spot problem, but enumerated from exploits rather than folklore. The repo publishes
detections and synthetic fixtures, never the source implementation: readers get what to
catch and how to catch it, not how to build it. This Phase 4-connected work maps into
`frameworks` and its ATT&CK submission drafts continue there.

| ID | Technique | Detection focus | MITRE |
|---|---|---|---|
| NOVEL-001 | Zero-width Unicode steg in text/code artifacts (README dead-drop C2) | presence-based: any zero-width codepoint in distributable text/code, excepted only by package provenance | T1027.018 (partial) |
| NOVEL-002 | AEAD-encrypt-then-ZW-encode C2 pipeline | covered by the same detector — catch the codepoint class, not the chain | none |
| NOVEL-003 | Port-shared bind shell (SO_REUSEPORT) coexisting with a real listener | per-port binder reconciliation: kernel socket-group membership vs the port's expected service owner | none |
| NOVEL-004 | Watchdog respawn with rotating process names | correlate by executable hash and endpoints, not argv; respawn-chain graph alert | T1036 (partial) |
| NOVEL-005 | In-host anti-competitor malware sweep | kill-events matching known-malware name pools — dual IOA: implant present, or an exclusive-tenancy war | none |
| NOVEL-006 | ZW-encoded heartbeat relayed through open-redirect URLs | egress checks for zero-width/non-printable bytes in URL query params | T1001.003 (partial) |
| NOVEL-007 | `LD_AUDIT`-based library-load interception | `ld.so.preload` / `LD_AUDIT` inventory reconciled with package provenance; auditor SOs must be instrumentation | none |
| NOVEL-008 | fanotify listener event suppression | fanotify listener registration + ignored-mask grants vs package provenance | none |
| NOVEL-009 | systemd generator unit injection | generator inventory vs provenance; diff transient units under `/run/systemd/generator` | none (T1543 family gap) |
| NOVEL-010 | eBPF filtering of the audit subsystem | in-kernel BPF program attach inventory on audit/lsm hooks; anything not fleet-pinned alerts | none |
| NOVEL-011 | CRIU checkpoint/restore process resurrection | checkpoint-image monitor + restore-invocation tracing + exec-less lineage anomaly alert | none |
| NOVEL-012 | Multi-method obfuscation chaining in binaries (encoding→packing→encryption stacks, depth as a signal) | chain-depth estimator + bounded peeling pipeline + peel-exhausted honest states; runtime unpack taps as the sensor-side complement | T1027 family (partial) |
| NOVEL-013 | Script-level multi-encoding chains (eval loops, macro-stomp + remote-template + encoded-payload stacks) | script-AST transformation capture through the chain — the normalized final-call surface, not the raw text | T1027 + T1059 family (partial) |

- [ ] Engine-side `internal/stego`: zero-width codepoint detector for text and code
  artifacts, with a YARA module backing it — presence-based, because density thresholds
  are the first thing this class trivially drops below. Console adds the egress URL check.
- [ ] Sensor-side rules in `internal/behavior` for the host techniques: binder
  reconciliation, respawn-chain graphs, kill-pool matching, fanotify/generator/BPF
  inventories, CRIU restore tracing. Provenance (Debian/etc., per Phase 7 #5) is the
  benign anchor for all five inventory checks.
- [ ] Phase 6 ties: each technique becomes a fixed regression case in the evasion-report
  suite, executed against the corpus.
- [ ] Fixtures are generated synthetic samples (corpus policy: nothing sensitive is
  committed); every detector ships with FP/FN numbers through the Phase 1 gates.
- [ ] `frameworks` gains a `novel: NOVEL-xxx` field beside the ATT&CK/UKC/MISP IDs, and
  each technique family is drafted as an ATT&CK submission with detection strategies —
  the honest path for detection-first research to be upstreamed.
- [ ] `internal/peeler`: bounded unpeeling pipeline walking the candidate *tree* via
  parallel unwrap (the DoS design below). Over-cap yields a `peel-exhausted` outcome
  routed to emulation fallback — an honest result rendered first-class — never
  silent-clean.
- [ ] Chain-depth estimator as a cheap pre-pass: entropy-segment profiling plus
  structural fingerprints (overlay chains, packed-import tables, section anomalies)
  route samples to specialized peelers (archive / packer / script) before full peel cost
  is paid. Depth itself is a signal: layer counts above a threshold raise the score
  regardless of the payload verdict, so a chain that outlives the gate still flags.
  Provenance reconciles benign packers — nested packers inside official packages don't
  alert, the same FP rule as everything else.
- [ ] Chain-signature model: each peel records the ordered transformation set it
  removed; ordered chain patterns become family signatures — the multi-layer equivalent
  of a hash — and enter the same detection-content lifecycle with model cards.
- [ ] Emulation-sidecar fallback (Phase 5 runtime): peel-stalled samples run
  unpack-then-scan in the isolated sidecar — snapshot memory, scan the unpacked image,
  same budget caps as static peel.
- [ ] Sensor complement in `internal/behavior`: runtime unpack behavior taps — large
  writable→RX transitions, write-then-execute patterns, self-decryption loops. A chain
  that defeats static peeling meets telemetry that doesn't care how many layers were
  applied.
- [ ] Eval-time synthetic chains: the Phase 1 generator *composes* its own
  obfuscation-path library into randomized chains for blue/red fixtures. Depth-swept
  FP/FN must stay flat as depth grows, and multi-layer fixtures land in CI as
  regression cases.
- [ ] Peel-as-tree, not peel-as-chain: each layer's candidate continuations spawn as
  bounded speculative tasks on a work-stealing pool. The budget wall — cpu-ms, allocated
  bytes, syscall counts, wall-clock — is *global per sample*, shared across every
  branch: an attacker adds depth, not spend, and where the budget goes is the engine's
  choice, not the sample content's.
- [ ] Estimator-guided task graph: the chain-depth estimator ranks the frontier;
  low-probability branches queue last and are cancelled mid-run when the budget counter
  passes its floor. A cancel carries its reason — "peel-exhausted (budget), branch-cancel
  at layer N" is a labeled outcome, not a generic failure.
- [ ] Wall-clock bounded by construction: speculative parallel unwrap caps
  time-to-verdict regardless of chain design — a stall-shaped chain burns its own
  budget, not the scan queue. Queue-level DoS dies at this row.
- [ ] CPU honesty, stated plainly: parallelism reduces latency, not cost — aggregate
  CPU per sample can rise. The DoS boundary is the budget wall plus fairness; the plan
  does not pretend the tree buys a free lunch.
- [ ] Per-source fairness: tenant-level token buckets on the scan queue — a flood from
  one tenant can never consume the fleet's peel capacity. Ties to the multi-tenancy
  pricing row.
- [ ] Content-addressed dedupe: peel artifacts land in a CAS keyed by blob hash — a
  repeated identical chain costs O(1) after its first peel, and the duplicates-flood
  vector amortizes to nothing.
- [ ] Bounded task-graph invariants: max in-flight children per node, no unbounded
  queues, workers die on budget exhaustion, cancellation is cooperative. These are
  asserted by Phase 1 conformance tests, not just documented.
- [ ] DoS honesty: Phase 9's decompression-bomb caps extend across the tree path —
  "peel-exhausted, N layers observed" is still the rendering for anything that hits a
  wall, and CI depth-sweep fixtures assert the wall-clock cap holds across chain shapes
  while benchstat tracks the aggregate-CPU delta so the same-budget guarantee is
  measured, never assumed.
- [ ] ATT&CK framing: T1027 family (partial) with the chain-pattern classification
  itself drafted as an ATT&CK submission alongside the other NOVEL families.
- [ ] Publication rule: detectors, synthetic fixtures and templates are public; the
  offensive framing (bypass notes, source implementation, live payloads) does not enter
  this repo. If a technique description cannot be written without becoming a recipe, it
  ships as a short alert-name reference only.

---

## Phase 11 — Linux ATT&CK coverage matrix (detection requirements)

The ArcticFox corpus also carries a full ATT&CK Enterprise/Linux mapping. What transfers
into this plan is the technique ID list — expressed as the engine's Linux coverage
requirements, written from detection definitions rather than from the source material's
implementation and evasion columns, which remain internal under the Phase 10 rule. The
source's duplicate T1546.016 rows are deduplicated; T1055/T1620 share one analytic;
T1091 (unimplemented in the corpus) is dropped.

| ID | Technique | Detection analytic | Owner |
|---|---|---|---|
| T1090.004 | Domain Fronting | egress SNI-vs-Host mismatch; CDN-tenant review | console |
| T1102.002 | Web Service: Bidirectional | long-lived HTTPS sockets held by non-package processes; egress-domain inventory | sensor |
| T1001.003 | Protocol Impersonation | NOVEL-006 URL-stego egress check | console |
| T1573.002 | Encrypted Channel: Asymmetric | caught at origin via stego/fileless/server-side analytics, not payload inspection | sensor |
| T1008 | Fallback Channels | multi-endpoint rotation from one executable hash; silent-failover pattern | sensor |
| T1095 | Non-App-Layer Protocol | ICMP echo cadence/payload-entropy analytics; UDP/53 binder reconciliation (NOVEL-003) | sensor |
| T1571 | Non-Standard Port | port-owner inventory + NOVEL-003 | sensor |
| T1059.004 | Unix Shell | shell child-chains from non-shell parents (behavior engine) | sensor |
| T1203 | Exploitation for Client Execution | fault-then-lineage correlation: crash followed by payload process | sensor |
| T1106 | Native API | fileless-execution telemetry: exec from anonymous/memfd inodes | sensor |
| T1053.003 | Cron | crontab diffs vs package provenance | sensor |
| T1547.001 | XDG autostart | autostart entry inventory vs provenance | sensor |
| T1543.002 | Systemd service/timer | unit inventory + transient-unit diffing (NOVEL-009) | sensor |
| T1546.004 | Runtime-load hooks | `ld.so.preload` + `LD_AUDIT` watch (NOVEL-007) | sensor |
| T1546.008 | PAM | pam.d file provenance; unexpected module load events | sensor |
| T1037.004 | init.d | sysv-init inventory vs provenance | sensor |
| T1546.016 | Installer-script hooks | package-manager hook config provenance diffs | sensor |
| T1027 + .013 | Obfuscation | NOVEL-001/002 stego detector | engine |
| T1036.005 | Match Legitimate Name | NOVEL-004 hash/endpoint correlation | sensor |
| T1055 / T1620 | Injection / Reflective Load | deleted-exe and memfd-exec lineage anomalies; memory-symbol checks | sensor |
| T1070.004 | File Deletion | running-but-deleted inode alert | sensor |
| T1070.006 | Timestomp | filesystem metadata consistency audits on runtime state | sensor |
| T1140 | Decode | covered by stego + fileless analytics | engine/sensor |
| T1202 / T1218 | Indirect / Proxy Execution | LOLBin caller anomaly: execution flags from unexpected parents | sensor |
| T1222.002 | Linux Permissions | immutable-bit set events on non-package paths | sensor |
| T1562.001 | Impair Defenses | NOVEL-005 kill-pool + agent self-aliveness from an independent monitor | sensor/console |
| T1564.001 | Hidden artifacts | hidden-executable paths in autostart/persistence dirs flagged by the engine | engine |
| T1574.006 | LD_PRELOAD | same analytic as T1546.004 | sensor |
| T1046 | Network Service Discovery | connect-sweep telemetry bursts | sensor |
| T1082 / 1016 / 1033 / 1083 | Discovery via shell | behavior-engine command patterns — reported as partial by design | sensor |
| T1110.001 / .003 | Brute force | auth-log cadence analytics | console |
| T1552.001 / T1003.008 | Credential files | privileged reads on credential stores outside package context | sensor |
| T1021.004 / T1210 | SSH phase / remote exploit | fleet-wide key-reuse pivot query (Threat Graph); exploit-fault lineage | console/sensor |
| T1005 / T1119 | Collection | bulk-read/write telemetry | sensor |
| T1041 | Exfil over C2 | covered by the C2 channel analytics above | sensor |
| T1048.003 | Exfil via URL params | NOVEL-006 egress check | console |
| T1485 / T1489 / T1498 | Impact | mass permission/ownership-change alerts; kill-pool; egress flood shaping with attribution | sensor |

- [ ] `cau coverage --format sarif`: per-technique state rendered as detected / partial /
  planned / none. Same honesty rule as the Phase 4 matrix: techniques with no rule are
  reported, never padded.
- [ ] Provenance is the benign anchor for every inventory row, resolved against the
  Phase 7 #5 provenance DB — alert quality does not depend on per-customer tuning.
- [ ] Fixtures: synthetic blue/red pairs generated at eval time and measured through the
  Phase 1 gates. No source-derived content enters the repo.
- [ ] Coverage honesty: Discovery-via-shell rows ship labeled *partial by design* —
  command-pattern analytics are fallible, and the report says so rather than implying a
  guarantee.
- [ ] The source document (implementation details, per-technique evasion notes, the
  product-by-product bypass summary) remains internal only. This repo ships detections,
  fixtures and coverage states.
- [ ] Analytic-design rule, distilled from the same hardening lessons but kept at
  principle level: no detection may anchor on attacker-controlled surface — process or
  argv names, freely chosen file paths, timing patterns, protocol field values. Detections
  anchor instead on provenance, lineage and presence-floor attributes the adversary
  cannot shed without losing the capability they came for. (NOVEL-004's hash-based
  correlation is the worked example of this rule.)
- [ ] CI measures every detection against the internal bypass corpus on each merge. The
  corpus exists in that context only as test fixtures; its per-technique engineering
  details are never enumerated here. A bypass regression fails the release the same way
  an eval regression does.

---

## Sensor self-protection — anti-tamper (extends the Phase 11 T1562.001 row)

The sensor assumes it is a target: malware deploys kill-pools (T1562.001) explicitly
against EDR. Countermeasures are integrity and redundancy — never camouflage:

- **Binary identity:** self-hash at startup, verified against a signed release manifest
  (Phase 7 #1 attestations). Mismatch means fail-closed: halt detection, log, alert —
  never run half-verified.
- **Config integrity:** configs are root-owned, provenance-checked and signed; unsigned
  overrides alert instead of applying. No obfuscation of the config itself — clarity of
  the security state is a feature, and stego-encoded config would trip this program's
  own stego detector (NOVEL-001/002).
- **Process integrity:** the sensor inspects its own `/proc/self/exe`, open-FD inventory
  and periodic self-checks, but identity is anchored by an *independent* supervisor — a
  second dedicated process, or an eBPF-based watchdog keying on the agent's cgroup rather
  than its name. A kill-pool that filters on process names therefore has nothing
  decisive to filter on; the alarms they cannot see keep firing.
- **No masquerading:** the sensor runs under its own product name from a package-owned
  binary. Masquerading as common services (T1036.005 / NOVEL-004 patterns) would collide
  with the provenance inventory rows (T1053.003, T1543.002, T1547.001) and trip
  NOVEL-004's rotation analytic — the agent helps no one by looking like both sides of
  its own detection logic.
- **Console side:** remote attestation per sensor, signed one-way heartbeats, and
  quarantine-on-tamper policy — a tampered sensor drops to containment rather than
  silence.

---

## Kernel-level support & anti-tamper (Linux-first; Windows stays console-side)

Phase 7 #7 chose eBPF over a kernel driver deliberately. "Kernel level" here completes
that story — plus the honest assumption underneath all of it: a compromised kernel cannot
be inspected from inside itself, so every anti-tamper design leans on anchors *outside*
it (TPM, provenance, a second process, the VM layer, or the crash itself).

**Sensor kernel components (Linux):**
- [ ] BPF-LSM first: the sensor registers as an LSM (signed, package-managed) for real
  blocking decisions — exec, mount, socket connect, ptrace, module load — beyond passive
  telemetry. This is the kernel-native enforcement point without the out-of-tree-driver
  brittleness.
- [ ] Minimal signed out-of-tree module only where BPF-LSM cannot serve, DKMS-packaged
  with a kernel-version matrix in CI; never loads unsigned. Windows kernel components
  land in the closed console sensor per the licensing-leak rule — the OSS engine ships
  nothing it cannot verify.
- [ ] "vkernel" mode for VM fleets, opt-in: KVM/QEMU guest introspection driven from the
  host via QMP — console queries process/memory/network state of a guest from a layer the
  guest's rootkit cannot see or unhook. Off by default; guest-free on the guest itself.

**Anti kernel / firmware tampering:**
- [ ] Boot-anchored measurement: verified measured-boot state (TPM PCRs) plus IMA
  appraisal before the sensor starts; an unexpected PCR state puts the sensor into
  containment mode (self-protection section above) instead of scanning from a client the
  kernel could lie to.
- [ ] Kernel hook inventory at rest and on change: kprobe/ftrace/livepatch/eBPF program
  tables and LSM registrations diffed against a signed baseline — NOVEL-010's analytic
  generalized to every attach point; anything not fleet-pinned alerts.
- [ ] Kernel state drift checks: module list, taints and signature state against the
  provenance DB; kernel symbol-table diff (kallsyms with KASLR-aware rebasing) against
  the package-owned baseline. Firmware side remains Phase 8's surface — runtime
  efivarfs/DBX/option-ROM diffs are re-checked on every boot, making its layers one
  contiguous tamper story from boot chain to runtime.
- [ ] Crash-capture containment: on tamper suspicion the host forces a kdump snapshot
  before anything can react — a capture a running rootkit cannot scrub ex post — and the
  image goes to console-side memory forensics (Volatility3-class parsing feeding the
  Phase 5 ML ladder offline). Live findings are tripwires; the dump is the verdict.
- [ ] In-kernel heuristics (rkhunter-class) exist only as tripwires routed through the
  higher-privilege verifier. Nothing inside a compromised kernel is trusted to declare
  itself clean.

**Kernel-gap sweep (added audits):**
- [ ] Hardening posture as a report class: kernel sysctl/integrity state —
  `kptr_restrict`, `dmesg_restrict`, `yama.ptrace_scope`, `unprivileged_bpf_disabled`,
  `perf_event_paranoid`, `modules_disabled`, `module.sig_enforce`, `kexec_load_disabled`,
  `bpf_jit_harden`, lockdown mode — rendered per host with drift alerts on change events
  (sysctl write watch). Posture is reported honestly; blocking still belongs to
  BPF-LSM, not to scolding the operator's config.
- [ ] Kernel-memory access channels: audit opens of `/dev/mem`, `/dev/kmem` and
  `/proc/kcore`; unexpected access alerts and escalates straight to crash capture
  (these are the classic direct paths to kernel tampering).
- [ ] Cross-view process reconciliation: `/proc/loadavg`'s scheduler thread counter vs.
  the enumerated task list. A mismatch is a hidden-process tripwire that escalates to
  the kdump verifier — neither view is trusted alone, and the dump is the tiebreak.
- [ ] Hidden-module reconciliation in the dump: module-object walk inside the crash
  image vs. `/sys/module` enumeration — memory truth over runtime truth, closing the
  hidden-LKM seam that the runtime drift check cannot see.
- [ ] `io_uring` coverage fixture: CI asserts BPF-LSM file-operation hooks observe
  ops issued through `io_uring` (a known audit/monitoring seam). If the seam exists,
  it closes at the LSM layer — never by pretending the API is not used.
- [ ] BPF surface inventory: bpffs mounts, pinned maps and programs, JIT hardening
  state — extends NOVEL-010's attach-point coverage to the filesystem side of BPF.

---

## Sensor self-verification — hardware-anchored identity

Self-protection proves the sensor survives tampering. This adds the second proof: that
what is running *is what the console thinks it is*, anchored in hardware roots rather
than in host-controlled state. Extends the kernel section's measured-boot work and the
Phase 7 #1 attestation pipeline from boot-time to the runtime lifecycle.

| Anchor | Verification | Attack class defeated |
|---|---|---|
| TPM quote lifecycle | sensor runtime state is quoted at every check-in; console verifies against the EK certificate and the PCR chain, stale/replayed quotes are rejected by freshness window | agent spoofing, stolen-identity replay |
| DMI/SMBIOS identity | UUID, board serial, product and chassis serial recorded at first enrollment; console flags duplicate serials across the fleet | cloned-host identity theft — two sensors claiming one physical machine |
| NIC permanent MAC | interface-configured MAC vs the NIC's EEPROM/burned-in address (`ethtool -P` / netlink), divergence is L2 self-misdescription | MAC spoofing and L2 anonymization attempts — the packet guard's egress-spoof row gains a hardware witness |
| Hardware monotonic counters | monotonic receipts chained into every event stream; console rejects out-of-order sequences under an EK-certified identity | event-stream replay with stolen keys |
| Entropy-source health | hardware RNG failures degrade the sensor to software entropy as a labeled alert-posted state, never a silent fallback | quiet weak-entropy degradation of the sensor's own crypto |

- [ ] `internal/hwanchor`: quote capture, DMI snapshot, permanent-MAC divergence check;
  attestation receipts land in the console's fleet/identity surfaces, feeding the
  identity-continuity row's machine-id collision work.
- [ ] Honest degradation as a first-class state: no TPM, no EEPROM permanent address,
  and hardware crypto offload planes render *unverifiable* — labeled degraded in every
  report and coverage rendering, never silently padded to "verified". The free-reporting
  honesty rule runs on hardware data too.
- [ ] Fleet pivots: duplicate serials and MAC divergences join the Threat Graph — "two
  hosts claim the same hardware identity" is an automatic incident class.
- [ ] Privacy: DMI/SMBIOS serials are hardware metadata retained under the same
  host-scope posture as device-plane inventory — class and identity only, no content
  leaves the host.

---

## Exploit-attempt ledger — kernel, hardware, network planes

The plan's existing rows detect behavior and persistence. This adds the third tier: the
*attempt itself* — exploitation events caught as events, before (or without) any
compromise landing — formalized across planes into one ledger instead of scattered
signals. Some taps exist already (kcore alerts, taint drift, kallsyms diffs, kprobe
hook inventory); the ledger is what makes them the same thing.

| Plane | Attempt events the ledger receives |
|---|---|
| Kernel | oops/BUG event clusters, taint-state changes, `/proc/kcore` + `/proc/kallsyms` access from unexpected lineages, kprobe/ftrace registration by non-package lineage (extends the anti-tamper section's per-check inventories into the attempt surface) |
| Privilege | ptrace / `process_vm_readv/writev` against privileged targets, setuid-exec chains from unexpected parents, capset events — the privesc ladder, observed rung by rung |
| Hardware | flash/MTD/ESP firmware-write events from non-updater lineage (the companion to the Phase 8 scanner: attempts caught as events, implants caught as images), PCIe enumeration diffs, IOMMU/DMA-fault events formalized out of the device-plane rows |
| Network | protocol-anomaly probe storms at service ports (T1595.002), malformed-flag sweeps (packet-addendum tie), and the probe→fault→lineage chain that upgrades a probe to a confirmed attempt; the netguard MITM rows supply the L2 half |
| Memory | memfd/deleted-inode exec (T1106) and the runtime unpack taps (NOVEL-012) join as compromise-evidence classes |

- [ ] `internal/exploitledger`: one attempt-ledger keyed by lineage and evidence class,
  unifying the taps above; every entry carries a *status* — attempt observed vs
  compromise confirmed — resolved from chain state, never merged.
- [ ] Attempt→compromise upgrade is the ledger's whole point: fault-then-lineage,
  unpack taps and crash capture can promote an entry, and the promotion event itself
  lands as a timeline pivot ("attempt → confirmed" is one graph hop).
- [ ] Coverage honesty: attempts and compromises count separately in every coverage
  rendering, forever — an attempt is never padded into a compromise and vice versa.
- [ ] Hardware-plane boundary, stated: implants below PCI-enumeration visibility do not
  run on this host — Phase 8's scanner is the sole truth source; the ledger carries
  interception *attempts* and documents the floor, not iommu-backed completeness.
- [ ] Ring-0 boundary, stated: a fully compromised kernel defeats runtime checks by
  definition — the ledger carries attempt evidence; prevention claims live in the
  anti-tamper section and nowhere else.
- [ ] Fleet pivot: "three hosts observed the same probe/flash/DMA shape within an hour"
  is an automatic fleet-incident class, the netguard corroboration pattern applied to
  the attempt plane.
- [ ] Perf honesty: attempt-class taps vary wildly in volume — kcore reads are rare,
  probe storms are not — so per-class throughput budgets and drop-policy under load
  apply, benched in CI.
- [ ] Fixtures: synthetic oopses, flash-write events and protocol probes generated at
  eval time, blue/red pairs only — attempt-class FP/FN numbers through the Phase 1
  gates.

---

## Defense-in-depth hardening — the product is also a target

Every layer of this architecture is itself attackable surface. The stance from the scope
note applies upward: assume the components are discoverable, and make discovery
pointless by making attacks fail — never by hiding.

**Engine (CLI/library)**
- [ ] Read-only by construction: scanning never executes or writes sample content; the
  MCP path is the only sandboxed exception (Phase 3).
- [ ] Renderer injection closed: file paths, threat names and rule metas are data to
  every report renderer (text/JSON/SARIF) — structured and escaped, never concatenated
  into templates; a fixture with hostile filenames runs in CI.
- [ ] Resource exhaustion pinned: per-run budgets (jobs, memory, time, decompression
  caps) verified against the adversarial fixture corpus from the Phase 9 fuzzing work.

**Sensor (host)**
- [ ] Privilege separation: a minimal privileged collector (eBPF/LSM) and an
  unprivileged analysis process joined by a credentials-checked unix socket
  (SO_PEERCRED) — a compromised analysis side cannot touch kernel telemetry or load
  rules into the collector.
- [ ] SELinux/AppArmor policy modules ship in the package; no listening network ports on
  the host (console-relay model with mTLS and per-identity keys).
- [ ] Runtime artifacts hard-permissioned (root-owned, 0640) — nothing world-readable
  that doubles as recon material for T1562 kill-pool attacks, which are themselves a
  detection row (Phase 11).

**Console (server)**
- [ ] Rootless containers, distroless runtime images (no shell inside), `cap_drop: ALL`,
  secrets only in the platform keychain/KMS, TLS everywhere.
- [ ] Auth hardening as a checked posture: no default credentials (first admin is a
  one-time bootstrap token), lockout policy on auth failures (the console's own T1110
  row), CSP/CSRF/cookie flags and endpoint rate limits verified in CI, step-up approval
  for irreversible actions (pairs with the exclusions governance).
- [ ] Audit log is append-only at the storage layer, so a compromised console process
  cannot rewrite history.

**Distribution (signed update channel)**
- [ ] Anti-rollback protection: a persisted, monotonic minimum-version floor — a validly
  signed *old* bundle must be refused. The classic gap in otherwise-correct signed
  update schemes, now closed in `cau update` and the air-gap bundles alike.
- [ ] Reproducible builds + SBOM + SLSA attestations (Phase 7 #1, Phase 9) close the
  supply chain end-to-end; the Phase 4 release channel inherits all three.

**MCP / analysis agents**
- [ ] Path allowlists, size caps and timeouts (Phase 3 non-negotiables), plus evidence
  minimization: raw sample content stays in the sandbox — agents receive verdicts and
  bounded excerpts, never verbatim payloads (the injection-defense surface owned by
  Phase 7 console governance).

**On "stop them from looking for this":** enumeration of the agent is assumed. What it
buys an attacker is bounded by construction — kill-pools matching agent names trip the
NOVEL-005 row, name-independent supervisors keep firing (self-protection section),
tamper fails closed, and a kill attempt escalates to crash capture. Camouflage and
anti-detection styling of our own components remain refused under the scope note:
discovery resistance here means attack failure, not invisibility.

---

---

## Garlic-routed telemetry — agents forward what relays can't read

Transport architecture, borrowed from I2P's garlic routing: telemetry travels in
multi-hop bundles ("cloves") where every forwarding hop peels only its own routing
layer and forwards what it cannot read. Only the sink's key opens the contents — and
there are two sinks, each with its own key.

| Path element | What it does |
|---|---|
| Clove bundling | the agent batches event cloves into shipments; padding to size classes and timing jitter/mix budgets shrink traffic correlation |
| Per-sink end-to-end encryption | the dashboard and the customer's Wazuh sink each receive an independently E2E-encrypted copy — Astra never holds the Wazuh sink's key, so Astra cannot read the customer's SIEM events |
| Hop-layer separation | relays (Astra-operated, customer-owned fleet relays, or community relays) learn only that traffic passed and who their neighbors are; host identity rides the E2E layer only, never the hop layer |
| Fleet relay mode | self-hosted relay mesh stays inside the customer network — the air-gapped deployment gets garlic routing with zero Astra transit |
| Direct fallback | relay-mesh outage falls back to direct QUIC with a `transport: direct-fallback` label rendered in coverage — delivery never silently changes character |

- [ ] `internal/garlic`: clove bundler (batching, size-class padding, jitter/mix
  budgeting), hop-layer crypto, and per-sink receipts; no relay anywhere holds a
  content key.
- [ ] Cryptography: hybrid X25519+ML-KEM-768 key agreement on QUIC/TLS 1.3, ML-DSA
  signatures for relay receipts — extending the Phase 9 post-quantum chain from
  update bundles to the telemetry path. Terminology honesty: the plan says
  *post-quantum cryptography* against quantum adversaries' future compute, never
  "quantum encryption/QKD" — QKD needs specialized hardware shipments and is not what
  ships; no overclaim enters any surface.
- [ ] QUIC mechanics: per-class streams (priority events and bulk telemetry share one
  connection cleanly), 0-RTT resume for ephemeral/CI sensors that reconnect constantly,
  connection migration for mobile or DHCP-shuffled fleets.
- [ ] Latency honesty: garlic routing buys metadata privacy with latency — so critical-
  class events may default to a short path (one hop or direct) as an explicit per-class
  fleet-profile choice, and the default is stated, never silent. Bulk telemetry takes
  the full path.
- [ ] The traffic-analysis claim is enumerated precisely: relays gain content
  confidentiality and neighborhood-only metadata — strictly better than the industry-
  default direct upload, and *not* a claim of perfect anonymity set. Where correlation
  remains possible, the doc says so.
- [ ] Replay protection: monotonic-counter receipts from the hardware-anchor row chain
  into sink ingestion — a replayed batch cannot re-enter either sink.
- [ ] Relay fairness: token buckets per source-relay mirror the peeler fairness rules
  — a flooded relay can't starve the fleet's transport, and DoS budgets benched in CI.
- [ ] Self-hosted console note: customers who want *no* Astra-readable copies at all
  point both sinks at self-hosted infrastructure; the dashboard path exists for those
  who don't. Both paths are rendered in pricing and the licensing rows, not hidden.
- [ ] `cau selftest` gains a transport row: mesh-hop aliveness, hop-crypto handshake
  state, and fallback state surface in fleet health.

---

---

## Transport ladder for server fleets — when direct and mesh fail

The garlic section's direct fallback assumes egress exists. Server fleets often do
not: strict-firewall egress, QUIC-blocking middleboxes, mandatory proxies, and
occasional total loss of outbound. The ladder below is the order the sensor tries,
per fleet profile, with every rung transition rendered as its own timeline event.

| Rung | Path | When it applies |
|---|---|---|
| 0 | Fleet egress diversity: a neighbor server with an alternate route carries the stuck host's alert-class events over the local link | direct fails, a fleet sibling has egress |
| 1 | Direct QUIC on 443 | normal operation |
| 2 | TCP-443 with HTTP/2 framing | middleboxes block UDP/QUIC |
| 3 | Customer proxy — `HTTPS_PROXY`/CONNECT, PAC-aware; MASQUE-style HTTP/3-in-TCP tunneling | strict firewalled egress |
| 3.5 | Echo-lane — QUIC-like alert transport over ICMP echo, post-quantum E2E | UDP, TCP and proxies all filtered; ICMP survives |
| 4 | Emergency band — BMC/Redfish or a pre-provisioned bastion pull, alert-class events only | all host egress fails |
| 5 | Local spool with retention caps, host rendered `transport: unreachable` | everything fails |

- [ ] Spool is encrypted at rest under the vault row and replay-safe: monotonic
  receipts from the hardware-anchor row dedupe redelivery on reconnect, so a full
  spool drains once, not twice.
- [ ] When the spool fills, the event-loss policy decides what sheds — by labeled
  class, never silently, and the rendering says which classes dropped and why.
- [ ] Emergency band is opt-in and BMC-honest: it depends on controller presence and
  admin consent, carries alert-class only, and is documented as a quarantine-grade
  band rather than telemetry — the BMC stays what the cross-system sweep says it is.
- [ ] Fleet egress diversity is opt-in and L2-local: the carrying host forwards under
  the garlic receipt scheme, and carries under the same token-bucket fairness so a
  carried host cannot flood its carrier.
- [ ] Air-gapped servers use rung 5 + the media shuttle: spool ships by signed,
  manifest-verified removable media — the update channel's post-quantum chain covers
  the telemetry shuttle both directions.
- [ ] The ladder is per-fleet-profile configuration with stated defaults; every rung
  transition lands on the timeline (`transport: rung-3-proxy` etc.), and `cau
  selftest` renders current rung, spool depth, and last-success rung in fleet health.
- [ ] A host is never dark: `transport: unreachable` is a *state* in the console, not
  an absence — consistent with the no-silent-kill rule.

---

---

## Echo-lane — post-quantum ICMP transport for alert-class events

 QUIC's semantics rebuilt over ICMP echo request/reply: connection identity in the
echo identifier, offsets in the sequence space, payload bytes in the echo data — the
last usable wire in networks where UDP, TCP and proxy egress are all filtered but
ICMP echo passes. Named honestly: this is PQC over a hostile path, not "quantum
encryption" per the standing terminology rule.

- [ ] `internal/echolane`: connection-id → echo identifier, stream offsets → sequence
  space, payload chunking across consecutive echo frames at path MTU (~1472 bytes per
  echo at 1500). Reliability via reply-acked windows with idempotent, nonce-keyed
  retries. Stream multiplexing rides the garlic clove model so the lane and the mesh
  share one framing.
- [ ] Crypto parity: the same per-sink hybrid X25519+ML-KEM-768 end-to-end agreement
  and ML-DSA receipts as every other lane — no downgrade because the path is hostile,
  and monotonic-counter receipts keep replayed frames out of the sinks.
- [ ] Class honesty: alert-class only, never bulk telemetry. ICMP is kernel rate-limited
  (`icmp_ratelimit`), middlebox-deprioritized, and MTU-capped — the lane paces under
  the default limits and does not pretend to be a full transport. Bulk stays on the
  spool; the ladder's rung 5 remains the honest fallback.
- [ ] Detector self-consistency: the plan's own T1095 ICMP analytics flag unpinned
  echo payload-cadence *by design* — the echo lane is provenance-pinned (fleet-pinned
  sink identifiers, sensor-signed receipts on both directions) and emits a
  `fleet-owned echo lane` event class, so our own detector and our own lane coexist
  honestly. `cau selftest` asserts the pinning instead of assuming it.
- [ ] Spoofing honesty: ICMP is trivially spoofable — nothing in-band is trusted
  before ML-DSA receipt verification, and "on-path or ring-0 attackers can inject
  noise" is stated in the lane's own documentation. The channel's answer is
  authentication and receipts, not the IP layer's goodwill.
- [ ] Injection-tolerance: frame-level nonce idempotence means duplicate or
  attacker-injected frames are detected and dropped at receipt verification; budget
  for the DoS class is the same fairness model as the relay and peel paths.
- [ ] Timeline ties: `transport: rung-3.5-echo-lane` transitions are timeline events
  like every other rung, and the layer renders in fleet health.

---

## Packet-layer guard — L2/L3 spoofing from the host's eye

Phase 11 covers host behavior; this covers the bearer layer. Host-based honesty up front:
a single host cannot fully verify a switching fabric, so the guard owns the narrow,
truthful slice it *can* see — kernel-asserted events and packet taps — labeled by
evidence class, alert-only by default, with inline drop only as an opt-in per-host
profile.

| Signal | Detection analytic | Mapping |
|---|---|---|
| ARP conflict / IP→MAC churn | netlink duplicate-address events (kernel-asserted) + gratuitous-ARP rate + ARP table churn entropy | T1557.002 |
| Rogue DHCP | multiple OFFER sources within a lease window vs. lease history | T1557.003 |
| DHCP starvation | NAK/DECLINE storms and lease-exhaustion cadence around the host | — |
| LLMNR / NBT-NS / mDNS poisoning | the host answers only names it owns; an answer from *another* host for one of ours is the tripwire | T1557.001 |
| IPv6 RA spoofing / router churn | conflicting RAs, multiple router claims, DAD conflicts | T1557 family (no dedicated ATT&CK sub-technique — noted honestly) |
| Martian / spoofed-local ingress | rp_filter drop counters + TTL-floor check (a packet claiming a same-subnet source with a remote-hop TTL is lying) | anti-spoof, ingress |
| Egress spoof check | outbound frames sourced from an IP not configured on the interface, or prefix/MAC mismatch — a compromised stack, a relay, or an injected frame | anti-spoof, egress |
| ICMP redirect ingress | kernel event tap — a classic MITM primitive that should not exist on a configured host | MITM primitive |
| BPDU / LLDP / CDP surprises | a host never speaks STP; unexpected LLDP/CDP from a non-switch MAC means rogue infrastructure on the wire | — |
| VLAN double-tag (QinQ) arrival | extra 802.1Q tags on an access-port frame — VLAN-hopping recon | — |
| Resolver answer anomalies | NXDOMAIN-then-success oscillation and TTL-zero corporate names — cache-poisoning fingerprints seen from the local resolver | MITM (DNS) |

- [ ] `internal/netguard`: eBPF tc/XDP taps plus netlink/proc event taps, feeding the one
  internal event model (all sink formats behave per the Phase 7 #9 matrix), with the
  "kernel-asserted vs inferred" evidence labeling required by the free-reporting rules.
- [ ] Both directions: every analytic runs ingress (spoofed arrival) and egress
  (compromised stack or injected frame going out).
- [ ] Fleet corroboration through the Threat Graph (#Phase 7 #8): one host observing a
  MAC claiming the gateway is suspicion; three hosts observing the same MAC within an
  hour is a fleet incident — cross-host IP→MAC churn history upgrades single-host alerts
  automatically.
- [ ] ATT&CK rows land in the Phase 11 `frameworks` object and the coverage matrix; the
  two honest gap-marked rows (RA spoofing, DHCP starvation) stay gap-marked until their
  ATT&CK submission lands upstream — coverage is never padded.

---

## Packet-guard addendum — the IP-plane gaps

The guard's table covered L2 spoof-arrival and the host's own anti-spoof tripwires.
This extends the plane with the IP/transport checks a host can legitimately run, plus
the kernel counters it already exposes — same taps, same event model, no second sensor.

| Signal | Detection analytic | Mapping |
|---|---|---|
| IP fragmentation plane | oversized/short fragments, overlapping fragments, mid-flow DF-bit flips, fragment-flood cadence vs baseline | — (gap-marked, submission candidate) |
| TCP-flag plane | malformed-flag sweeps, RST-injection probing of long-lived sessions, cross-checked against conntrack/session state | — (gap-marked) |
| Neighbor-table churn | `ip neigh` state oscillation and probe storms — L2 enumeration fingerprints reflected in the host's own table | T1046 family (partial) |
| Raw-socket ownership | AF_PACKET socket inventory vs provenance — who runs packet captures on this host besides the sensor itself | — (counter-surveillance) |
| Interface creation | tun/tap/gre/sit/wireguard interface creation by non-package lineage — tunnel construction is a channel primitive before it is a traffic pattern | T1572 |
| Routing-plane tamper | route-table and rpdb rule diffs, XFRM/IPsec/WireGuard state changes vs provenance — a host whose routing is re-described goes quietly blind | — (gap-marked, submission candidate) |
| Conntrack exhaustion | ct-table pressure cadence — conntrack starvation is a drop-everything interference class against the host's own visibility | T1498 family (partial) |
| MACsec / crypto offload | macsec interface inventory; the guard sees only post-decryption frames — the boundary is documented, not pretended away | — (honest boundary) |

- [ ] `internal/netguard` extension: these rows ride the same tc/XDP and netlink tap
  set; kernel drop counters flow through the same "kernel-asserted vs inferred"
  evidence labeling.
- [ ] The gap-marked rows stay gap-marked until ATT&CK submissions land upstream —
  coverage is never padded, per the guard's own rule.
- [ ] Fragment-plane honesty: if fragment reassembly is attempted at the tap, it is a
  *new parser* and goes through the Phase 9 fuzzing gate like every other parser —
  reassembly bugs are a scanner liability, not a free win.
- [ ] Interface-creation telemetry ties to the cloud/egress sweep: a wireguard
  interface appearing on a node that runs no VPN workload correlates with the
  destination-endpoint inventory first, alerts second.

---

## Cross-system gap sweep — planes the plan still missed

Kernel, firmware, packet and host-state are covered; these are the remaining systems
where an attacker operates underneath normal EDR visibility. Same rules as everywhere:
provenance is the benign anchor, evidence class is labeled, and every row lands in the
coverage matrix via the Phase 11 `frameworks` object.

| Plane | Gap in the current plan | Deliverable |
|---|---|---|
| Identity (sudo/SSSD/FreeIPA/SSH keys) | PAM/cron/systemd inventories exist; identity *config* drift is unmonitored | `internal/identity`: sudoers.d churn, new group-sudo members, sssd/IdP config diffs, authorized_keys and ssh_config (ProxyCommand) drift per host — extends the fleet key-reuse row (T1021.004) with per-host state |
| Trust store | MITM enabler nobody watches: root-CA additions/removals, per-app NSS trust churn, world-readable key material | drift watch on system + NSS trust stores; pairs with Phase 2 signer-implausibility work and the netguard MITM rows (T1557) |
| Log continuity | T1070.002 clears logs; journald has no native tamper-evidence | shipper writes a hash-chained continuity header per rotation; "gap" and "rewind" alerts at console; volume-vacuum events alert |
| Time continuity | clock manipulation defeats cross-host correlation silently | clock-step and chrony/NTP tamper events as sensor telemetry; console-side cross-host monotonicity check — a host whose timeline steps backwards against fleet consensus is flagged, correlation queues freeze rather than mis-order |
| Devices (USB/HID) | removable media and input capture invisible today | new-device inventory (vendor/product first-seen), HID grabber detection (EVIOCGRAB and `/dev/input` readers outside an interactive session — T1056.001), and an engine hook to auto-scan mounted removable media |
| Container escape seams | scan-time coverage exists (Phase 9); runtime escape indicators do not | socket-permission audits (docker/containerd sockets), privileged-container telemetry, cgroup `release_agent` writes and `nsenter` host-pivot alerts (T1611 family) at the sensor |
| BMC / out-of-band (Redfish) | Phase 8 covers host firmware; BMCs are the unowned floor beneath it | console-side Redfish periodic audit: BMC firmware inventory, default-credential fingerprint, BMC-LAN segmentation state — gap-marked in ATT&CK until a mapping exists upstream |
| CI runner profile | build hosts self-scan today by hand | a sensor *mode* for ephemeral CI hosts: short-lived identity, secrets-usage telemetry, artifact hash gates on outputs — the LOTP intake supplies the abuse catalog |
| Memory residue (swap/hibernate) | memory remnants unexamined between boots | engine offline pass: `cau scan --swap <partition|image>` with the same one-read discipline; console IR mode schedules it with crash captures |
| Fleet identity continuity | sensor identity is long-lived IP; theft or collision is unhandled | identity key rotation with revocation windows, machine-id collision alerts at console, and revocation propagation checked in the same CI that tests update channels |

- [ ] Every row: kernel-asserted signal preferred, inferred labeled as inferred; the
  two ATT&CK-unmapped rows (BMC, memory residue) ship gap-marked like the packet guard's
  already do.
- [ ] Nothing here adds telemetry collection of content — devices, keys, configs and
  logs are inventoried as state, not read as payloads, keeping the privacy stance of the
  reporting rules intact.

---

## Device & USB plane — the full sweep

The gap-sweep row covered the entrée (first-seen inventory, HID grabber detection,
mount-time scan). This extends the device plane to its full extent, class by class, with
the same evidence-labeling and provenance rules. Most of what malware does over USB is behavior the host stack *can*
observe — this plane's job is to observe it on purpose.

| Surface | Attack class | Detection / control |
|---|---|---|
| HID keyboards | keystroke-injection hardware (automation cadence, not human typing) | inter-key timing uniformity metrics, typing during dead-silent sessions, HID descriptor anomalies (composite device with a vendor-specific class riding along) |
| HID without hardware | software-injected input via `uinput` | `uinput` module load and `/dev/uinput` node creation events, reconciled against package provenance |
| HID over Bluetooth | mousejacking / keystroke injection over unencrypted HID profiles | duplicate-event accounting (two sources feeding one device), BT HID posture — research-tier until validated |
| RNDIS / CDC-NCM NICs | plug-in rogue NIC → DHCP/RA MITM from the host's own L2 | USB-attached NIC first-seen + instant OFFER/RA activity from it (feeds the netguard rows) |
| Wi-Fi/BT radios on USB | attack-cable class (rogue radio built into a cable), hostile AP | first-seen radio inventory; concurrent AP-mode behavior on an unknown dongle alerts |
| Storage — autorun lineage | `.desktop` Exec keys, `.lnk` re-targeting, `autorun.inf` heritage | media scan runs *before* user opens anything; exec lines in mounted filesystems flag |
| Storage — hidden regions | HPA/DCO and vendor partitions beyond the declared logical size | geometry audit (interface-reported sectors vs partition table) plus a read-beyond-logical-end probe in IR mode |
| Storage — hidden data | payload in unallocated space / filesystem slack / bad blocks | `--device` full-disk offline pass (sibling of the `--swap` pass), scanning unallocated ranges deliberately |
| Storage — composite impersonation | emulated CD-ROM + MSD composites posing as installer media | composite-class storage flags unless provenance-pinned to a fleet-trusted vendor |
| Copy-out (DLP-lite) | bulk exfiltration to removable | write-volume telemetry, policy alerts; mount-class deny available through the BPF-LSM mount hook the kernel section already registers |
| Power Delivery / Type-C | BadPower-class contract abuse from chargers | `typec` / `power_supply` sysfs event taps: contract changes and unexpected PDOs logged per charger identity |
| USB stack abuse | `usbip` remote device injection, raw `/dev/bus/usb` readers | `usbip` disabled in posture with alerts on bind attempts; raw usbfs readers provenance-reconciled |
| Bus posture (DMA) | Thunderbolt/USB4 PCIe tunneling DMA, weak IOMMU | posture audit: IOMMU state, Thunderbolt security level, hotplug policy; IOMMU fault events tapped as DMA-attempt evidence — honest gap: no clean ATT&CK node exists, marked for submission |
| Class policy | anything-not-allow-listed reaches drivers | peripheral allow-list profiles: HID+storage+charging classes only by default; others sit `authorized=0` at udev with events logged |

- [ ] `internal/usbguard`: eBPF/udev/netlink taps, per-host first-seen inventory, the same
  "kernel-asserted vs inferred" labels as the packet guard.
- [ ] Device-first-seen nodes join the Threat Graph — "which process opened the new USB
  device" is a one-hop pivot, and a device followed by anomalous process behavior
  correlates automatically.
- [ ] Kernel postures land in the hardening-posture report class: default-deny device
  authorization, `usbip` off, IOMMU/TB security checks.
- [ ] Accepted limit, stated plainly: inline hardware keyloggers and bus-level analog
  interception are invisible to the host stack — they are asset-management problems, not
  detection problems, and the plan documents the boundary rather than pretending
  otherwise.

---

## Session-plane sweep — clipboard, capture and agent taps

The Phase 11 matrix covers persistence, execution and the network deeply but leaves the
*session* thin — the surface a human is actually touching. That is where credential-grade
secrets move and where most contemporary stealers operate, precisely because it is quiet
and personal.

| Surface | Attack class | Detection / control |
|---|---|---|
| Clipboard | capture-style stealers and wallet-address swap writes (T1115) | selection-event tap + write-diff: address-like text copied, a *different* address-like text pasted; clipboard-manager daemons reconciled against provenance |
| Screen | grab-and-stage: capture tooling from non-package parents, XRecord/XShm clients, scheduled screenshot jobs with no user action (T1113) | display-access process-set diffing — which processes hold a screen-grab interface in a session nobody is visibly using |
| Remote access | desktop-sharing software first-seen, and unused-but-listening installs (T1219) | x11vnc/wayvnc/rustdesk-class daemon inventory + outgoing-socket correlate at listen start; deny-by-default policy row for locked-down profiles |
| Audio | capture-stream holds: source-output registrations, raw capture-node opens (T1123) | audio-graph taps per consumer, first-seen per device node |
| Video | capture holds plus virtual-camera impersonation via `v4l2loopback` (T1125) | `/dev/video` open table vs package lineage; module-load alert for `v4l2loopback` itself |
| History | mid-session history tampering: `HISTFILE`/`HISTSIZE=0` runtime sets, history-file truncation diffs (T1070.003) | shell-event telemetry — evidence-labeled, because plenty of humans do this too; the label carries the load |
| Session-bus persistence | D-Bus activation-service drop-ins, polkit rules granting silent auth, activation Exec landing in user-writable paths (gap-marked — no clean ATT&CK node, submission candidate) | `/usr/share/dbus-1/services` + polkit rules diffs vs provenance |
| Agent sockets | SSH/gpg-agent socket rebinding and agent impersonation — key material harvested at use time (gap-marked; the nearest ATT&CK family isn't close) | `SSH_AUTH_SOCK` runtime-set telemetry, `$XDG_RUNTIME_DIR` socket diffing, extra agent instances spawned |
| Sleep hooks | suspend/resume persistence — `/etc/systemd/system-sleep` scripts; the resume window is a quiet, given edge (gap-marked) | sleep-hook dir inventory vs provenance, resume-time execution telemetry |
| udev rules | runtime-added `.rules` persistence — the device plane's own persistence gap, mirrored here (gap-marked) | rules-file diffs vs package provenance; non-package rules flag |

- [ ] `internal/sessiontap`: one sensor module registers the clipboard, capture, audio and
  video taps — plug-in so single-module registration keeps the agent-footprint sales
  point (Phase 7 #7) intact instead of creeping into per-device daemons.
- [ ] Honest anchoring: clipboard managers, screen-sharers, volume daemons and
  window-listeners are legitimately alive — analytics anchor on provenance and
  behavior bandwidth, never on "the tool is suspect" alone.
- [ ] Session-plane events join the Threat Graph: agent-socket replacement,
  address-swap clipboard writes and capture-before-exfil are one-hop pivots with
  compounding edge metadata.
- [ ] Capture-indicator honesty: host analytics see kernel-open holds; they cannot see
  or assert hardware states — the covered-camera question is posture advice, not
  detection, and the report says so.

---

## Cloud-adjacent planes — egress and transfer sweep

Cloud fleets silently face several planes the cross-system sweep hinted at but never
enumerated. Most rows already use classes Astra taps — the additions are destinations,
lineages and config diffs, not new telemetry volumes.

| Surface | Attack class | Detection / control |
|---|---|---|
| Cloud metadata | instance-metadata credential theft from workloads (T1552.005) | link-local metadata endpoints (169.254.169.254, fd00:ec2::254, 100.100.100.200, metadata.google.internal) alert unless the allowlisted agent process is the caller |
| Kubernetes node | ServiceAccount-token reads outside kubelet/containerd lineage, static-pod drop-ins, container-API credential stores (T1552.007) | token-file open table per lineage; manifest-dir diffs |
| Anonymization | anonymizer-LOTL C2 (T1090.003) | tor daemon first-seen + control-port listener; i2p router start; policy-gated inventory |
| Exfil-vacuum | first-seen cloud-transfer tooling (rclone/restic/borg) and scheduled-job retargeting (T1567.002) | transfer-tool inventory + destination-endpoint first-seen per host; schedule-edit events re-run the destination check |
| Egress config | DNS-plane tamper: resolv.conf/dnsmasq/systemd-resolved diffs, per-process DoH/DoT adoption, `http_proxy` config injection (extends the packet-layer guard) | config diffs vs provenance + "this process never spoke DoH before" analytics — a host whose DNS plane moved quietly can't see its own C2 |
| Git plane | repo-shipped hooks exec'ed on first interaction with a clone, smudge/clean filter exec, `core.fsmonitor` process exec (gap-marked — ATT&CK has no clean node; submission candidate) | git-config provenance diffs + repo-dir hook first-run telemetry; filters pointing at user-writable exec paths flag |
| Network file plane | exec from NFS/CIFS mounts, iscsi initiator retargeting (gap-marked) | mount-flag posture audit (noexec where policy says), per-exec mount-origin attribution, initiator config diffs |
| Language ecosystems | hook persistence beyond distro packaging — npm postinstall, pip `.pth` + `sitecustomize`, `setup.py`, cargo `build.rs`, `NODE_OPTIONS` (T1546.016 extension) | the same provenance-diff mechanics as the package-hook row, keyed per ecosystem |

- [ ] `internal/cloudplane`: the metadata tap and token-file table ship default-on for
  cloud fleets; token lineage reconciles against kubelet/containerd judgments first.
- [ ] Destination-endpoint inventory persists per-host exactly like device- and
  NIC-first-seen.
- [ ] Canary extension — honeycred: planted token-shaped strings in predictably-read
  credential stores, which only an attacker ever reaches; the zero-FP class of the
  canary-file primitive extends from files to credentials.

---

## Install-plane scanning — .sh at the moment it is read

Installer execution is the highest-value script plane on a host: dpkg/rpm scriptlets,
language-ecosystem hooks, and piped installs all run shell the moment software lands.
The engine's job is to make that the moment it watches hardest — knowable lineage
*before* exec, content analysis before any write lands.

| Surface | What the scanner does |
|---|---|
| exec-perm hold | `FAN_OPEN_EXEC_PERM` holds the open of every script spawned under a package-manager lineage (dpkg/apt/rpm/pacman/npm/pip/cargo children) until the engine renders a verdict — the script is scanned *before* exec completes |
| payload-ownership reconciliation | the engine resolves which package payload a script belongs to (dpkg database / rpmdb / local metadata, fully offline); scripts executed by installer children that no payload owns flag as install-time tampering |
| script-content analysis | the shell analyzer checks writes into persistence dirs (systemd, autostart, cron, udev, sleep hooks), authorized_keys appends, LD_PRELOAD exports, curl→exec patterns, encoded blobs, sudoers edits — findings carry the same evidence labels and FP lifecycle as everything else |
| pipe-delivered installs | `curl | bash` never opens a scannable file — the behavioral rule is lineage-level (network→pipe→shell), and the row says so honestly instead of pretending content capture happened |
| ecosystem hooks | dpkg postinst/preinst, RPM scriptlets, npm postinstall, pip `setup.py`, cargo `build.rs` feed the T1546.016 row: script-run events per ecosystem reconcile against the provenance store, never a static allowlist |

- [ ] `internal/shscanner`: parses shell scripts as data, not text blobs — an AST bound
  by the Phase 9 parse budgets, with the YARA module matching AST tokens rather than
  raw-text regex, so an obfuscated script that evades pattern-matching doesn't evade
  the structure view.
- [ ] Verdict semantics are explicit, never silent: hold-and-decide is the default on
  installer lineages; fleet profiles select hold-installer / hold-all / audit-only. The
  verdict deadline is configurable — fail-closed by default on installer lineages,
  fail-open-with-alert as an *explicit* fleet choice. A stalled installer never guesses.
- [ ] Offline-first: ownership resolution and content analysis run fully air-gapped — no
  cloud verdict dependency on the install path.
- [ ] FP rule mirrors the house rule: package-shipped scripts pass via payload
  ownership; user-local and piped scripts go through content analysis, not name
  allowlists. Pre-exec decisions are allow/flag/quarantine per fleet profile, each one
  labeled in the timeline.
- [ ] Honest edge, stated: scripts executed from `/proc/self/fd` or heredocs bypass
  file-open entirely — the covered detection there is lineage-level (installer child +
  exec-from-anon-fd is the alert surface), and coverage renders carry the gap-mark
  rather than implying content was seen.
- [ ] Timeline tie: "package X ran script S wrote file F" is one Threat-Graph pivot —
  the install plane feeds the same chain-evidence model, and CI benches the
  install-storm case (mass package bursts across many hosts) against the sensor budget
  and the event-loss policy, so scanning never becomes the queue's DoS.

---

## Installed-plane monitoring — packages, dependencies, quiet planes

Install-time scanning covers the moment software lands; this covers the rest of its
life. Two tables: the package/dependency plane, and the planes that routinely go
unmonitored because no agent product grew up around them.

**The package and dependency plane**

| Signal | Detection |
|---|---|
| Package lifecycle | install/remove/downgrade events reconciled against the provenance DB — downgrades alert by default, extending the anti-rollback row from release channel to the host's own package set |
| Installed-binary mutation | installed files hash-diffed against package manifests; mutation outside a package transaction is a tamper alert — the package DB still claims the older content |
| Dependency substitution | a binary's runtime library set diverging from its manifest's declared dependency set — the loader resolving libs from outside the owning package (dependency-hijack class; adjacent to the T1574 family, listed honestly as partial) |
| Vendored ecosystems | vendored trees (node_modules, cargo vendor, go vendoring) hashed against their lockfiles on the host — lockfile edits without the lock-owner process running flag |
| Uninstall scripts | prerm/postrm events scan symmetrically to postinst under the install-plane holds — the removal path is historically less watched |
| Package-DB integrity | dpkg status / rpmdb reads and writes outside a package transaction — the package *database itself* tampering to hide `(not-obviously-)owned` state |

**The quiet planes — nobody's floor**

| Surface | Why it matters | Detection |
|---|---|---|
| SUID/SGID drift | setuid/setgid bits on non-package paths — the classic privesc primitive is invisible in default agent telemetry | bit set/clear events + full inventory diff vs package manifests |
| Network hooks | NetworkManager dispatcher.d, ifup/ifdown.d, netplan drop-ins, wicked — network-state persistence | drop-in inventory vs package provenance |
| Print plane | CUPS filters and PPDs run as root on every print event — the printer as an execution plane | filter/PPD first-seen + payload-ownership reconciliation |
| Pager plane | LESSOPEN/LESSPIPE, man-db filters, groff — code that runs every time someone pages a file | pager-filter config diffs; env-change telemetry on the parent lineage |
| Portal grant plane | xdg-desktop-portal permission-store mutations — sandbox-piercing grants written without any visible transaction | permission-store diffs first-seen per app-id |
| Fontconfig drops | font parsers are a classic exploitation surface and font dirs are unmonitored everywhere | font/config drops outside fontconfig-owned dirs first-seen |
| /dev/shm | exec-class artifacts in shared memory — the dropper segment that never lands on disk | shm exec-class file events, reconciled against package lineage |
| hosts-file writes | the oldest name-redirection primitive, effectively unmonitored | `/etc/hosts` mutation outside package ownership |
| Alternatives & triggers | update-alternatives resolution and dpkg trigger registration — the quietly authoritative command-resolution layer | alternatives symlink-state diffs; trigger registration events |

- [ ] `internal/pkgmon`: package-database watch, manifest-diff engine, drift baselines
  backed by the Phase 7 #5 provenance DB; package transactions define the *legal
  namespace* — anything outside a transaction that touches installed state flags.
- [ ] Quiet-plane taps ride the existing sensor modules (fs, session, net taps) — no
  new daemons; every row lands in `cau selftest` and the fleet-health surfaces.
- [ ] Same FP lifecycle everywhere: CUPS, font and pager paths are owned by distro
  packages, so drift-by-payload-ownership keeps FPs near zero without name allowlists.
- [ ] Adoption honesty: "nobody monitors this" is a differentiation claim — these rows
  re-check against the inversion table's CI gate like everything else; a row whose
  claim decays renders as *partial* instead of holding.
- [ ] Performance honesty: quiet-plane taps are high-frequency surfaces (pager and
  print events alone can be busy on desktop fleets) — throughput budgets and the
  event-loss policy apply identically, benched in CI, and the drop-policy states *what
  sheds under a print storm*.

---

---

## Supply-chain defense — the top five package managers, and the harder-to-kill rule

Language ecosystems (npm, PyPI, cargo, go vendoring) already ride the T1546.016 and
vendored-tree rows. The five OS-level managers below get their own threat-specific
surfaces — their escape hatches differ, so the detection rows differ.

| Manager | Supply-chain threat shape it faces | Detection / control |
|---|---|---|
| APT / .deb | malicious-mirror metapackages, postinst persistence, unauthenticated-downgrade tricks | scriptlets through the install-plane hold; sources.list.d drop-in diffs per host; apt-keyring writes outside a package transaction alert (pairs with the trust-store row) |
| DNF / RPM | dnf plugin persistence, %post scriptlets, COPR/repo key churn, rpm key-import tricks | dnf plugin-dir diffs; rpm-keyring watch; scriptlets through the install-plane hold; `rpm --rebuilddb` and rebuild anomalies as package-DB tamper events |
| pacman / AUR | AUR PKGBUILDs execute arbitrary build code as root on every build; alpm hook drop-ins run pre/post transaction | makepkg/AUR-helper spawn is installer lineage — the hold-scan applies; alpm hook-dir diffs; `/etc/pacman.d` repo drop diffs |
| snap | lifecycle hooks (prepare/configure/remove), classic-snap command-chains, interface grants changing at install | snap hook inventory per snap-id vs store manifest; interface-grant audit events; snapd socket writes from unauthorized lineage |
| flatpak | override drop-ins relaxing sandbox permissions at `/var/lib/flatpak/overrides`, fake-Flathub app installs, portal grants | a permission-*relaxing* override write is an alert on its own; portal-grant events tie the grant row; export/commands dirs first-seen |

- [ ] Per-ecosystem provenance keys: the Phase 7 #5 provenance DB gains a keyring and
  source-list anchor class per manager, so repo/key changes can only come from package
  transactions — everything else is a first-class alert.
- [ ] The kill-attempt ledger gets its supply-chain row: any non-package-agent attempt
  to stop, disable, mask, or uninstall the sensor (systemd unit masks, package-manager
  removal of sensor packages, profile drop-ins disabling gates, binary deletion) is a
  first-class event — evidence is captured before the action lands.
- [ ] Harder-to-kill rule, honest form: the design goal is *harder to kill quietly*,
  not impossible to kill. Ring-0 attackers end userspace defenses by definition; what
  the plan claims is that every kill attempt leaves evidence that survives the kill —
  crash capture, kernel anti-tamper, and the independent aliveness monitor.
- [ ] No silent kill: selftest/aliveness failure renders the host *degraded* on the
  console, never dark. A dead sensor is a visible dead sensor.
- [ ] Self-heal with a floor: fleet policy may auto-reinstall the sensor package from
  the signed channel on unexpected removal; a second removal inside the window
  escalates the host. The claim is delay-and-evidence, not invincibility.
- [ ] Gate-resilience clause: the install-plane holds, payload-ownership checks and
  package-DB integrity watch all bind into the anti-tamper core — disabling any
  detection module counts as a kill attempt and rides the same ledger. Supply-chain
  defenses that can be quietly turned off are not defenses.
- [ ] Package-manager locks: sensor packages mark themselves protected with the host's
  own manager mechanisms; removal attempts coerce a console alert plus a fleet-policy
  response (host containment is an opt-in console action, never autonomous by default).

---

## Platform support policy — EOL operating systems retained

Commercial EDRs drop EOL distro support aggressively because it damps their support
cost. Large real fleets cannot upgrade on that clock. The product stays useful where the
hosts actually are — with honesty about what EOL means, and without laundering it
(addressed below in policy governance):

- [ ] Support tiers: *Frontline* (two newest LTS branches per major distro, full
  feature matrix), *Legacy/EOL* (at minimum two years beyond distro EOL: detection and
  sensor keep working, supported, packageable), *Retired* (documented per release in
  SUPPORT.md, never silently dropped between releases).
- [ ] Engine portability is the mechanism: static/musl builds with libyara bundled, so
  no distro glibc floor blocks an EOL host; deb/rpm packages for EOL distro versions
  ship with every release alongside the hash channel.
- [ ] Sensor kernel matrix explicitly includes EOL LTS kernels (4.19, 5.4, 5.10-class);
  BPF-CO-RE keeps one binary across them; DKMS covers the tails. Feature degradation per
  kernel is published in the matrix — never silent.
- [ ] EOL visibility, not EOL euphemism: reports flag hosts running an EOL OS with the
  distro's support state — in plain wording, per the free-reporting rules — but
  detection continues unaffected. The product never implies an EOL host is secure, and
  never offers to hide that flag (see policy governance).

---

# Astra Console — paid tier

**License: per protected host.** One console, four agent types.

## Agent types

**1. Sensor agents** — `astra-sensor`, resident. Everything stateful lives here: real-time
and scheduled scanning, filesystem/process event subscription, memory scanning, quarantine,
restore, process kill. *This is where Episodes 8+ (fileless, AMSI/ETW tampering, memory)
land, because it cannot live in a stateless OSS scanner.* Metered entity.

**2. Scan nodes** — `astra-scanner`, stateless container workers. Bulk scanning of repos,
CI pipelines, artifact stores, blob storage. Central queue, work-stealing, result cache
keyed by SHA256.

**3. AI/MCP analysis agents** — third-party or customer-built LLM agents consuming the OSS
MCP server. Console governs: registration, per-agent tool allowlists, rate limits, budget
caps, output sanitization (prompt-injection defense on agent results), quality scoring
against gold labels, revocation.

**4. Autonomous detection agents** — Astra-run. Continuously hunt: mine new samples, cluster
by imphash/TLSH, propose YARA and capa rules, propose quarantine. **Human-in-the-loop
approval gate.** A proposal is promoted only if it beats the incumbent on a held-out corpus
with measured FP/FN. The verification gate is the contribution, not the generation.

## Console surfaces

- **Fleet** — inventory across all four types, health, version pinning, staged/canary rollout
- **Policy** — hierarchical org → group → agent; policy-as-code; signed; audit-logged
- **Detection content** — signature + rule lifecycle, lint, test-before-promote with
  measured regression, one-click revert, ATT&CK coverage matrix
- **Incidents** — cross-agent-type correlation, ATT&CK-mapped timeline, triage, response actions
- **Agent governance** — permission scoping, budgets, immutable audit trail, injection-defense
  status, quality score
- **Model registry** — signed artifacts, model cards, temporal-generalization metrics, gate
- **Evasion telemetry** — fleet-wide evasion-distance trending; "which rule families are
  degrading under adversary pressure" is a dashboard no one else can draw
- **Reporting** — SARIF/JSON export, compliance, ATT&CK coverage

## Policy governance — no "risk accepted" mode

The console will not ship a permanent "risk accepted" state that silences detections.
That control is the most abused one in commercial EDR: exclusions become paths, paths
become implants, and the exclusion list outlives every review that approved it.

- [ ] Exclusions are objects with a lifetime: scope-bound (host, path, hash, process),
  named owner, reason, provenance-signed, time-boxed with a hard default cap, renewable
  only via re-executed approval. No silent allow-lists exist in any surface.
- [ ] Detections never skip during an exclusion window: findings still compute and are
  stored, reported as `excluded-by <id>` — suppressed, not erased. The audit trail keeps
  both the detection and the decision.
- [ ] Coverage honesty carries into governance: the fleet-wide exclusion report renders
  beside the ATT&CK matrix, because a detection engine whose output can be switched off
  by policy has not reported truth until it reports the policy too.
- [ ] Engine-side parallel (same rule the repo's own agents run under): eval gates and
  exit codes cannot be overriden by config — no `|| true` equivalent exists. The engine
  ignores any "accept findings" field; JSON/SARIF stay factual.
- [ ] The design stance: a product that accepts risks on behalf of its customers can be
  made to blind itself; this one refuses the state instead of gating it.

## Licensing mechanics

- Metered at the **sensor** layer, per protected host. License enforcement lives in the
  closed-source sensor binary only — if it lives in the OSS engine it will be stripped.
- Stable host identity, signed license files, node-locked or floating.
- **AI/MCP agents are unmetered.** Host-based pricing would otherwise punish the exact
  extensibility that makes the OSS engine worth adopting. Actions are bounded by host
  count, not by agent count.
- 1-year term with host-count tiers; air-gapped renewal path for regulated buyers.

### Paid surfaces (dashboard + multi-tenancy)

- **The dashboard is paid by design, not crippled into it.** The web console — fleet
  inventory, policy editor, incident timelines, detection-content lifecycle, governance
  surfaces — runs only from the licensed console. The OSS side stays complete for its
  persona (CLI, JSON/SARIF output, MCP tools, eval harness): single-fleet technical
  operators pay nothing and lose nothing they were promised.
- **Multi-tenancy is the second paid surface.** Org → group → host hierarchy, tenant
  isolation and quota, RBAC/SSO, and cross-tenant pivoting are console-licensed. The
  engine itself has no tenant concept — single-fleet by design — so the paywall lives on
  inherently stateful server-side capability, not on fake feature-caps in the engine.
- Charging shape: sensors meter per protected host (above), the dashboard is licensed
  per console deployment or tiered by managed host count, and multi-tenancy is priced
  per tenant — exact numbers stay in `pricing.toml` (Phase 7 #4), never in prose.
- Enforcement lives in the console server + sensor binaries only, mirroring the
  licensing-leak rule. A license check must never appear in engine code, and paid
  features must always be things the free version *structurally cannot host* — that is
  what keeps the split honest at renewal time.

### Free reporting — normal commercial use

- [ ] Basic reporting is free and MIT for any commercial use: per-run artifacts — text,
  JSON, SARIF — with per-file verdicts, heuristic category breakdowns, and YARA matches
  with rule meta. No license gates, no phoning home, no watermarking in report content.
- [ ] Neutral wording inside artifacts: reports record tool name, version, engine
  thresholds and per-file data in plain professional language, suitable for CI runs and
  audit handoff ("what was checked, why this verdict"). The CLI banner and tagline are
  stderr persona only and never enter report artifacts; machine formats were already
  banner-free by design (`finish()` writes a document even on failed runs).
- [ ] Linux-first packaging for normal commercial deployment: deb/rpm packages with the
  engine at the standard paths (resources under `/usr/share/cau`, config under
  `/etc/cau` — matching the existing discovery order), man pages, shell completions,
  and a systemd timer unit for scheduled scans writing reports to a configurable
  directory.
- [ ] The free/paid reporting boundary rides existing lines: anything a single run can
  emit is free; anything that requires server-side state (fleet rollups, history,
  cross-tenant views, compliance packs) is a console surface. Same structural rule the
  paid-surfaces section enforces — reporting introduces no artificial cripples.

## Repo layout

```
astrav2/                     # MIT — the engine
  cmd/astra-av/              # CLI
  cmd/astra-mcp/             # MCP server
  internal/engine/           # detectors
  internal/eval/             # corpus harness, metrics, gates
  evasionsuite/              # Episode 7 adversarial harness

astra-console/               # proprietary
  cmd/astra-sensor/          # resident agent (licensed, enforcing)
  cmd/astra-scanner/         # scan node
  internal/controlplane/     # API, policy engine, detection content, model registry
  web/                       # dashboard
```

---

## Sequence

Phase 0-2 (fork fixes, harness, episodes 4/5/6) → Phase 3 (MCP) → Phase 4 (intel + content
lifecycle) → Phase 5 (ML) → Phase 6 (evasion suite) → Phase 7 (credibility bets: items 1-4
can start immediately on the OSS assets; 5-10 land inside Console Phases A-B) → Phases
8-9 (firmware/boot-chain and the blind-spot sweep, interleaved with Console A) → Phase 10
(novel-technique detections — content work, starts immediately) → Phase 11 (Linux ATT&CK
coverage matrix, driven by the same corpus) → Console
Phase A (fleet + policy + detection lifecycle, shippable paid tier) → Console Phase B
(incident + response) → Console Phase C (autonomous agents + model registry).

MCP and the evasion suite are the OSS credibility plays. They make the engine worth
adopting and they are the two things a commercial EDR will never publish.

---

## Blind-spot inversion — their thin spots, then ours again

Two directions, both honest: the classes the wider detection market has historically
left thin, each claimed against the row of this plan that owns it (so differentiation
stays checkable against the plan, not against vibes), and a third round of self-audit
on what this plan still doesn't have after every sweep above.

**Their thin spots → our rows**

| Class | Where other stacks historically stay thin | Row here that owns it |
|---|---|---|
| Linux-native persistence | endpoint products tuned to Windows telemetry treat Linux surfaces generically | the full Phase 11 matrix + the session/cloud sweeps |
| Boot-chain and firmware | usually not an endpoint product at all — a separate SKU or outsourced | Phase 8 |
| Runtime-provenance verification | SBOM tooling produces manifests; sensors rarely verify them against running state | provenance DB (Phase 7 #5) |
| CI/CD and ephemeral workloads | per-host agent models assume long-lived machines | cross-system sweep + orchestrator plane |
| Cross-host L2 corroboration | per-host views only; IP→MAC churn is rarely correlated fleet-wide | Threat Graph (Phase 7 #8) |
| Document stego / fileless | signature engines skip both; behavior engines skip the first | NOVEL rows (Phase 10) |
| Kernel-BPF implants | agents that are themselves eBPF rarely audit hostile BPF | kernel section's bpffs/pinned-state inventory |
| Self-attestation | agents rarely attest their own runtime integrity | hardware-anchor section |
| Hardware-witnessed endpoint identity | MAC/hostname spoofing checked in software only | NIC permanent-MAC row |
| EOL OS continuity | support matrices drop EOL distros years before fleets do | platform support policy |
| Honest coverage reporting | "all detections" pillars with nothing behind them | `cau coverage` gap-marks and the Phase 1 gates |

**Ours still open — round three of the self-audit**

| Open row | Why it's a gap | Ask |
|---|---|---|
| Rename-storm cadence | mass permission/ownership alerts exist; the canonical ransomware tripwire — rapid rename/extension mutation on data directories — is absent | write-volume + rename-cadence detector in the behavior engine, measured in Phase 1 |
| Provenance beyond packaging | the provenance DB anchors distro packages; npm/cargo/pip installs, snap/flatpak/appimage, vendored and hand-built binaries have no anchor classes — the language-ecosystem sweep row silently depends on them | extend Phase 7 #5 with per-ecosystem anchor classes |
| Event-vault at-rest crypto | console hardening covers auth, supply and anti-rollback; the event store's at-rest encryption and key rotation is never stated | console-vault row in the hardening section |
| Retention and data governance | retention windows, subject-rights workflow, deletion propagation for sensor/behavior metadata: unplanned | data-governance row — retention policy and deletion paths tested like code |
| IR playbook library | the console ships response APIs; no operational playbook content rides the top Linux detections | pre-written runbook pack per top-20 detection, versioned and reviewed like detection content |
| `cau selftest` | a sensor can fall out of coverage silently — tap dead, BPF misload, kernel-gated, clock skew | one-command self-verification rendered in the console and gating fleet health |
| Release architecture matrix | the build matrix ships amd64; arm64 is implied, riscv64 uncommitted | architecture matrix in the release workflow, gates equal across arches |

- [ ] The inversion table is re-checked against the live coverage matrix at the same CI
  gate: a "thin spot" whose owning row regresses to planned/none re-opens the claim, so
  differentiation statements age with the product instead of rotting into marketing.

## The path to ten — category, not scoreboard

On the commercial-EDR board a ten is unwinnable without becoming that vendor — fleet-years,
install-base and data opacity are structural. So the ten lives on a different board: the
YARA/Sigma/Zeek outcome, becoming the layer the field plugs into rather than the product
that wins their scoreboard. Four components, each with its reason incumbents can't follow:

| Component | What it is | Why incumbents can't follow |
|---|---|---|
| Third-party scoring gate | the Phase 1 harness accepts external engines, Sigma-class rule packs and vendor coverage claims; per-technique FP/FN and evasion-distance publish for whoever submits | entering means publishing numbers their franchise has never published; staying out means being measured anyway |
| Prevalence co-op | opt-in class-level behavioral telemetry federation — taxonomy only, no content, no endpoint names, retention contract written before any data flows | a data moat built from openness: participants join because they own their data, not because they were locked in |
| Honesty-index instrument | free-reporting rules rendered as a scriptable index (coverage gap-marks, measured FP, selftest health) that buyers, auditors and insurers can run themselves | transparency becomes procurement infrastructure; trust-based channels can't follow without confessing on themselves |
| Substrate posture | engine as an embeddable detection layer (appliances, gateways, SIEM packs, CI platforms) plus the MCP agentic surface | complements get helped by vendors in ways competitors never are |

The data axis flips from sensor-years (time × agents installed) to environment-hours
(breadth of environments × runs per day) — CI- and ephemeral-native collection is the one
axis where open beats installed-agent fleets without needing their scale.

- [ ] Third-party submissions pipeline: signed manifests, the same CI gates, a published
  scoreboard. The one thing that must never happen is refusing to measure an engine that
  shows up — the index's value is precisely that it measures everyone who enters.
- [ ] Co-op governance: the free-reporting privacy rules apply to federation itself; a
  co-op drifting into a data broker is a named failure mode in the governance section.
- [ ] Honesty-index v0: render coverage, Phase 1 results and selftest health into a
  single scriptable artifact now; v1 adds the third-party columns.
- [ ] Substrate track: an embedding guide plus a stable detection-API contract; the MCP
  surface grows coverage and eval tools next to the scan tools.
- [ ] Honest boundary: this path's schedule is market-gated, not code-gated — adoption,
  not engineering, is the limiting resource. The ten-path runs parallel to
  closing-the-loop and never replaces shipping the boxes.

---

---

## Standards program — writing the bar, not meeting it

The ten-path defines becoming the layer the field plugs into; this defines what "plugged
in" means concretely: specifications Astra publishes that are *stricter than industry
practice*, each shipping with a conformance suite from day one — because a standard
nobody can test is marketing.

| Standard | What it sets | Industry state | Artifact + conformance |
|---|---|---|---|
| Detection-evidence contract | every shipped detection carries a provenance manifest, model card, per-technique FP/FN, last-measured date, bypass-regression state | vendor content ships with nothing comparable public | manifest schema + validator any vendor can run against their own content |
| Evidence-class labels | telemetry stratified by derivation: kernel-asserted / subsystem-confirmed / inferred, per event class | surveys count signals; nobody labels how each was derived | label schema + cross-check suite |
| Coverage honesty | gap-marks, planned/partial/detected states, no-padding render rules | coverage claims are marketing artifacts | `cau coverage` spec + independent re-checker |
| TTD metric | per-technique time-to-detect published with measurement conditions | eval programs measure it; vendors don't publish per-technique | open TTD harness spec + fixtures |
| Evasion-distance | per-technique, measured against the regression corpus, signed | not measured publicly anywhere | no precedent — the spec is written wherever it is invented |
| Event-loss accounting | drops by class with the fairness policy, published per sensor build | silent drops are the industry default | drop-account schema, verified by the CI benchstat runs |
| Eval-interchange fixtures | blue/red paired synthetic corpus format, versioned, license-clean, importable into other harnesses | eval corpora are private or ad-hoc | fixture-pack spec + importers; Sigma pairing where shapes overlap |
| Sensor-health contract | `selftest` schema: taps-alive, BPF-loaded, kernel-gates, clock-skew, hwanchor state as a readiness surface | agents ship health checks with no open contract | selftest schema + console/helm probe integration |
| Event-transparency profile | per-class privacy boundary + retention contract as machine-readable config, the free-reporting rules encoded | privacy posture ships as a PDF | profile schema + policy evaluator |

- [ ] `specs/` directory: every standard is a versioned spec document plus a reference
  validator, semvered so adopters never churn.
- [ ] Conformance as the credibility engine: the same suite that gates Astra's CI runs
  as `cau verify-spec <artifact>` — adopters self-test without shipping anything here.
- [ ] Adoption track: three early integrations per spec (one SIEM sink, one fleet tool,
  one eval harness) landed through the co-op's open-governance route, never through
  NDA-style silence.
- [ ] Interop anchoring: every spec imports and exports Sigma, STIX/TAXII and ECS where
  they overlap — strictness is layered on the norms that exist, never cut off from them.
- [ ] Honest boundary: a standard only Astra meets is a requirement, not a standard.
  Adoption re-checks ride the same CI gate as the inversion table — a spec whose only
  passing conformance is Astra's own regresses to "requirement," and the coverage
  render says so in place of the claim.

---

## Detection-methodology rating — versus industry practice

Industry methodology decomposes into four instruments: ATT&CK Evaluations-style
emulation scoring (external, technique-level, per-behavior), the telemetry-survey axis
(EDR-Telemetry-Project-style breadth mapping), commercial engine labs
(AV-Comparatives/SE-Labs style detection-rate testing with FP weighting), and vendor
internal regression corpora — the thing most products actually gate on. Honest grades
for this plan's execution at the done-right standard:

| Axis | Industry practice | Astra at standard | Grade |
|---|---|---|---|
| Coverage definition | technique matrices, Windows-clean, mostly post-hoc | full Linux matrix with per-technique analytic owner + gap-marks | A on Linux; nothing comparable market-wide |
| Validation independence | external emulation ranges running adversary traces | own synthetic blue/red fixtures, CI-gated | B — below the evals' standard until the third-party scoring gate lands |
| Content regression | vendor-internal corpora, rarely per-merge | every merge CI-measured against the bypass corpus; eval regressions fail releases | A — stricter than common practice |
| FP accounting | lab-tested and weighted, opaque per-technique | per-technique FP/FN numbers published | A |
| Evasion-distance | not measured publicly by vendors | published per technique | A — no industry precedent to follow |
| Telemetry honesty | survey taxonomy | kernel-asserted/inferred labels + drop accounting | A — stricter |
| Behavior-model maturity | fleet-scale incident corpora | small-corpus, planned Phase 5 ladder | C+ — honest until fleet-years |
| Prevention efficacy | graded axis (block vs detect) | detection-first with quarantine | C — a parallel axis, owned honestly |
| Time-to-detect | measured latencies, headline numbers | no per-technique TTD metric planned | C — addable, listed below |
| Environment diversity | multi-OS and multi-version emulation matrix | kernel/glibc spread only thinly planned | B- — fixtures matrix needed |

- [ ] Per-technique time-to-detect joins the Phase 11 renderings — it is the industry's
  headline number and the plan currently doesn't say it.
- [ ] A fixtures matrix across kernel/glibc/architecture variants joins Phase 1, so the
  environment-diversity row moves from B- to A at eval time.
- [ ] The third-party scoring gate is simultaneously the independence fix — the same
  component moves both rows that grade below B.

---

---

## Detection-quality program — improving the rows that already exist

The sweeps added planes; this program improves the *quality* of detection on every
plane — the gap between "a row exists in the matrix" and "the row fires at its target
FP/FN in production" is where detection programs actually live or die.

| Improvement | What it changes | Tie-in |
|---|---|---|
| Detection fusion lattice | independent weak analytics fuse into one score — beating one detector costs little; beating a fusion of sources costs multiplicatively, since each layer must be evaded separately with uncorrelated errors | behavior engine (Phase 5) + eval gates |
| Fleet-relative behavioral novelty | "first-seen *in this fleet*" as an analytic, not just per-host first-seen: a process behavior on 2 hosts of 1000 outranks the same behavior fleet-wide-ubiquitous — FP suppression and novel-threat detection in one move | Threat Graph (Phase 7 #8), prevalence tables |
| Detection-liveness program | per-module synthetic signal injection (each tap must echo a signed canary event end-to-end) + fleet canary hosts running periodic full-pipeline checks — a silently broken pipeline becomes visible in minutes, not at the incident | `cau selftest`, aliveness monitor |
| Retro-sweep on intel updates | newly-landed detection content re-scans the recent local backlog (recent scannables, recent telemetry) so a rule catches up on history instead of only firing forward — with the retro-window size and the catch-up quarantine results rendered | Phase 4 content lifecycle, quarantine primitives |
| Verdict feedback ledger | analyst dispositions (TP/FP/benign-true) feed per-detection calibration with published FP/FN trend lines; dispositions are class-level metadata, never content | console surfaces, detection-debt metric |
| Governed suppressions | recurring benign patterns can be silenced — as *expiring, signed, audited benign-pattern contracts* with mandatory quarterly re-review. A suppression is a benign-class annotation, never a malice-acceptance, and the governance section gains exactly this clause so it can't become a bypass surface | no-risk-accepted rule (Policy governance) |
| Temporal baselining | circadian and work-period-aware confidence weighting — same behavior at 3am and at 14:00 on a Tuesday is not the same signal on a workstation fleet | agent types, per-agent-type eval weights |
| Privileged script telemetry | command-line capture for root/sudo lineages only, opt-in per fleet profile with full privacy accounting — Linux's missing PowerShell-script-block equivalent, scoped honestly | session plane, privacy rules |
| Evasion-cost curves | per-detection published cost-of-evasion curves from the bypass corpus — what an attacker must spend (time, primitives, surface) to retain attack value — detection economics instead of "detected/not detected" | Phase 6 evasion suite, Phase 11 renderings |
| Streaming scan plan | chunked, resumable scan of multi-GB files in the write path with hard budget caps — large-file handling stops being a timeout race and becomes a scheduled, interruptible stream | engine budget gates (Phase 1) |

- [ ] `internal/fusion`: the lattice joins the one internal event model — fusion inputs
  carry their evidence labels through, and a fused verdict renders *which* sources
  agreed, not just the score.
- [ ] `internal/novelty`: fleet-relative first-seen persists per behavior-class key;
  the novelty ledger feeds the Threat Graph like the device and NIC inventories do.
- [ ] Canaries are content, not code: the canary event generator ships in the detection
  content pack, signed like every other pack item, so liveness checks rot as slowly
  as the detections they verify.
- [ ] Measure or don't ship: no improvement lands without per-detection before/after
  numbers on the same Phase 1 fixtures — the counter-claims (FP reduced, FN unchanged,
  latency flat) published where the detection's model card lives.
- [ ] Governance seam, written down once: benign-pattern contracts satisfy the
  no-risk-accepted rule *by construction* — they annotate benign patterns and expire;
  anything that would silence true-positive classes is, by definition, not a
  suppression and goes through the incident-and-response surface instead.

---

---

## Design-debt audit — flaws in this plan's own architecture

Coverage gaps are easy to add; this section is the harder pass — reviewing the plan
against itself. Eight design flaws exist in the current architecture as written. Each
stays a flaw until a design fixes it, not a paragraph.

**1. Event-model drift from module sprawl.** Ten-plus internal modules
(`netguard`, `usbguard`, `sessiontap`, `pkgmon`, `exploitledger`, `hwanchor`, `echolane`,
`garlic`, …) now feed the "one internal event model" claim. Left unspecified, they
drift into per-module formats and re-fragment the model the plan keeps citing.
Fix: a typed event-model registry — every module ships its event schema family plus a
conformance suite against the registry in CI, or it doesn't merge. The sink matrix
stays single-source at the registry, not at the promise.

**2. Tap-sum footprint.** Session taps, quiet-plane taps, install holds, transport
taps, ledger taps — each individually budgeted, jointly unaccounted. The RSS ceiling
and throughput budgets are per-program, not per-host-sum. Fix: a tap governor — every
tap declares its volume class (low/high/burst), per-class rate shaping with labeled
loss, and the *sum* flat-capped per host with shedding order published. The
agent-footprint sales point (Phase 7 #7) survives only if the sum is measured.

**3. No policy compiler.** Fleet profiles, class policies, allow-lists, thresholds,
hold deadlines, retention contracts, transport-ladder defaults — each feature invented
its own config surface. Config sprawl with divergent semantics is how "profiles" stop
meaning anything. Fix: one typed, signed policy schema with per-feature manifests and
explicit precedence rules; agent-types, fleet profiles and tenant hierarchy normalize
through it rather than each having private knobs.

**4. Update-in-flight semantics are unspecified.** Signed release channels and
anti-rollback exist; what happens *during* a sensor replacement does not — a watch-gap
mid-update is exactly the window an attacker wants. Fix: drain-and-handoff — the old
sensor drains its queue, the tap set hands over with no-watch-gap asserted by selftest,
receipts are version-tagged, and a failed handoff rolls back atomically.

**5. The sensor's privilege model is unspecified.** Most taps need capability (exec-perm
hold, XDP, kcore reads, flash-write taps) — but the plan never partitions privilege
inside the sensor itself. One watcher holding everything means one compromise holds
everything. Fix: a privilege-partitioned helper tree — capability sets declared per
tap, separate helper processes sized to their cap set, kill-scoped blast radius, and
the engine's decision path never reachable from any single helper.

**6. The self-heal / NOVEL-005 irony.** Our own row flags exclusive-tenancy wars —
agents killing other agents. Our self-heal mechanic (auto-reinstall on remove) is
behaviorally indistinguishable from that war *to other agents watching us*. Fix:
self-heal is open by label — reinstall only from the customer's configured channel,
rate-limited, profile opt-in, and emitting a `fleet-policy self-heal` event every time
so other agents observing us see policy, not a fight. Our NOVEL-005 detector should be
able to accept our own behavior by those labels alone.

**7. Local evidence is tamperable before transport.** Encrypted spool covers console
delivery; the on-host event journal itself can be deleted or edited by root before any
of it ships. Fix: an append-only, hash-chained local evidence journal — TPM-sealed
head via the hardware-anchor row, deletion or edit attempts are ledger events in
their own right, and the journal survives the kill attempts that the harder-to-kill
rule says must leave survivable evidence.

**8. Field FP is unmeasured.** Every FP number in the plan is fixture-derived. Synthetic
blue/red pairs test the generator's realism, not the fleet's — the methodology-rating
section's "field-FP calibration" gap remains. Fix: the prevalence co-op becomes the
calibration instrument — opt-in, class-level production FP measured per fleet-class,
published against the fixture numbers so each detection's model card carries *both*
(claimed and observed). Where they diverge, the divergence is the headline, not a
footnote.

- [ ] Registry, governor, policy compiler: three design docs land in `specs/` (they
  qualify as standards-program items: event-model registry, tap-governor contract,
  typed policy schema), each with a conformance suite — the standards program is the
  enforcement mechanism, not another label.
- [ ] The flaw-to- acceptance mapping: every design deck item above becomes a checkbox
  in the phase that owns it (kernel → #7 journal; console → #6 labels; Phase 1 → #2
  measurement), so the audit is scheduled rather than admired.
- [ ] CI: neither event-model conformance, tap-governor sum caps, nor policy-schema
  validation pass until their suites exist — new modules land *with* their schema,
  never behind it.
- [ ] Honesty line: the audit itself is re-run each release cycle; a fixed flaw stays
  fixed only if its conformance suite stays green — design debt has a gate now, not
  just a list.

---

---

## Performance-gap sweep — the contracts that are still missing

Phase 1 gates throughput, memory and timeouts; closing-the-loop §2 budgets per-hook
overhead and pipeline SLOs; the tap-governor caps the per-host sum. What's still
missing is the contract *per domain* — the performance work that has no number yet:

| Domain | Missing performance contract | The ask |
|---|---|---|
| Scan-result cache | no verdict cache exists — node_modules-scale trees re-scan identical content endlessly | content-hash verdict cache with pack-update invalidation (retro-sweep interplay), bounded size, hit-rate published |
| Engine worker pool | scan parallelism and I/O strategy unplanned | mmap/page-cache-friendly IO, worker pools sized under the memory ceilings, per-worker memory budgets |
| Event aggregation | the drop policy sheds under load but nothing *shrinks* load honestly | coalescing of identical repeated events into labeled aggregate events with counts — volume reduction without lying |
| Boot-window coverage | nothing measures how fast the sensor is *covering* after boot; pre-attach events are lost silently | time-to-covered per platform as a published metric; honest backfill via journald where available, gap-marked where not |
| Ephemeral attach latency | containers/CI runners churn faster than traditional fleets | container start-to-protected latency measured per runtime, CI-storm case benched |
| Ruleset compile budget | YARA/ruleset load time and pack size unplanned | compile-time and pack-size budgets, delta pack updates, incremental compile on hot reload |
| Console query SLOs | pivot/graph queries have no latency contract | graph-query latency caps, precomputed aggregates, pagination — the analyst console must answer in interactive time at fleet scale |
| Vault economics | retention/compaction/index growth unplanned | partitioned indexes, compaction schedules, storage caps with retention contracts enforced |
| PQC overhead | garlic/echo-lane require hybrid E2E per sink; ML-DSA receipts are *large* — unpriced | bytes+CPU per crypto op published per event class, receipt batching where signature size dominates |
| QUIC reconnect storms | ephemeral fleets reconnect constantly; handshake cost unpriced | anti-amplification rules, handshake caches, 0-RTT bounded by receipt pinning (no 0-RTT replay credit) |
| Per-arch parity | the arch matrix ships but performance parity is untested | the same SLO table per architecture — riscv64's honest delta published, not hidden behind one number |
| Fleet-scale soak | console horizontally-scaling knobs never exercised | nightly simulated-fleet soak (10k hosts) with scaling curves published *before* they're needed |

- [ ] `cau bench`: one harness, every domain registers a scenario, benchstat artifacts
  per run, regressions fail like any gate — the multi-domain gap closes only if
  measurement is one convention, not twelve.
- [ ] Bench-versus-fleet honesty: CI-runner numbers and real-fleet numbers are
  published side by side — the canary-host program (detection-liveness) doubles as the
  performance-canary fleet running synthetic load, with per-class p50/p99 reported.
- [ ] Kernel-side budgets land explicitly: BPF map memory caps, program-size and
  verifier limits, measured per-program attach cost — the kernel plane's performance
  budget is a document, not a hope.
- [ ] Crypto-DoS joins the coin side: repeated KEM-handshake forcing is rate-capped
  the way peel DoS was, with the same fairness model.
- [ ] Every number lands on the model-card surfaces the plan already publishes — no
  performance claim without its measurement conditions, per the standards program.

---

## Closing the loop — the four limits, owned

The plan's own critique surfaces four standing limits. Each gets a workstream rather
than a wish, and progress lands in the coverage artifact so it is measured, not promised.

**1. Detection-content supply (the open-matrix problem).**
The Phase 4 intake sources content; what it lacks is the *operations loop* that turns
open matrix rows into shipped detections:
- [ ] One open row = one tracked issue = one PR. Every merged detection lands with its
  model card and Phase 1 FP/FN numbers attached. "Detection debt" — open rows and the
  trend per release — is a published metric, not a private TODO.
- [ ] Generation assists, never ships: the Phase 5 Tier-3 LLM analyst and corpus-cluster
  rule drafts enter through the same gates as everything else — generated, gated,
  human-reviewed. There is no fast lane around Phase 1.
- [ ] Community contribution path: external rule PRs sign the same provenance manifest,
  with a standing revert contract — a contributed rule that costs FPs is pulled in the
  same CI cycle that introduced it, which is what keeps contributions safe to accept at
  scale.

**2. Latency and throughput (sensor runtime).**
Phase 1 budgets the engine and the eval; the sensor runtime needs its own explicit
numbers:
- [ ] Hook-overhead budget: every BPF-LSM/eBPF program documents its per-event cost in
  the source header; CI benches regressions with benchstat deltas and publishes
  flamegraph artifacts. Regressions fail the build like any other gate.
- [ ] Event-pipeline SLO: sustained-ingest target measured on the CI-runner baseline,
  with a published event-loss policy — drop classes are accounted, never silent, per the
  evidence-labeling rule. Under pressure the plan says *what sheds*, not aim silently.
- [ ] Memory ceilings: the sensor RSS cap is enforced and surfaced, because the
  agent-footprint argument (Phase 7 #7) only survives if it is measured.

**3. The product's own CVE credibility.**
- [ ] `SECURITY.md`, coordinated disclosure with embargo; `govulncheck` runs with
  lint/build/test in the CI stage; SBOM is consumed, not only produced, so Astra's own
  dependencies live under the same supply gates it enforces elsewhere.
- [ ] A bypass of this product, when found, lands as a regression fixture the same day
  as its fix — the Phase 11 bypass-corpus rule runs at Astra first.

**4. The internal-corpus dependency.**
- [ ] Every publicly planned detection names its public evidence source (MISP, abuse.ch,
  LOLDrivers, the LOTL catalogs, synthetic fixtures). The internal corpus steers the
  *priorities*; it never funds a public claim. Where no public twin of an internal
  detection exists, the row stays gap-marked in the coverage matrix instead of shipping
  a number the repo cannot itself support.

## Risks

- **Adoption vs. revenue.** OSS engine too weak → nobody adopts. Too strong → nobody pays.
  Mitigation: the persona split above. The OSS core is complete for analyst/CI work; the
  console is sold on fleet state and response authority, which the engine cannot offer.
- **Licensing leak.** Per-host enforcement in an MIT-licensed binary is unenforceable.
  Mitigation: enforcement only in the sensor binary; the engine refuses to be the license
  boundary.
- **AI agent licensing ambiguity.** Settle the "unmetered agents, host-bounded actions"
  policy before building governance surfaces, not after.
- **Feature migration.** Memory/fileless detection is the strongest differentiator and it
  lands in the closed repo by necessity. Keep the OSS roadmap honest about what it will
  never do rather than teasing it.
