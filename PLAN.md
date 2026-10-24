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

## Licensing mechanics

- Metered at the **sensor** layer, per protected host. License enforcement lives in the
  closed-source sensor binary only — if it lives in the OSS engine it will be stripped.
- Stable host identity, signed license files, node-locked or floating.
- **AI/MCP agents are unmetered.** Host-based pricing would otherwise punish the exact
  extensibility that makes the OSS engine worth adopting. Actions are bounded by host
  count, not by agent count.
- 1-year term with host-count tiers; air-gapped renewal path for regulated buyers.

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
