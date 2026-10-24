# Astra AV — v2 Plan

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

- [ ] STIX/TAXII + MalwareBazaar sync; replaces the hand-typed `hashes.txt`
- [ ] YARA rule linter — catches the dead rules already shipped in `rule_list.yar`
- [ ] Content test-before-promote: every rule change runs against Phase 1 corpus with
      measured regression, blocks merge on FP regression
- [ ] ATT&CK mapping on rules + a coverage matrix that reports techniques with **no**
      rule. This is the honest counterfactual to what CrowdStrike sells.

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
lifecycle) → Phase 5 (ML) → Phase 6 (evasion suite) → Console Phase A (fleet + policy +
detection lifecycle, shippable paid tier) → Console Phase B (incident + response) →
Console Phase C (autonomous agents + model registry).

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
