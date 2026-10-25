# Limitations

Every detector has a failure mode, and this engine is built so that each one
is stated rather than hidden. The planned evasion suite (PLAN.md, Phase 6)
will demonstrate all of them against this engine; the evaluation harness
exists so the demonstration can be measured.

## By detector

| Detector | Dies to | Survives |
|---|---|---|
| Hash signatures | a single flipped byte | nothing short of an identical file |
| Fuzzy hashes (TLSH, ssdeep, imphash) | a repack, a rebuild, a changed import set | trivial edits and appended data |
| YARA | an author who knows the ruleset: renamed strings, encrypted payloads, split patterns | content the rule author described |
| Heuristics | capability hidden behind dynamic API resolution or encryption; and the inverse: a debugger has an injector's import profile and is reported as one | binaries that still name what they do |
| Static structure | an unpacked, unsigned, plainly linked credential dumper looks ordinary; a packed benign tool looks packed | tampered headers, forged signatures, loader-only import tables, appended payloads |
| Invisible codepoints | a channel that uses visible characters, or lives in a binary format | any invisible codepoint in text or code, regardless of density |
| Fusion | a file silent on every detector | the attacker who beats one detector and leaves evidence on another |

## Documented false-positive classes

| Detector | Class | Measured |
|---|---|---|
| Heuristics | debuggers and injection-capable developer tools (OllyDbg scores 11) | 28 of 349 files in the Kali Windows tool set score at or above 7, almost all of them offensive tools shipped on purpose |
| Static | none above the threshold on the tool set; packed benign tools render as low suspicion with the packer named | `wget.exe` 7/8, `klogger.exe` 6/8 |
| Stego | a stray ZERO WIDTH SPACE pasted into documentation or a translation file; source files that enumerate Unicode categories (regular-expression libraries, identifier tables); a stray byte-order mark mid-file | 70 of 70,102 benign text artifacts (0.10 %) |
| Fusion | none observed | 0 fused-only detections on the tool set |

The stego pass is presence-based on purpose: a single pasted codepoint is
reported as exactly one occurrence with no payload run, so an analyst can
tell it from an encoded channel at a glance, and `--stego-threshold 8` makes
the engine require a payload run or an ASCII carrier as well.

## What is not covered yet

- **File formats.** The structural pass parses PE images. ELF, Mach-O, OLE /
  VBA, PDF, LNK, CHM, ISO, archives and firmware images each need their own
  pass (PLAN.md, Phases 8 and 9); until then they get hashing, YARA,
  heuristic strings, entropy, fuzzy digests and the stego pass only.
- **Unpacking.** Packed samples are identified, not unpacked. The bounded
  peeler and the emulation fallback are planned (NOVEL-012).
- **Behaviour.** The engine is static. Process lineage, network and runtime
  telemetry are the sensor's job, outside this repository.
- **Field false positives.** Every number here is fixture-derived from one
  machine's package set; a real corpus is Phase 1's open item.
- **Trust.** No certificate chain is verified against a trust store, by
  design and by name.
