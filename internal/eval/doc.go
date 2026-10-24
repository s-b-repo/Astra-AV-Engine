// Package eval implements the CAU EDR detection-evaluation harness.
//
// Nothing in this engine ships without a measured number behind it, so the
// harness is built around three ideas:
//
//  1. A corpus is *data*, declared in a JSON manifest (see Manifest), never
//     implied by directory naming or hand-remembered. The manifest records the
//     expected label for every sample, how to find it, and where it came from.
//     [Manifest.Validate] reports missing files, unresolved paths and hash
//     mismatches up front, because one silently broken path quietly poisons
//     every metric downstream.
//
//  2. A run is *deterministic*. [Runner] walks the manifest in manifest order
//     and stores results by index, so two runs of the same corpus produce
//     byte-identical reports regardless of scan duration or concurrency.
//     That is what makes a baseline diff meaningful.
//
//  3. A gate is *policy*, not magic numbers. [Policy] is a value that can be
//     loaded from JSON, reviewed in a diff, and unit-tested branch by branch.
//     [IsRegression] takes a baseline, a candidate run and a policy, and
//     returns an auditable [Decision] listing every violated rule.
//
// Dependency discipline: this package imports nothing from the rest of the
// module and nothing outside the standard library. Detectors are supplied by
// the caller through the [Detector] interface, so the harness is fully testable
// with synthesised inputs and does not break when the scanner is refactored
// underneath it. The bridge that adapts the real scanner to this interface
// lives in the separate package internal/eval/scannerbridge, which is the only
// package allowed to import both sides.
//
// Typical use:
//
//	manifest, err := eval.LoadManifest("corpus/manifests/local.json")
//	if err != nil { ... }
//	if v := manifest.Validate(eval.ValidateOptions{}); !v.OK() { ... }
//	run, err := eval.NewRunner(detectors, eval.RunOptions{}).Run(manifest)
//	report := eval.NewReport(run)
//	baseline, err := eval.LoadReport("corpus/baselines/main.json")
//	diff := eval.Diff(baseline, report)         // what changed
//	decision := eval.IsRegression(baseline, report, eval.DefaultPolicy())
//	if err := decision.Err(); err != nil { ... } // the gate
//
// Reports persist with [Report.WriteJSON]; everything in them is sorted, so
// two runs of one corpus differ only in run.generated_at and the duration
// fields, which [Diff] ignores except in its perf section.
package eval
