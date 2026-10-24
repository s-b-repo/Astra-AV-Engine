package eval

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

// Policy is the regression gate, as data. Absolute rules (MinRecall, MaxFPR,
// MaxErrors, per-detector/per-family minimums) apply to the candidate alone;
// relative rules compare against a baseline and are skipped when there is
// none. Every rule is optional. Fractions are 0..1; "Drop"/"Increase" rules
// are absolute differences in the same unit (0.01 = one percentage point).
//
// Undefined ratios never violate a rule: a metric that cannot be computed is
// "no information", not a regression.
type Policy struct {
	// Absolute thresholds on the candidate.
	MinRecall *float64 `json:"min_recall,omitempty"`
	MaxFPR    *float64 `json:"max_fpr,omitempty"`
	MaxErrors *int     `json:"max_errors,omitempty"`

	// Relative thresholds vs the baseline.
	MaxRecallDrop        *float64                  `json:"max_recall_drop,omitempty"`
	MaxFPRIncrease       *float64                  `json:"max_fpr_increase,omitempty"`
	MaxPrecisionDrop     *float64                  `json:"max_precision_drop,omitempty"`
	MaxNewFalsePositives *int                      `json:"max_new_false_positives,omitempty"`
	MaxNewFalseNegatives *int                      `json:"max_new_false_negatives,omitempty"`
	MaxErrorIncrease     *int                      `json:"max_error_increase,omitempty"`
	RequireSameCorpus    bool                      `json:"require_same_corpus,omitempty"`
	PerDetector          map[string]DetectorPolicy `json:"per_detector,omitempty"`
	PerFamily            map[string]FamilyPolicy   `json:"per_family,omitempty"`
	Perf                 PerfPolicy                `json:"perf,omitempty"`
}

// DetectorPolicy scopes rules to one detector.
type DetectorPolicy struct {
	MinRecall     *float64 `json:"min_recall,omitempty"`
	MaxFPR        *float64 `json:"max_fpr,omitempty"`
	MaxRecallDrop *float64 `json:"max_recall_drop,omitempty"`
}

// FamilyPolicy scopes rules to one malware family.
type FamilyPolicy struct {
	MinRecall *float64 `json:"min_recall,omitempty"`
}

// PerfPolicy is the performance budget, relative to the baseline. Percentages
// are plain numbers (50 = 50%). Zero disables a rule.
type PerfPolicy struct {
	MaxTotalDurationIncreasePct float64 `json:"max_total_duration_increase_pct,omitempty"`
	MaxP95IncreasePct           float64 `json:"max_p95_increase_pct,omitempty"`
	// MinThroughputRatio fails when candidate throughput / baseline throughput
	// falls below this (0.8 = may be at most 20% slower).
	MinThroughputRatio float64 `json:"min_throughput_ratio,omitempty"`
	// MinBaselineDurationMs is the floor under which the relative perf rules
	// are not applied: a 1 ms run that becomes 2 ms is timer noise, not a
	// regression. 0 means "use DefaultMinBaselineDurationMs"; set it negative
	// to apply the rules at any scale.
	MinBaselineDurationMs float64 `json:"min_baseline_duration_ms,omitempty"`
}

// DefaultMinBaselineDurationMs is the default PerfPolicy.MinBaselineDurationMs.
const DefaultMinBaselineDurationMs = 1000

func (p PerfPolicy) floor() time.Duration {
	switch {
	case p.MinBaselineDurationMs < 0:
		return 0
	case p.MinBaselineDurationMs == 0:
		return DefaultMinBaselineDurationMs * time.Millisecond
	default:
		return time.Duration(p.MinBaselineDurationMs * float64(time.Millisecond))
	}
}

func fptr(v float64) *float64 { return &v }
func iptr(v int) *int         { return &v }

// DefaultPolicy is the gate `cau eval gate` applies when none is given: no new
// false positive, no recall drop, no FPR increase, no new scan errors, and at
// most 50% more total scan time.
func DefaultPolicy() Policy {
	return Policy{
		MaxRecallDrop:        fptr(0),
		MaxFPRIncrease:       fptr(0),
		MaxNewFalsePositives: iptr(0),
		MaxErrorIncrease:     iptr(0),
		Perf:                 PerfPolicy{MaxTotalDurationIncreasePct: 50},
	}
}

// LoadPolicy reads a policy from a JSON file.
func LoadPolicy(path string) (Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, fmt.Errorf("eval: read policy: %w", err)
	}
	p, err := ParsePolicy(data)
	if err != nil {
		return Policy{}, fmt.Errorf("eval: policy %s: %w", path, err)
	}
	return p, nil
}

// ParsePolicy decodes a policy. Unknown fields are rejected: a misspelt rule
// would otherwise silently not be enforced.
func ParsePolicy(data []byte) (Policy, error) {
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	var p Policy
	if err := dec.Decode(&p); err != nil {
		return Policy{}, fmt.Errorf("parse policy: %w", err)
	}
	if err := ensureNoTrailingJSON(dec); err != nil {
		return Policy{}, fmt.Errorf("parse policy: %w", err)
	}
	if err := p.validate(); err != nil {
		return Policy{}, err
	}
	return p, nil
}

func (p Policy) validate() error {
	check := func(name string, v *float64) error {
		if v != nil && (*v < 0 || *v > 1) {
			return fmt.Errorf("policy: %s must be within 0..1, got %v", name, *v)
		}
		return nil
	}
	for name, v := range map[string]*float64{
		"min_recall": p.MinRecall, "max_fpr": p.MaxFPR, "max_recall_drop": p.MaxRecallDrop,
		"max_fpr_increase": p.MaxFPRIncrease, "max_precision_drop": p.MaxPrecisionDrop,
	} {
		if err := check(name, v); err != nil {
			return err
		}
	}
	for d, dp := range p.PerDetector {
		for name, v := range map[string]*float64{"min_recall": dp.MinRecall, "max_fpr": dp.MaxFPR, "max_recall_drop": dp.MaxRecallDrop} {
			if err := check("per_detector."+d+"."+name, v); err != nil {
				return err
			}
		}
	}
	for f, fp := range p.PerFamily {
		if err := check("per_family."+f+".min_recall", fp.MinRecall); err != nil {
			return err
		}
	}
	for name, v := range map[string]*int{"max_errors": p.MaxErrors, "max_new_false_positives": p.MaxNewFalsePositives,
		"max_new_false_negatives": p.MaxNewFalseNegatives, "max_error_increase": p.MaxErrorIncrease} {
		if v != nil && *v < 0 {
			return fmt.Errorf("policy: %s must not be negative, got %d", name, *v)
		}
	}
	if p.Perf.MaxTotalDurationIncreasePct < 0 || p.Perf.MaxP95IncreasePct < 0 || p.Perf.MinThroughputRatio < 0 {
		return fmt.Errorf("policy: perf limits must not be negative")
	}
	return nil
}

// WriteJSON persists the policy.
func (p Policy) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(p)
}

// Violation is one broken rule.
type Violation struct {
	Rule      string `json:"rule"`
	Scope     string `json:"scope"` // overall | detector:<name> | family:<name> | perf | corpus
	Message   string `json:"message"`
	Baseline  string `json:"baseline,omitempty"`
	Candidate string `json:"candidate,omitempty"`
}

func (v Violation) String() string {
	s := fmt.Sprintf("[%s] %s: %s", v.Scope, v.Rule, v.Message)
	if v.Baseline != "" || v.Candidate != "" {
		s += fmt.Sprintf(" (baseline %s, candidate %s)", orDash(v.Baseline), orDash(v.Candidate))
	}
	return s
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// Decision is the auditable outcome of IsRegression.
type Decision struct {
	Pass       bool        `json:"pass"`
	Violations []Violation `json:"violations"`
	// Notes carry information that did not fail the gate: skipped relative
	// rules, undefined metrics, corpus differences.
	Notes []string `json:"notes,omitempty"`
}

// Err returns nil on pass, otherwise an error listing every violation.
func (d Decision) Err() error {
	if d.Pass {
		return nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "eval: regression gate failed with %d violation(s)", len(d.Violations))
	for _, v := range d.Violations {
		fmt.Fprintf(&b, "\n  %s", v.String())
	}
	return fmt.Errorf("%s", b.String())
}

// WriteText renders the decision.
func (d Decision) WriteText(w io.Writer) error {
	if d.Pass {
		fmt.Fprintln(w, "gate: PASS")
	} else {
		fmt.Fprintf(w, "gate: FAIL (%d violation(s))\n", len(d.Violations))
	}
	for _, v := range d.Violations {
		fmt.Fprintf(w, "  ✗ %s\n", v.String())
	}
	for _, n := range d.Notes {
		fmt.Fprintf(w, "  · %s\n", n)
	}
	return nil
}

// IsRegression evaluates candidate against baseline under policy p. A nil
// baseline applies only the absolute rules and notes that the relative ones
// were skipped.
func IsRegression(baseline, candidate *Report, p Policy) Decision {
	d := Decision{Pass: true, Violations: []Violation{}}
	if candidate == nil {
		d.fail(Violation{Rule: "candidate", Scope: "overall", Message: "no candidate report"})
		return d
	}
	g := &gate{d: &d, b: baseline, c: candidate}

	// ── absolute ──
	g.minRatio("min_recall", "overall", p.MinRecall, candidate.Metrics.Recall)
	g.maxRatio("max_fpr", "overall", p.MaxFPR, candidate.Metrics.FPR)
	if p.MaxErrors != nil && len(candidate.Errors) > *p.MaxErrors {
		g.fail("max_errors", "overall", fmt.Sprintf("%d scan error(s), at most %d allowed", len(candidate.Errors), *p.MaxErrors),
			"", fmt.Sprint(len(candidate.Errors)))
	}
	for _, name := range sortedKeys(p.PerDetector) {
		dp := p.PerDetector[name]
		scope := "detector:" + name
		st, ok := candidate.detectorStat(name)
		if !ok {
			if dp.MinRecall != nil || dp.MaxFPR != nil || dp.MaxRecallDrop != nil {
				g.fail("detector_present", scope, "detector has no stats in the candidate report", "", "")
			}
			continue
		}
		g.minRatio("min_recall", scope, dp.MinRecall, st.Metrics.Recall)
		g.maxRatio("max_fpr", scope, dp.MaxFPR, st.Metrics.FPR)
		if baseline != nil && dp.MaxRecallDrop != nil {
			if bst, ok := baseline.detectorStat(name); ok {
				g.maxDrop("max_recall_drop", scope, *dp.MaxRecallDrop, bst.Metrics.Recall, st.Metrics.Recall)
			} else {
				g.note("%s: no baseline stats, max_recall_drop skipped", scope)
			}
		}
	}
	for _, name := range sortedKeys(p.PerFamily) {
		fp := p.PerFamily[name]
		scope := "family:" + name
		fs, ok := candidate.familyStat(name)
		if !ok {
			if fp.MinRecall != nil {
				g.fail("family_present", scope, "family has no samples in the candidate report", "", "")
			}
			continue
		}
		g.minRatio("min_recall", scope, fp.MinRecall, fs.Recall)
	}

	// ── relative ──
	if baseline == nil {
		g.note("no baseline: relative rules (drops, increases, new FP/FN, perf) skipped")
		return d
	}
	diff := Diff(baseline, candidate)
	if len(diff.AddedSamples) > 0 || len(diff.RemovedSamples) > 0 {
		msg := fmt.Sprintf("corpus differs from baseline: %d sample(s) added, %d removed", len(diff.AddedSamples), len(diff.RemovedSamples))
		if p.RequireSameCorpus {
			g.fail("require_same_corpus", "corpus", msg, fmt.Sprint(len(baseline.Samples)), fmt.Sprint(len(candidate.Samples)))
		} else {
			g.note("%s; new/fixed FP/FN are computed on the common samples", msg)
		}
	}
	g.maxDrop("max_recall_drop", "overall", deref(p.MaxRecallDrop, -1), baseline.Metrics.Recall, candidate.Metrics.Recall)
	g.maxRise("max_fpr_increase", "overall", deref(p.MaxFPRIncrease, -1), baseline.Metrics.FPR, candidate.Metrics.FPR)
	g.maxDrop("max_precision_drop", "overall", deref(p.MaxPrecisionDrop, -1), baseline.Metrics.Precision, candidate.Metrics.Precision)
	if p.MaxNewFalsePositives != nil && len(diff.NewFalsePositives) > *p.MaxNewFalsePositives {
		g.fail("max_new_false_positives", "overall",
			fmt.Sprintf("%d new false positive(s), at most %d allowed: %s", len(diff.NewFalsePositives), *p.MaxNewFalsePositives, keysOf(diff.NewFalsePositives)),
			fmt.Sprint(baseline.Totals.FP), fmt.Sprint(candidate.Totals.FP))
	}
	if p.MaxNewFalseNegatives != nil && len(diff.NewFalseNegatives) > *p.MaxNewFalseNegatives {
		g.fail("max_new_false_negatives", "overall",
			fmt.Sprintf("%d new false negative(s), at most %d allowed: %s", len(diff.NewFalseNegatives), *p.MaxNewFalseNegatives, keysOf(diff.NewFalseNegatives)),
			fmt.Sprint(baseline.Totals.FN), fmt.Sprint(candidate.Totals.FN))
	}
	if p.MaxErrorIncrease != nil && len(candidate.Errors)-len(baseline.Errors) > *p.MaxErrorIncrease {
		g.fail("max_error_increase", "overall",
			fmt.Sprintf("scan errors rose by %d, at most %d allowed", len(candidate.Errors)-len(baseline.Errors), *p.MaxErrorIncrease),
			fmt.Sprint(len(baseline.Errors)), fmt.Sprint(len(candidate.Errors)))
	}

	// ── perf ──
	bp, cp := baseline.Perf, candidate.Perf
	if floor := p.Perf.floor(); bp.TotalDuration < floor {
		if p.Perf.MaxTotalDurationIncreasePct > 0 || p.Perf.MaxP95IncreasePct > 0 || p.Perf.MinThroughputRatio > 0 {
			g.note("perf rules skipped: baseline scan time %s is under the %s floor (perf.min_baseline_duration_ms)",
				bp.TotalDuration, floor)
		}
		return d
	}
	if p.Perf.MaxTotalDurationIncreasePct > 0 && bp.TotalDuration > 0 {
		pct := pctChange(float64(bp.TotalDuration), float64(cp.TotalDuration))
		if pct > p.Perf.MaxTotalDurationIncreasePct {
			g.fail("max_total_duration_increase_pct", "perf",
				fmt.Sprintf("total scan time rose %.1f%%, at most %.1f%% allowed", pct, p.Perf.MaxTotalDurationIncreasePct),
				bp.TotalDuration.String(), cp.TotalDuration.String())
		}
	}
	if p.Perf.MaxP95IncreasePct > 0 && bp.P95 > 0 {
		pct := pctChange(float64(bp.P95), float64(cp.P95))
		if pct > p.Perf.MaxP95IncreasePct {
			g.fail("max_p95_increase_pct", "perf",
				fmt.Sprintf("p95 scan time rose %.1f%%, at most %.1f%% allowed", pct, p.Perf.MaxP95IncreasePct),
				bp.P95.String(), cp.P95.String())
		}
	}
	if p.Perf.MinThroughputRatio > 0 && bp.Throughput > 0 {
		ratio := cp.Throughput / bp.Throughput
		if ratio < p.Perf.MinThroughputRatio {
			g.fail("min_throughput_ratio", "perf",
				fmt.Sprintf("throughput ratio %.2f below %.2f", ratio, p.Perf.MinThroughputRatio),
				fmt.Sprintf("%.0f B/s", bp.Throughput), fmt.Sprintf("%.0f B/s", cp.Throughput))
		}
	}
	return d
}

func (d *Decision) fail(v Violation) {
	d.Pass = false
	d.Violations = append(d.Violations, v)
}

type gate struct {
	d    *Decision
	b, c *Report
}

func (g *gate) fail(rule, scope, msg, base, cand string) {
	g.d.fail(Violation{Rule: rule, Scope: scope, Message: msg, Baseline: base, Candidate: cand})
}

func (g *gate) note(format string, args ...any) {
	g.d.Notes = append(g.d.Notes, fmt.Sprintf(format, args...))
}

func (g *gate) minRatio(rule, scope string, min *float64, r Ratio) {
	if min == nil {
		return
	}
	if !r.Defined {
		g.note("%s: %s undefined in candidate, rule skipped", scope, rule)
		return
	}
	if r.Value < *min {
		g.fail(rule, scope, fmt.Sprintf("%s below the %.2f%% minimum", percentString(r), *min*100), "", percentString(r))
	}
}

func (g *gate) maxRatio(rule, scope string, max *float64, r Ratio) {
	if max == nil {
		return
	}
	if !r.Defined {
		g.note("%s: %s undefined in candidate, rule skipped", scope, rule)
		return
	}
	if r.Value > *max {
		g.fail(rule, scope, fmt.Sprintf("%s above the %.2f%% maximum", percentString(r), *max*100), "", percentString(r))
	}
}

// maxDrop fails when cand < base - allowed. allowed < 0 disables the rule.
func (g *gate) maxDrop(rule, scope string, allowed float64, base, cand Ratio) {
	if allowed < 0 {
		return
	}
	if !base.Defined || !cand.Defined {
		g.note("%s: %s skipped (baseline %s, candidate %s)", scope, rule, base.Percent(), cand.Percent())
		return
	}
	drop := base.Value - cand.Value
	if drop > allowed+1e-12 {
		g.fail(rule, scope, fmt.Sprintf("dropped %.2f pt, at most %.2f pt allowed", drop*100, allowed*100), base.Percent(), cand.Percent())
	}
}

// maxRise fails when cand > base + allowed. allowed < 0 disables the rule.
func (g *gate) maxRise(rule, scope string, allowed float64, base, cand Ratio) {
	if allowed < 0 {
		return
	}
	if !base.Defined || !cand.Defined {
		g.note("%s: %s skipped (baseline %s, candidate %s)", scope, rule, base.Percent(), cand.Percent())
		return
	}
	rise := cand.Value - base.Value
	if rise > allowed+1e-12 {
		g.fail(rule, scope, fmt.Sprintf("rose %.2f pt, at most %.2f pt allowed", rise*100, allowed*100), base.Percent(), cand.Percent())
	}
}

func deref(p *float64, def float64) float64 {
	if p == nil {
		return def
	}
	return *p
}

func pctChange(base, cand float64) float64 {
	if base == 0 {
		return 0
	}
	return (cand - base) / base * 100
}

func keysOf(fs []FlaggedSample) string {
	const max = 5
	keys := make([]string, 0, len(fs))
	for i, f := range fs {
		if i == max {
			keys = append(keys, fmt.Sprintf("+%d more", len(fs)-max))
			break
		}
		keys = append(keys, f.Key)
	}
	return strings.Join(keys, ", ")
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
