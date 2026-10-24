package eval

import (
	"strings"
	"testing"
	"time"
)

func reportFrom(samples ...SampleResult) *Report {
	return NewReport(&Run{Info: RunInfo{Detectors: []string{"hash", "yara"}}, Samples: samples})
}

func hit(det string) Signal { return Signal{Detector: det, Rule: det + "_rule"} }

func violated(d Decision, rule string) bool {
	for _, v := range d.Violations {
		if v.Rule == rule {
			return true
		}
	}
	return false
}

func TestPolicyParse(t *testing.T) {
	p, err := ParsePolicy([]byte(`{"min_recall":0.9,"max_new_false_positives":0,"per_detector":{"yara":{"max_fpr":0.01}},"perf":{"max_p95_increase_pct":20}}`))
	if err != nil {
		t.Fatal(err)
	}
	if *p.MinRecall != 0.9 || *p.MaxNewFalsePositives != 0 || *p.PerDetector["yara"].MaxFPR != 0.01 || p.Perf.MaxP95IncreasePct != 20 {
		t.Errorf("policy = %+v", p)
	}
	if _, err := ParsePolicy([]byte(`{"min_recal":0.9}`)); err == nil {
		t.Error("unknown field accepted")
	}
	if _, err := ParsePolicy([]byte(`{"min_recall":1.5}`)); err == nil {
		t.Error("out-of-range ratio accepted")
	}
	if _, err := ParsePolicy([]byte(`{"max_errors":-1}`)); err == nil {
		t.Error("negative count accepted")
	}
	var b strings.Builder
	if err := DefaultPolicy().WriteJSON(&b); err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePolicy([]byte(b.String())); err != nil {
		t.Errorf("default policy does not round-trip: %v\n%s", err, b.String())
	}
}

func TestIsRegressionAbsoluteRules(t *testing.T) {
	cand := reportFrom(
		sample("m1", "fam", true, hit("yara")),
		sample("m2", "fam", false),
		sample("c1", LabelClean, true, hit("yara")),
		sample("c2", LabelClean, false),
		sample("c3", LabelClean, false),
		SampleResult{ID: "e1", Path: "e1", Expected: "fam", Error: "x"},
	)
	// recall 0.5, fpr 1/3, 1 error.
	p := Policy{MinRecall: fptr(0.6), MaxFPR: fptr(0.1), MaxErrors: iptr(0),
		PerDetector: map[string]DetectorPolicy{"yara": {MaxFPR: fptr(0.1)}, "hash": {MinRecall: fptr(0.1)}, "ghost": {MinRecall: fptr(0.5)}},
		PerFamily:   map[string]FamilyPolicy{"fam": {MinRecall: fptr(0.9)}, "nofam": {MinRecall: fptr(0.1)}}}
	d := IsRegression(nil, cand, p)
	if d.Pass {
		t.Fatal("expected failure")
	}
	for _, rule := range []string{"min_recall", "max_fpr", "max_errors", "detector_present", "family_present"} {
		if !violated(d, rule) {
			t.Errorf("rule %s not violated: %+v", rule, d.Violations)
		}
	}
	var scopes []string
	for _, v := range d.Violations {
		scopes = append(scopes, v.Scope+"/"+v.Rule)
	}
	joined := strings.Join(scopes, " ")
	for _, want := range []string{"detector:yara/max_fpr", "detector:hash/min_recall", "family:fam/min_recall", "overall/min_recall"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %s in %s", want, joined)
		}
	}
	if len(d.Notes) == 0 || !strings.Contains(strings.Join(d.Notes, "\n"), "no baseline") {
		t.Errorf("notes = %v, want a 'no baseline' note", d.Notes)
	}
	if err := d.Err(); err == nil || !strings.Contains(err.Error(), "violation") {
		t.Errorf("Err() = %v", err)
	}
	var b strings.Builder
	_ = d.WriteText(&b)
	if !strings.Contains(b.String(), "gate: FAIL") {
		t.Errorf("text = %s", b.String())
	}

	// Passing case and passing text.
	ok := IsRegression(nil, cand, Policy{MinRecall: fptr(0.5), MaxFPR: fptr(0.5)})
	if !ok.Pass || ok.Err() != nil {
		t.Errorf("expected pass, got %+v", ok)
	}
}

func TestIsRegressionUndefinedNeverViolates(t *testing.T) {
	cand := reportFrom(sample("c1", LabelClean, false)) // no malware: recall undefined
	d := IsRegression(nil, cand, Policy{MinRecall: fptr(1)})
	if !d.Pass {
		t.Errorf("undefined recall violated min_recall: %+v", d.Violations)
	}
	base := reportFrom(sample("m1", "fam", true, hit("yara")))
	cand2 := reportFrom(sample("m1", "fam", true, hit("yara")), sample("c1", LabelClean, false))
	// baseline FPR undefined (no benign); candidate defined: must not violate.
	d = IsRegression(base, cand2, Policy{MaxFPRIncrease: fptr(0)})
	if !d.Pass {
		t.Errorf("undefined baseline FPR violated: %+v", d.Violations)
	}
}

func TestIsRegressionRelativeRules(t *testing.T) {
	base := reportFrom(
		sample("m1", "fam", true, hit("yara")),
		sample("m2", "fam", true, hit("hash")),
		sample("c1", LabelClean, false),
		sample("c2", LabelClean, false),
		sample("c3", LabelClean, true, hit("yara")),
	)
	cand := reportFrom(
		sample("m1", "fam", true, hit("yara")),
		sample("m2", "fam", false),                  // new FN, recall drop
		sample("c1", LabelClean, true, hit("yara")), // new FP
		sample("c2", LabelClean, false),
		sample("c3", LabelClean, false),                               // fixed FP
		SampleResult{ID: "e", Path: "e", Expected: "fam", Error: "x"}, // added sample + new error
	)
	d := IsRegression(base, cand, DefaultPolicy())
	if d.Pass {
		t.Fatal("expected failure")
	}
	for _, rule := range []string{"max_recall_drop", "max_new_false_positives", "max_error_increase"} {
		if !violated(d, rule) {
			t.Errorf("rule %s not violated: %+v", rule, d.Violations)
		}
	}
	// FPR is unchanged (1/3 -> 1/3), so it must not fire.
	if violated(d, "max_fpr_increase") {
		t.Errorf("max_fpr_increase fired on unchanged FPR: %+v", d.Violations)
	}
	if !strings.Contains(strings.Join(d.Notes, "\n"), "corpus differs") {
		t.Errorf("expected a corpus-differs note, got %v", d.Notes)
	}
	// Same policy but require_same_corpus: becomes a violation.
	p := DefaultPolicy()
	p.RequireSameCorpus = true
	if d := IsRegression(base, cand, p); !violated(d, "require_same_corpus") {
		t.Errorf("require_same_corpus not enforced: %+v", d.Violations)
	}
	// Tolerances relax it.
	p = Policy{MaxRecallDrop: fptr(0.5), MaxNewFalsePositives: iptr(1), MaxNewFalseNegatives: iptr(1), MaxErrorIncrease: iptr(1), MaxPrecisionDrop: fptr(1)}
	if d := IsRegression(base, cand, p); !d.Pass {
		t.Errorf("relaxed policy failed: %+v", d.Violations)
	}
	// Per-detector drop: hash went 1/2 -> 0/2.
	p = Policy{PerDetector: map[string]DetectorPolicy{"hash": {MaxRecallDrop: fptr(0.1)}, "yara": {MaxRecallDrop: fptr(0.1)}}}
	d = IsRegression(base, cand, p)
	if !violated(d, "max_recall_drop") || d.Violations[0].Scope != "detector:hash" {
		t.Errorf("per-detector drop: %+v", d.Violations)
	}
}

func TestIsRegressionPerf(t *testing.T) {
	mk := func(d time.Duration, size int64) *Report {
		return NewReport(&Run{Samples: []SampleResult{{ID: "a", Expected: LabelClean, Scored: true, Duration: d, Size: size}}})
	}
	base, cand := mk(2*time.Second, 1000), mk(4*time.Second, 1000)
	d := IsRegression(base, cand, DefaultPolicy())
	if !violated(d, "max_total_duration_increase_pct") {
		t.Errorf("perf budget not enforced: %+v", d)
	}
	d = IsRegression(base, cand, Policy{Perf: PerfPolicy{MaxP95IncreasePct: 10, MinThroughputRatio: 0.9}})
	if !violated(d, "max_p95_increase_pct") || !violated(d, "min_throughput_ratio") {
		t.Errorf("p95/throughput not enforced: %+v", d)
	}
	if d := IsRegression(base, mk(2400*time.Millisecond, 1000), DefaultPolicy()); !d.Pass {
		t.Errorf("20%% slower failed the 50%% budget: %+v", d)
	}
	// Under the duration floor, relative perf rules are noise and are skipped.
	tiny := IsRegression(mk(time.Millisecond, 1000), mk(10*time.Millisecond, 1000), DefaultPolicy())
	if !tiny.Pass || len(tiny.Notes) == 0 {
		t.Errorf("sub-floor perf change must not fail: %+v", tiny)
	}
	strict := Policy{Perf: PerfPolicy{MaxTotalDurationIncreasePct: 50, MinBaselineDurationMs: -1}}
	if d := IsRegression(mk(time.Millisecond, 1000), mk(10*time.Millisecond, 1000), strict); d.Pass {
		t.Error("negative floor must apply perf rules at any scale")
	}
	if d := IsRegression(nil, cand, Policy{}); !d.Pass {
		t.Errorf("nil candidate policy: %+v", d)
	}
	if d := IsRegression(base, nil, Policy{}); d.Pass {
		t.Error("nil candidate passed")
	}
}
