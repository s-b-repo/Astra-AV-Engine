package eval

import (
	"encoding/json"
	"strings"
	"testing"
)

func keys(fs []FlaggedSample) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.Key)
	}
	return out
}

func TestDiff(t *testing.T) {
	base := reportFrom(
		sample("m1", "fam", true, hit("yara")),
		sample("m2", "fam", true, hit("yara")),
		sample("m3", "fam", false),
		sample("c1", LabelClean, false),
		sample("c2", LabelClean, true, hit("yara")),
		sample("gone", LabelClean, false),
	)
	cand := reportFrom(
		sample("m1", "fam", true, hit("yara")),
		sample("m2", "fam", false),                                            // new FN
		sample("m3", "fam", true, Signal{Detector: "yara", Rule: "new_rule"}), // fixed FN
		sample("c1", LabelClean, true, hit("hash")),                           // new FP
		sample("c2", LabelClean, false),                                       // fixed FP
		sample("added", LabelClean, true, hit("hash")),                        // added sample: not a "new FP"
	)
	d := Diff(base, cand)
	if got := keys(d.NewFalsePositives); strings.Join(got, ",") != "c1" {
		t.Errorf("new FP = %v", got)
	}
	if got := keys(d.FixedFalsePositives); strings.Join(got, ",") != "c2" {
		t.Errorf("fixed FP = %v", got)
	}
	if got := keys(d.NewFalseNegatives); strings.Join(got, ",") != "m2" {
		t.Errorf("new FN = %v", got)
	}
	if got := keys(d.FixedFalseNegatives); strings.Join(got, ",") != "m3" {
		t.Errorf("fixed FN = %v", got)
	}
	if strings.Join(d.AddedSamples, ",") != "added" || strings.Join(d.RemovedSamples, ",") != "gone" || d.CommonSamples != 5 {
		t.Errorf("added=%v removed=%v common=%d", d.AddedSamples, d.RemovedSamples, d.CommonSamples)
	}
	if d.Totals.Delta.FP != 1 || d.Totals.Delta.TP != 0 {
		t.Errorf("totals delta = %+v", d.Totals.Delta)
	}
	if !d.Metrics.Recall.Delta.Defined || d.Metrics.Recall.Delta.Value != 0 {
		t.Errorf("recall delta = %v", d.Metrics.Recall.Delta)
	}
	var newRule, hashAdded bool
	for _, r := range d.ByRule {
		if r.Rule == "new_rule" && r.Status == "added" {
			newRule = true
		}
	}
	for _, dd := range d.ByDetector {
		if dd.Detector == "hash" && dd.Counts.Delta.FP == 2 {
			hashAdded = true
		}
	}
	if !newRule || !hashAdded {
		t.Errorf("rule/detector deltas: %+v / %+v", d.ByRule, d.ByDetector)
	}

	var b strings.Builder
	if err := d.WriteText(&b); err != nil {
		t.Fatal(err)
	}
	text := b.String()
	for _, want := range []string{"eval diff:", "false positives 1 → 2 (2.0x)", "new false positives (1)", "fixed false negatives (1)", "1 added, 1 removed", "new_rule", "[added]"} {
		if !strings.Contains(text, want) {
			t.Errorf("diff text lacks %q:\n%s", want, text)
		}
	}
	if _, err := json.Marshal(d); err != nil {
		t.Fatal(err)
	}

	// Summary shows a multiplier when FPs grow.
	d2 := Diff(reportFrom(sample("c1", LabelClean, true, hit("yara")), sample("c2", LabelClean, false), sample("c3", LabelClean, false)),
		reportFrom(sample("c1", LabelClean, true, hit("yara")), sample("c2", LabelClean, true, hit("yara")), sample("c3", LabelClean, true, hit("yara"))))
	if s := d2.Summary(); !strings.Contains(s, "false positives 1 → 3 (3.0x)") {
		t.Errorf("summary = %s", s)
	}
	if Diff(nil, nil) == nil {
		t.Error("Diff(nil,nil) must not panic or return nil")
	}
}
