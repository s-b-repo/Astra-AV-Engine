package eval

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

// RatioDelta is one metric before and after, with the change in the metric's
// own unit (0.01 = one percentage point). Delta is undefined unless both sides
// are defined.
type RatioDelta struct {
	Baseline  Ratio `json:"baseline"`
	Candidate Ratio `json:"candidate"`
	Delta     Ratio `json:"delta"`
}

func ratioDelta(b, c Ratio) RatioDelta {
	d := RatioDelta{Baseline: b, Candidate: c}
	if b.Defined && c.Defined {
		d.Delta = DefinedRatio(c.Value - b.Value)
	}
	return d
}

// RatiosDelta is RatioDelta for every headline metric.
type RatiosDelta struct {
	Precision   RatioDelta `json:"precision"`
	Recall      RatioDelta `json:"recall"`
	F1          RatioDelta `json:"f1"`
	Specificity RatioDelta `json:"specificity"`
	FPR         RatioDelta `json:"fpr"`
	Accuracy    RatioDelta `json:"accuracy"`
}

func ratiosDelta(b, c Ratios) RatiosDelta {
	return RatiosDelta{
		Precision:   ratioDelta(b.Precision, c.Precision),
		Recall:      ratioDelta(b.Recall, c.Recall),
		F1:          ratioDelta(b.F1, c.F1),
		Specificity: ratioDelta(b.Specificity, c.Specificity),
		FPR:         ratioDelta(b.FPR, c.FPR),
		Accuracy:    ratioDelta(b.Accuracy, c.Accuracy),
	}
}

// CountsDelta is a confusion matrix before, after, and the difference.
type CountsDelta struct {
	Baseline  Counts `json:"baseline"`
	Candidate Counts `json:"candidate"`
	Delta     Counts `json:"delta"`
}

func countsDelta(b, c Counts) CountsDelta {
	return CountsDelta{Baseline: b, Candidate: c, Delta: Counts{TP: c.TP - b.TP, FP: c.FP - b.FP, TN: c.TN - b.TN, FN: c.FN - b.FN}}
}

// DetectorDelta compares one detector across runs. Status is "added",
// "removed" or "" (present in both).
type DetectorDelta struct {
	Detector string      `json:"detector"`
	Status   string      `json:"status,omitempty"`
	Counts   CountsDelta `json:"counts"`
	Metrics  RatiosDelta `json:"metrics"`
}

// FamilyDelta compares one family across runs.
type FamilyDelta struct {
	Family            string     `json:"family"`
	Status            string     `json:"status,omitempty"`
	Recall            RatioDelta `json:"recall"`
	BaselineMissed    int        `json:"baseline_missed"`
	CandidateMissed   int        `json:"candidate_missed"`
	BaselineFalsePos  int        `json:"baseline_false_positives"`
	CandidateFalsePos int        `json:"candidate_false_positives"`
}

// RuleDelta compares one rule across runs.
type RuleDelta struct {
	Rule              string `json:"rule"`
	Status            string `json:"status,omitempty"`
	BaselineFires     int    `json:"baseline_fires"`
	CandidateFires    int    `json:"candidate_fires"`
	BaselineTruePos   int    `json:"baseline_true_positives"`
	CandidateTruePos  int    `json:"candidate_true_positives"`
	BaselineFalsePos  int    `json:"baseline_false_positives"`
	CandidateFalsePos int    `json:"candidate_false_positives"`
}

// PerfDelta compares the perf sections.
type PerfDelta struct {
	Baseline               Perf    `json:"baseline"`
	Candidate              Perf    `json:"candidate"`
	TotalDurationChangePct float64 `json:"total_duration_change_pct"`
	P95ChangePct           float64 `json:"p95_change_pct"`
	ThroughputRatio        float64 `json:"throughput_ratio"`
}

// ReportDiff is the structured comparison of two reports. Per-sample lists
// are computed on the samples common to both runs; AddedSamples and
// RemovedSamples name the rest. Durations are compared only in Perf.
type ReportDiff struct {
	BaselineInfo  RunInfo `json:"baseline_run"`
	CandidateInfo RunInfo `json:"candidate_run"`

	Totals  CountsDelta `json:"totals"`
	Metrics RatiosDelta `json:"metrics"`

	ByDetector []DetectorDelta `json:"by_detector"`
	ByFamily   []FamilyDelta   `json:"by_family"`
	ByRule     []RuleDelta     `json:"by_rule"`

	NewFalsePositives   []FlaggedSample `json:"new_false_positives"`
	FixedFalsePositives []FlaggedSample `json:"fixed_false_positives"`
	NewFalseNegatives   []FlaggedSample `json:"new_false_negatives"`
	FixedFalseNegatives []FlaggedSample `json:"fixed_false_negatives"`
	NewErrors           []SampleError   `json:"new_errors"`
	FixedErrors         []SampleError   `json:"fixed_errors"`

	AddedSamples   []string `json:"added_samples"`
	RemovedSamples []string `json:"removed_samples"`
	CommonSamples  int      `json:"common_samples"`

	Perf PerfDelta `json:"perf"`
}

// Diff compares candidate against baseline. Both must be non-nil.
func Diff(baseline, candidate *Report) *ReportDiff {
	if baseline == nil {
		baseline = &Report{}
	}
	if candidate == nil {
		candidate = &Report{}
	}
	d := &ReportDiff{
		BaselineInfo:        baseline.Info,
		CandidateInfo:       candidate.Info,
		Totals:              countsDelta(baseline.Totals, candidate.Totals),
		Metrics:             ratiosDelta(baseline.Metrics, candidate.Metrics),
		NewFalsePositives:   []FlaggedSample{},
		FixedFalsePositives: []FlaggedSample{},
		NewFalseNegatives:   []FlaggedSample{},
		FixedFalseNegatives: []FlaggedSample{},
		NewErrors:           []SampleError{},
		FixedErrors:         []SampleError{},
		AddedSamples:        []string{},
		RemovedSamples:      []string{},
	}

	// ── samples ──
	bs, cs := baseline.sampleByKey(), candidate.sampleByKey()
	for k := range cs {
		if _, ok := bs[k]; !ok {
			d.AddedSamples = append(d.AddedSamples, k)
		}
	}
	for k := range bs {
		if _, ok := cs[k]; !ok {
			d.RemovedSamples = append(d.RemovedSamples, k)
		}
	}
	sort.Strings(d.AddedSamples)
	sort.Strings(d.RemovedSamples)

	common := func(k string) bool {
		_, inB := bs[k]
		_, inC := cs[k]
		return inB && inC
	}
	d.CommonSamples = len(cs) - len(d.AddedSamples)

	bFP, cFP := flaggedByKey(baseline.FalsePositives), flaggedByKey(candidate.FalsePositives)
	bFN, cFN := flaggedByKey(baseline.FalseNegatives), flaggedByKey(candidate.FalseNegatives)
	for k, f := range cFP {
		if _, was := bFP[k]; !was && common(k) {
			d.NewFalsePositives = append(d.NewFalsePositives, f)
		}
	}
	for k, f := range bFP {
		if _, still := cFP[k]; !still && common(k) {
			d.FixedFalsePositives = append(d.FixedFalsePositives, f)
		}
	}
	for k, f := range cFN {
		if _, was := bFN[k]; !was && common(k) {
			d.NewFalseNegatives = append(d.NewFalseNegatives, f)
		}
	}
	for k, f := range bFN {
		if _, still := cFN[k]; !still && common(k) {
			d.FixedFalseNegatives = append(d.FixedFalseNegatives, f)
		}
	}
	sortFlagged(d.NewFalsePositives)
	sortFlagged(d.FixedFalsePositives)
	sortFlagged(d.NewFalseNegatives)
	sortFlagged(d.FixedFalseNegatives)

	bErr, cErr := errorsByKey(baseline.Errors), errorsByKey(candidate.Errors)
	for k, e := range cErr {
		if _, was := bErr[k]; !was && common(k) {
			d.NewErrors = append(d.NewErrors, e)
		}
	}
	for k, e := range bErr {
		if _, still := cErr[k]; !still && common(k) {
			d.FixedErrors = append(d.FixedErrors, e)
		}
	}
	sort.Slice(d.NewErrors, func(i, j int) bool { return d.NewErrors[i].Key < d.NewErrors[j].Key })
	sort.Slice(d.FixedErrors, func(i, j int) bool { return d.FixedErrors[i].Key < d.FixedErrors[j].Key })

	// ── detectors ──
	bd, cd := map[string]DetectorStat{}, map[string]DetectorStat{}
	for _, s := range baseline.ByDetector {
		bd[s.Detector] = s
	}
	for _, s := range candidate.ByDetector {
		cd[s.Detector] = s
	}
	for _, name := range unionKeys(bd, cd) {
		b, inB := bd[name]
		c, inC := cd[name]
		dd := DetectorDelta{Detector: name, Counts: countsDelta(b.Counts, c.Counts), Metrics: ratiosDelta(b.Metrics, c.Metrics)}
		dd.Status = status(inB, inC)
		d.ByDetector = append(d.ByDetector, dd)
	}

	// ── families ──
	bf, cf := map[string]FamilyStat{}, map[string]FamilyStat{}
	for _, s := range baseline.ByFamily {
		bf[s.Family] = s
	}
	for _, s := range candidate.ByFamily {
		cf[s.Family] = s
	}
	for _, name := range unionKeys(bf, cf) {
		b, inB := bf[name]
		c, inC := cf[name]
		d.ByFamily = append(d.ByFamily, FamilyDelta{
			Family: name, Status: status(inB, inC), Recall: ratioDelta(b.Recall, c.Recall),
			BaselineMissed: b.Missed, CandidateMissed: c.Missed,
			BaselineFalsePos: b.FalsePositives, CandidateFalsePos: c.FalsePositives,
		})
	}

	// ── rules ──
	br, cr := map[string]RuleStat{}, map[string]RuleStat{}
	for _, s := range baseline.ByRule {
		br[s.Rule] = s
	}
	for _, s := range candidate.ByRule {
		cr[s.Rule] = s
	}
	for _, name := range unionKeys(br, cr) {
		b, inB := br[name]
		c, inC := cr[name]
		d.ByRule = append(d.ByRule, RuleDelta{
			Rule: name, Status: status(inB, inC),
			BaselineFires: b.Fires, CandidateFires: c.Fires,
			BaselineTruePos: b.TruePositives, CandidateTruePos: c.TruePositives,
			BaselineFalsePos: b.FalsePositives, CandidateFalsePos: c.FalsePositives,
		})
	}
	sort.SliceStable(d.ByRule, func(i, j int) bool {
		di := d.ByRule[i].CandidateFalsePos - d.ByRule[i].BaselineFalsePos
		dj := d.ByRule[j].CandidateFalsePos - d.ByRule[j].BaselineFalsePos
		if di != dj {
			return di > dj // most new FPs first
		}
		return d.ByRule[i].Rule < d.ByRule[j].Rule
	})

	// ── perf ──
	bp, cp := baseline.Perf, candidate.Perf
	d.Perf = PerfDelta{
		Baseline: bp, Candidate: cp,
		TotalDurationChangePct: pctChange(float64(bp.TotalDuration), float64(cp.TotalDuration)),
		P95ChangePct:           pctChange(float64(bp.P95), float64(cp.P95)),
	}
	if bp.Throughput > 0 {
		d.Perf.ThroughputRatio = cp.Throughput / bp.Throughput
	}
	return d
}

func status(inB, inC bool) string {
	switch {
	case inB && !inC:
		return "removed"
	case !inB && inC:
		return "added"
	}
	return ""
}

func flaggedByKey(fs []FlaggedSample) map[string]FlaggedSample {
	out := make(map[string]FlaggedSample, len(fs))
	for _, f := range fs {
		out[f.Key] = f
	}
	return out
}

func errorsByKey(es []SampleError) map[string]SampleError {
	out := make(map[string]SampleError, len(es))
	for _, e := range es {
		out[e.Key] = e
	}
	return out
}

func unionKeys[V any](a, b map[string]V) []string {
	seen := map[string]struct{}{}
	for k := range a {
		seen[k] = struct{}{}
	}
	for k := range b {
		seen[k] = struct{}{}
	}
	return sortedKeys(seen)
}

// Summary is the one-line verdict: "recall +0.40 pt, false positives 2 → 6 (3.0x)".
func (d *ReportDiff) Summary() string {
	var parts []string
	parts = append(parts, "recall "+pointsDiff(d.Metrics.Recall.Delta))
	parts = append(parts, "precision "+pointsDiff(d.Metrics.Precision.Delta))
	parts = append(parts, fmt.Sprintf("false positives %d → %d%s", d.Totals.Baseline.FP, d.Totals.Candidate.FP, factor(d.Totals.Baseline.FP, d.Totals.Candidate.FP)))
	parts = append(parts, fmt.Sprintf("false negatives %d → %d", d.Totals.Baseline.FN, d.Totals.Candidate.FN))
	if d.Perf.Baseline.TotalDuration > 0 {
		parts = append(parts, fmt.Sprintf("scan time %+.1f%%", d.Perf.TotalDurationChangePct))
	}
	return strings.Join(parts, ", ")
}

func factor(b, c int) string {
	if b == 0 || c == 0 || b == c {
		return ""
	}
	return fmt.Sprintf(" (%.1fx)", float64(c)/float64(b))
}

// WriteText renders the diff for a PR comment or a terminal.
func (d *ReportDiff) WriteText(w io.Writer) error {
	fmt.Fprintf(w, "eval diff: %s\n", d.Summary())
	fmt.Fprintf(w, "  baseline : %s\n  candidate: %s\n", describeRun(d.BaselineInfo), describeRun(d.CandidateInfo))
	if len(d.AddedSamples) > 0 || len(d.RemovedSamples) > 0 {
		fmt.Fprintf(w, "  corpus   : %d common, %d added, %d removed\n", d.CommonSamples, len(d.AddedSamples), len(d.RemovedSamples))
	}

	fmt.Fprintln(w, "\nconfusion matrix        baseline  candidate   delta")
	fmt.Fprintf(w, "  true positives        %8d  %9d  %+6d\n", d.Totals.Baseline.TP, d.Totals.Candidate.TP, d.Totals.Delta.TP)
	fmt.Fprintf(w, "  false positives       %8d  %9d  %+6d\n", d.Totals.Baseline.FP, d.Totals.Candidate.FP, d.Totals.Delta.FP)
	fmt.Fprintf(w, "  true negatives        %8d  %9d  %+6d\n", d.Totals.Baseline.TN, d.Totals.Candidate.TN, d.Totals.Delta.TN)
	fmt.Fprintf(w, "  false negatives       %8d  %9d  %+6d\n", d.Totals.Baseline.FN, d.Totals.Candidate.FN, d.Totals.Delta.FN)

	fmt.Fprintln(w, "\nmetrics                 baseline  candidate   delta")
	writeRatioRow(w, "precision", d.Metrics.Precision)
	writeRatioRow(w, "recall", d.Metrics.Recall)
	writeRatioRow(w, "f1", d.Metrics.F1)
	writeRatioRow(w, "fpr", d.Metrics.FPR)
	writeRatioRow(w, "accuracy", d.Metrics.Accuracy)

	if len(d.ByDetector) > 0 {
		fmt.Fprintln(w, "\nper detector            recall (b → c)          fpr (b → c)")
		for _, dd := range d.ByDetector {
			fmt.Fprintf(w, "  %-20s  %8s → %-8s %7s  %8s → %-8s %7s %s\n", dd.Detector,
				dd.Metrics.Recall.Baseline.Percent(), dd.Metrics.Recall.Candidate.Percent(), pointsDiff(dd.Metrics.Recall.Delta),
				dd.Metrics.FPR.Baseline.Percent(), dd.Metrics.FPR.Candidate.Percent(), pointsDiff(dd.Metrics.FPR.Delta), tag(dd.Status))
		}
	}
	if changed := changedFamilies(d.ByFamily); len(changed) > 0 {
		fmt.Fprintln(w, "\nfamilies that changed   recall (b → c)")
		for _, fd := range changed {
			fmt.Fprintf(w, "  %-20s  %8s → %-8s %7s  missed %d → %d, blamed on benign %d → %d %s\n", fd.Family,
				fd.Recall.Baseline.Percent(), fd.Recall.Candidate.Percent(), pointsDiff(fd.Recall.Delta),
				fd.BaselineMissed, fd.CandidateMissed, fd.BaselineFalsePos, fd.CandidateFalsePos, tag(fd.Status))
		}
	}
	if changed := changedRules(d.ByRule); len(changed) > 0 {
		fmt.Fprintln(w, "\nrules that changed      fires      tp         fp")
		for _, rd := range changed {
			fmt.Fprintf(w, "  %-20s  %3d → %-3d  %3d → %-3d  %3d → %-3d %s\n", rd.Rule,
				rd.BaselineFires, rd.CandidateFires, rd.BaselineTruePos, rd.CandidateTruePos, rd.BaselineFalsePos, rd.CandidateFalsePos, tag(rd.Status))
		}
	}

	writeFlaggedList(w, "new false positives", d.NewFalsePositives, 50)
	writeFlaggedList(w, "fixed false positives", d.FixedFalsePositives, 50)
	writeFlaggedList(w, "new false negatives", d.NewFalseNegatives, 50)
	writeFlaggedList(w, "fixed false negatives", d.FixedFalseNegatives, 50)
	if len(d.NewErrors) > 0 {
		fmt.Fprintf(w, "\nnew scan errors (%d)\n", len(d.NewErrors))
		for _, e := range d.NewErrors {
			fmt.Fprintf(w, "  %s: %s\n", e.Key, e.Message)
		}
	}
	if len(d.FixedErrors) > 0 {
		fmt.Fprintf(w, "\nfixed scan errors (%d)\n", len(d.FixedErrors))
		for _, e := range d.FixedErrors {
			fmt.Fprintf(w, "  %s\n", e.Key)
		}
	}

	fmt.Fprintln(w, "\nperf                    baseline  candidate")
	fmt.Fprintf(w, "  total scan time       %8s  %9s  %+.1f%%\n", d.Perf.Baseline.TotalDuration.Round(time.Microsecond), d.Perf.Candidate.TotalDuration.Round(time.Microsecond), d.Perf.TotalDurationChangePct)
	fmt.Fprintf(w, "  p95 per sample        %8s  %9s  %+.1f%%\n", d.Perf.Baseline.P95.Round(time.Microsecond), d.Perf.Candidate.P95.Round(time.Microsecond), d.Perf.P95ChangePct)
	fmt.Fprintf(w, "  throughput            %8s  %9s  ratio %.2f\n", humanBytes(d.Perf.Baseline.Throughput)+"/s", humanBytes(d.Perf.Candidate.Throughput)+"/s", d.Perf.ThroughputRatio)
	return nil
}

func tag(status string) string {
	if status == "" {
		return ""
	}
	return "[" + status + "]"
}

func changedFamilies(in []FamilyDelta) []FamilyDelta {
	var out []FamilyDelta
	for _, f := range in {
		if f.Status != "" || f.BaselineMissed != f.CandidateMissed || f.BaselineFalsePos != f.CandidateFalsePos ||
			(f.Recall.Delta.Defined && f.Recall.Delta.Value != 0) {
			out = append(out, f)
		}
	}
	return out
}

func changedRules(in []RuleDelta) []RuleDelta {
	var out []RuleDelta
	for _, r := range in {
		if r.Status != "" || r.BaselineFires != r.CandidateFires || r.BaselineTruePos != r.CandidateTruePos || r.BaselineFalsePos != r.CandidateFalsePos {
			out = append(out, r)
		}
	}
	return out
}

func writeRatioRow(w io.Writer, name string, rd RatioDelta) {
	fmt.Fprintf(w, "  %-20s  %8s  %9s  %s\n", name, rd.Baseline.Percent(), rd.Candidate.Percent(), pointsDiff(rd.Delta))
}

func writeFlaggedList(w io.Writer, title string, fs []FlaggedSample, max int) {
	if len(fs) == 0 {
		return
	}
	fmt.Fprintf(w, "\n%s (%d)\n", title, len(fs))
	for i, f := range fs {
		if i == max {
			fmt.Fprintf(w, "  +%d more\n", len(fs)-max)
			break
		}
		fmt.Fprintf(w, "  %s", f.Key)
		if f.Path != f.Key {
			fmt.Fprintf(w, "  (%s)", f.Path)
		}
		fmt.Fprintf(w, "  expected %s", f.Expected)
		if len(f.Detectors) > 0 {
			fmt.Fprintf(w, "  fired: %s", strings.Join(f.Detectors, ","))
		}
		if rules := ruleNames(f.Signals); len(rules) > 0 {
			fmt.Fprintf(w, "  rules: %s", strings.Join(rules, ","))
		}
		if f.Notes != "" {
			fmt.Fprintf(w, "  [%s]", f.Notes)
		}
		fmt.Fprintln(w)
	}
}

func ruleNames(sigs []Signal) []string {
	var out []string
	for _, s := range sigs {
		out = addUnique(out, s.Rule)
	}
	sort.Strings(out)
	if len(out) > 5 {
		out = append(out[:5], fmt.Sprintf("+%d", len(out)-5))
	}
	return out
}

func describeRun(info RunInfo) string {
	parts := []string{}
	if info.Tool != "" {
		parts = append(parts, info.Tool)
	}
	if !info.GeneratedAt.IsZero() {
		parts = append(parts, info.GeneratedAt.UTC().Format(time.RFC3339))
	}
	if info.CorpusName != "" {
		parts = append(parts, "corpus "+info.CorpusName)
	} else if info.Corpus != "" {
		parts = append(parts, "corpus "+info.Corpus)
	}
	if len(info.Detectors) > 0 {
		parts = append(parts, "detectors "+strings.Join(info.Detectors, "+"))
	}
	if len(parts) == 0 {
		return "(no run info)"
	}
	return strings.Join(parts, ", ")
}

func humanBytes(v float64) string {
	units := []string{"B", "KiB", "MiB", "GiB"}
	i := 0
	for v >= 1024 && i < len(units)-1 {
		v /= 1024
		i++
	}
	return fmt.Sprintf("%.1f %s", v, units[i])
}
