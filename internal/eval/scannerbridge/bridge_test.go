package scannerbridge

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/cau-edr/cau/internal/eval"
	"github.com/cau-edr/cau/scanner"
)

const (
	smokeManifest = "../../../corpus/smoke/manifest.json"
	smokeHashes   = "../../../corpus/smoke/hashes.txt"
	repoRules     = "../../../rules/rule_list.yar"
)

func loadEngine(t *testing.T) ([]eval.Detector, *eval.Manifest) {
	t.Helper()
	m, err := eval.LoadManifest(smokeManifest)
	if err != nil {
		t.Fatal(err)
	}
	if v := m.Validate(eval.ValidateOptions{VerifyHashes: true}); !v.OK() {
		t.Fatalf("smoke corpus invalid:\n%s", v)
	}
	db, err := scanner.LoadSignatures(smokeHashes)
	if err != nil {
		t.Fatal(err)
	}
	ys, _, err := scanner.LoadYaraRules(repoRules, scanner.WithWarnFunc(func(string, ...interface{}) {}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ys.Close() })
	return Engine(db, ys, 0), m
}

func TestEngineOnSmokeCorpus(t *testing.T) {
	dets, m := loadEngine(t)
	run, err := eval.NewRunner(dets, eval.RunOptions{Concurrency: 4, Tool: "bridge-test"}).Run(m)
	if err != nil {
		t.Fatal(err)
	}
	rep := eval.NewReport(run)
	var text strings.Builder
	_ = rep.WriteText(&text)
	t.Log(text.String())

	if !rep.Metrics.Recall.Defined || rep.Metrics.Recall.Value != 1 {
		t.Errorf("recall = %v, want 1.0; false negatives: %+v", rep.Metrics.Recall, rep.FalseNegatives)
	}
	if rep.Totals.FP != 0 {
		t.Errorf("false positives = %d: %+v", rep.Totals.FP, rep.FalsePositives)
	}
	if len(rep.Errors) != 0 {
		t.Errorf("errors: %+v", rep.Errors)
	}
	if rep.Totals != (eval.Counts{TP: 5, TN: 4}) {
		t.Errorf("totals = %s", rep.Totals)
	}

	fired := map[string]bool{}
	for _, rs := range rep.ByRule {
		fired[rs.Rule] = true
		if rs.FalsePositives != 0 {
			t.Errorf("rule %s fired on benign samples: %v", rs.Rule, rs.FalsePositivePaths)
		}
	}
	for _, want := range []string{"wannacry_ransomware", "mimikatz_strings", "lokibot_stealer", "generic_ransomware_extensions", "Smoke_Hash Synthetic Sample"} {
		if !fired[want] {
			t.Errorf("rule %q did not fire; fired: %v", want, fired)
		}
	}
	for _, d := range rep.ByDetector {
		switch d.Detector {
		case eval.DetectorHash:
			if d.Counts.TP != 1 || d.Exclusive != 1 {
				t.Errorf("hash detector: %+v", d)
			}
		case eval.DetectorYara:
			if d.Counts.TP != 4 || d.Exclusive < 3 { // heuristics also catch the mimikatz sample
				t.Errorf("yara detector: %+v", d)
			}
		case eval.DetectorHeuristic:
			if d.Counts.FP != 0 {
				t.Errorf("heuristic detector flagged benign files: %+v", d)
			}
		}
	}
	// Per-family breakdown is populated from the manifest families.
	if len(rep.ByFamily) != 5 {
		t.Errorf("families = %+v", rep.ByFamily)
	}
}

func TestDetectorsRefuseEmptyConfig(t *testing.T) {
	if _, err := HashDetector(nil).ScanFile("x"); err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Errorf("nil db: %v", err)
	}
	if _, err := YaraDetector(nil).ScanFile("x"); err == nil {
		t.Error("nil yara scanner accepted")
	}
	if got := len(Engine(nil, nil, -1)); got != 0 {
		t.Errorf("Engine(nil,nil,-1) = %d detectors", got)
	}
	if got := len(Engine(nil, nil, 0)); got != 1 {
		t.Errorf("Engine(nil,nil,0) = %d detectors, want heuristic only", got)
	}
}

func TestYaraSignalNaming(t *testing.T) {
	ys, _, err := scanner.LoadYaraRuleFiles([]scanner.RuleSource{
		{Text: "rule ns_rule { meta: family = \"Fam\" threat_level = 4 strings: $a = \"BRIDGE_NS\" condition: $a }", Namespace: "custom"},
		{Text: "rule plain_rule { strings: $a = \"BRIDGE_PLAIN\" condition: $a }"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ys.Close()
	dir := t.TempDir()
	path := filepath.Join(dir, "s.bin")
	if err := writeFile(path, "BRIDGE_NS BRIDGE_PLAIN"); err != nil {
		t.Fatal(err)
	}
	f, err := YaraDetector(ys).ScanFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]eval.Signal{}
	for _, s := range f.Signals {
		got[s.Rule] = s
	}
	if s, ok := got["custom/ns_rule"]; !ok || s.Family != "fam" || !strings.Contains(s.Detail, "threat_level=4") {
		t.Errorf("namespaced signal = %+v (all: %+v)", s, f.Signals)
	}
	if _, ok := got["plain_rule"]; !ok {
		t.Errorf("default-namespace rule not plain: %+v", f.Signals)
	}
	if f.Duration <= 0 {
		t.Error("duration not measured")
	}
}
