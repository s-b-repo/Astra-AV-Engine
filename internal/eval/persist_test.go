package eval

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReportRoundTripAndStability(t *testing.T) {
	m := writeCorpus(t, 12)
	fixed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mk := func() *Report {
		run, err := NewRunner([]Detector{nameDetector("a", true), nameDetector("b", true)},
			RunOptions{Concurrency: 4, Now: func() time.Time { return fixed }}).Run(m)
		if err != nil {
			t.Fatal(err)
		}
		stripDurations(run)
		return NewReport(run)
	}
	var a, b bytes.Buffer
	if err := mk().WriteJSON(&a, true); err != nil {
		t.Fatal(err)
	}
	if err := mk().WriteJSON(&b, true); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Fatalf("two runs of the same corpus produced different JSON:\n%s\n---\n%s", a.String(), b.String())
	}

	path := filepath.Join(t.TempDir(), "baseline.json")
	if err := os.WriteFile(path, a.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadReport(path)
	if err != nil {
		t.Fatal(err)
	}
	var c bytes.Buffer
	if err := loaded.WriteJSON(&c, true); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Bytes(), c.Bytes()) {
		t.Fatalf("report changed through a load/save round trip:\n%s\n---\n%s", a.String(), c.String())
	}
	if d := Diff(mk(), loaded); len(d.NewFalsePositives)+len(d.NewFalseNegatives)+len(d.AddedSamples)+len(d.RemovedSamples) != 0 {
		t.Errorf("self-diff is not empty: %+v", d)
	}

	if _, err := ParseReport([]byte(`{"schema_version":"99"}`)); err == nil || !strings.Contains(err.Error(), "schema_version") {
		t.Errorf("wrong schema accepted: %v", err)
	}
	if _, err := ParseReport([]byte(`not json`)); err == nil {
		t.Error("garbage accepted")
	}

	var text strings.Builder
	if err := loaded.WriteText(&text); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"confusion matrix", "per detector", "recall", "perf", "a_rule"} {
		if !strings.Contains(text.String(), want) {
			t.Errorf("text report lacks %q:\n%s", want, text.String())
		}
	}
}

func TestSmokeCorpusManifestValidates(t *testing.T) {
	m, err := LoadManifest(filepath.Join("..", "..", "corpus", "smoke", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	v := m.Validate(ValidateOptions{VerifyHashes: true, RequireProvenance: true})
	if !v.OK() {
		t.Fatalf("smoke corpus has errors:\n%s", v)
	}
	if v.Malware != 7 || v.Benign != 10 {
		t.Errorf("smoke corpus: %d malware, %d benign, want 7/10\n%s", v.Malware, v.Benign, v)
	}
	// The empty benign file is a warning, by design.
	var sawEmpty bool
	for _, i := range v.Warnings() {
		if strings.Contains(i.Message, "empty") {
			sawEmpty = true
		}
	}
	if !sawEmpty {
		t.Errorf("expected an empty-sample warning, got %v", v.Warnings())
	}
	for _, s := range m.Samples {
		if s.SHA256 == "" || s.ID == "" || s.Provenance.Source != "synthetic" || s.Provenance.License != "MIT" {
			t.Errorf("sample %s is under-specified: %+v", s.Path, s)
		}
	}
}
