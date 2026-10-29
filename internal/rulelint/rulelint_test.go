package rulelint

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, dir, name, src string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func codes(r *Report) map[string][]Finding {
	out := map[string][]Finding{}
	for _, f := range r.Findings {
		out[f.Code] = append(out[f.Code], f)
	}
	return out
}

const good = `
rule good_rule
{
    meta:
        author = "CAU"
        description = "A complete rule"
        family = "test"
        threat_level = 3
        mitre_attack = "T1486"
    strings:
        $a = "a long enough string" ascii wide
        $b = { 4D 5A 90 00 }
    condition:
        $a and $b
}
`

func TestCleanRulePasses(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "good.yar", good)
	rep, err := Lint(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Findings) != 0 || rep.Rules != 1 || rep.Files != 1 {
		t.Fatalf("unexpected findings: %+v", rep.Findings)
	}
	if rep.Failed(true) {
		t.Error("clean report must not fail")
	}
}

func TestFindings(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "bad.yar", `
rule BadName
{
    meta:
        threat_level = 9
        mitre_attack = "1486"
    strings:
        $hex = "0x89,0x00,0x00,0x00,0x60,0x89"   // comment with "quotes"
        $short = "ab"
        $narrow = "narrow only string"
        $tiny = { 4D 5A }
    condition:
        any of them
}

rule trivial {
    meta:
        description = "d"
        author = "x"
        family = "f"
        threat_level = 1
        mitre_attack = "T1027.002"
    condition:
        true
}
`)
	rep, err := Lint(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	got := codes(rep)
	want := map[string]string{
		"meta-description":   Error,
		"meta-author":        Warning,
		"meta-threat-level":  Error,
		"meta-family":        Warning,
		"meta-technique":     Error,
		"name-style":         Warning,
		"string-hex-as-text": Error,
		"string-short":       Warning,
		"string-narrow":      Warning,
		"condition-trivial":  Error,
		"no-strings":         Info,
	}
	for code, sev := range want {
		fs := got[code]
		if len(fs) == 0 {
			t.Errorf("missing %s", code)
			continue
		}
		if fs[0].Severity != sev {
			t.Errorf("%s severity %s, want %s", code, fs[0].Severity, sev)
		}
	}
	if n := len(got["string-short"]); n != 2 {
		t.Errorf("string-short x%d, want 2 ($short and $tiny): %+v", n, got["string-short"])
	}
	if n := len(got["string-narrow"]); n != 3 {
		t.Errorf("string-narrow x%d, want 3: %+v", n, got["string-narrow"])
	}
	if f := got["string-hex-as-text"][0]; f.Line != 8 || f.Rule != "BadName" || !strings.HasSuffix(f.File, "bad.yar") {
		t.Errorf("hex-as-text location: %+v", f)
	}
	if f := got["condition-trivial"][0]; f.Rule != "trivial" || f.Line != 23 {
		t.Errorf("condition-trivial location: %+v", f)
	}
	if !rep.Failed(false) {
		t.Error("errors must fail the report")
	}

	// Generic profile: conventions off, hygiene on.
	gen, err := Lint(dir, Options{Profile: ProfileGeneric})
	if err != nil {
		t.Fatal(err)
	}
	g := codes(gen)
	for _, off := range []string{"meta-family", "name-style", "string-narrow"} {
		if len(g[off]) != 0 {
			t.Errorf("generic profile should not report %s", off)
		}
	}
	for _, on := range []string{"meta-description", "string-hex-as-text", "condition-trivial", "meta-technique"} {
		if len(g[on]) == 0 {
			t.Errorf("generic profile should report %s", on)
		}
	}
	// threat_level out of range is still an error in generic; missing is not.
	if len(g["meta-threat-level"]) != 1 {
		t.Errorf("generic threat-level findings: %+v", g["meta-threat-level"])
	}
}

func TestCompileErrorsAreErrors(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "good.yar", good)
	write(t, dir, "broken.yar", "rule broken { strings: $a = \"x\" condition: $b }\n")
	rep, err := Lint(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	got := codes(rep)
	if len(got["compile"]) == 0 || got["compile"][0].Severity != Error || !strings.HasSuffix(got["compile"][0].File, "broken.yar") {
		t.Errorf("compile findings: %+v", got["compile"])
	}
	if rep.Rules != 1 {
		t.Errorf("rules compiled = %d, want 1", rep.Rules)
	}
	// Meta checks for the good rule still run, attributed to its file.
	for _, f := range rep.Findings {
		if f.Rule == "good_rule" {
			t.Errorf("good rule should be clean: %+v", f)
		}
	}
}

func TestAllBrokenIsStillAReport(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "broken.yar", "rule { }\n")
	rep, err := Lint(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Errors == 0 {
		t.Error("expected a compile error")
	}
}

func TestBadInputs(t *testing.T) {
	if _, err := Lint("/definitely/not/here", Options{}); err == nil {
		t.Error("missing path should error")
	}
	if _, err := Lint(".", Options{Profile: "strictest"}); err == nil {
		t.Error("unknown profile should error")
	}
	dir := t.TempDir()
	if _, err := Lint(dir, Options{}); err == nil {
		t.Error("empty dir should error")
	}
}

func TestRenderers(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "r.yar", "rule r { strings: $a = \"abcdef\" condition: $a }\n")
	rep, _ := Lint(dir, Options{})
	var text, js bytes.Buffer
	if err := rep.WriteText(&text); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text.String(), "[meta-description]") || !strings.Contains(text.String(), "errors") {
		t.Errorf("text:\n%s", text.String())
	}
	if err := rep.WriteJSON(&js, true); err != nil {
		t.Fatal(err)
	}
	var back Report
	if err := json.Unmarshal(js.Bytes(), &back); err != nil || back.Rules != 1 {
		t.Errorf("json round trip: %v %+v", err, back)
	}
}

func TestHelpers(t *testing.T) {
	if stripComment(`$a = "http://x" // c`) != `$a = "http://x" ` {
		t.Error("stripComment must keep // inside strings")
	}
	if unescapedLen(`\x4d\x5a`) != 2 || unescapedLen(`a\"b`) != 3 || unescapedLen("abcd") != 4 {
		t.Error("unescapedLen")
	}
}
