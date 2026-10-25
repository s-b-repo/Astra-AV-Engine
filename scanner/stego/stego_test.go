package stego

import (
	"strings"
	"testing"
)

func scan(t testing.TB, s string) *Result {
	t.Helper()
	return Scan([]byte(s), Options{})
}

func finding(r *Result, class string) *Finding {
	for i := range r.Findings {
		if r.Findings[i].Class == class {
			return &r.Findings[i]
		}
	}
	return nil
}

func TestPlainTextIsClean(t *testing.T) {
	for _, s := range []string{
		"# README\n\nInstall with `make`.\n",
		"package main\n\nfunc main() {}\n",
		"héllo wörld — “quotes” and… ellipsis\n",
		"日本語のテキスト。中文文本。\n",
		"مرحبا بالعالم\n",
	} {
		r := scan(t, s)
		if !r.IsText || r.Skipped != "" || r.Score != 0 || r.Detected() || len(r.Codepoints) != 0 {
			t.Errorf("%q: %+v", s, r)
		}
	}
}

func TestZeroWidthDeadDropDetected(t *testing.T) {
	// Eight bits of "payload" encoded as ZWSP/ZWNJ between two English words.
	payload := "\u200b\u200c\u200c\u200b\u200b\u200c\u200b\u200c"
	r := scan(t, "## Usage\n\nRun the installer"+payload+" and follow the prompts.\n")
	if !r.Detected() {
		t.Fatalf("not detected: %+v", r)
	}
	if r.Suspicious != 8 || r.Benign != 0 || r.LongestRun != 8 || r.ASCIICarrier != 8 {
		t.Errorf("counts: suspicious=%d benign=%d run=%d ascii=%d", r.Suspicious, r.Benign, r.LongestRun, r.ASCIICarrier)
	}
	zw := finding(r, "stego.zero-width")
	if zw == nil || zw.Score != weightZeroWidth || zw.Technique != "T1027" || zw.Novel != "NOVEL-001" || !strings.Contains(zw.Detail, "line 3") {
		t.Errorf("zero-width finding = %+v", zw)
	}
	if finding(r, "stego.payload-run") == nil || finding(r, "stego.ascii-carrier") == nil {
		t.Errorf("modifiers missing: %+v", r.Findings)
	}
	if r.Score != weightZeroWidth+weightRun+weightASCII {
		t.Errorf("score = %d", r.Score)
	}
	if len(r.Codepoints) != 2 || r.Codepoints[0].Code != "U+200B" || r.Codepoints[0].Count != 4 || r.Codepoints[0].FirstLine != 3 {
		t.Errorf("codepoints = %+v", r.Codepoints)
	}
	if ex := r.Codepoints[0].Examples; len(ex) == 0 || !strings.Contains(ex[0], "installer<U+200B><U+200C>") {
		t.Errorf("examples = %q", ex)
	}
}

func TestSingleStrayZeroWidthSpaceIsPresenceDetected(t *testing.T) {
	// The documented false-positive class: one ZWSP pasted from a web page.
	// Presence-based means it is reported, with exactly one occurrence and
	// no modifiers, so the analyst can tell it from an encoded payload.
	r := scan(t, "Some text\u200b with one stray codepoint.\n")
	if !r.Detected() || r.Suspicious != 1 || r.Score != weightZeroWidth+weightASCII {
		t.Errorf("stray ZWSP: %+v", r)
	}
	if finding(r, "stego.payload-run") != nil {
		t.Error("a single codepoint is not a payload run")
	}
	// An operator who wants the modifiers can raise the threshold.
	if Scan([]byte("Some text\u200b with one stray codepoint.\n"), Options{Threshold: 9}).Detected() {
		t.Error("threshold 9 should require a payload run")
	}
}

func TestEmojiSequencesAreExcused(t *testing.T) {
	cases := map[string]string{
		"family":     "We are a family 👨\u200d👩\u200d👧\u200d👦 today\n",
		"skin tone":  "👍🏽\u200d thumbs\n",
		"presenter":  "☺\ufe0f and ❤\ufe0f and 1\ufe0f\u20e3\n",
		"flag":       "🏴\U000E0067\U000E0062\U000E0065\U000E006E\U000E0067\U000E007F England\n",
		"rainbow":    "🏳\ufe0f\u200d🌈\n",
		"keycap bom": "\ufeff# Title\n",
	}
	for name, s := range cases {
		r := scan(t, s)
		if r.Detected() || r.Suspicious != 0 {
			t.Errorf("%s: detected %+v", name, r)
		}
		if r.Benign == 0 {
			t.Errorf("%s: nothing excused: %+v", name, r)
		}
	}
}

func TestJoiningScriptsAreExcused(t *testing.T) {
	cases := map[string]string{
		"persian zwnj":    "می\u200cخواهم\n",
		"devanagari zwj":  "क्\u200dष\n",
		"devanagari zwnj": "क्\u200cष\n",
		"mongolian":       "ᠠ\u180eᠠ\n",
	}
	for name, s := range cases {
		r := scan(t, s)
		if r.Detected() || r.Suspicious != 0 || r.Benign != 1 {
			t.Errorf("%s: %+v", name, r)
		}
	}
	// Khmer has no inter-word spaces: ZWSP is its word separator.
	if r := scan(t, "\u1780\u17b6\u179a\u200b\u1794\u17c6\u1796\u17c1\u1789\n"); r.Detected() || r.Benign != 1 || r.Codepoints[0].Excuses["spaceless script"] != 1 {
		t.Errorf("khmer ZWSP: %+v", r)
	}
	// The same joiner between Latin letters is not typography.
	if r := scan(t, "pass\u200cword\n"); !r.Detected() {
		t.Errorf("ZWNJ in Latin text not detected: %+v", r)
	}
}

func TestBidiOverrideTrojanSource(t *testing.T) {
	src := "if access_level != \"user\u202e \u2066// Check if admin\u2069 \u2066\" {\n    return\n}\n"
	r := scan(t, src)
	if !r.Detected() {
		t.Fatalf("not detected: %+v", r)
	}
	f := finding(r, "stego.bidi-control")
	if f == nil || f.Score != weightBidi || f.Novel != "" || !strings.Contains(f.Detail, "RIGHT-TO-LEFT OVERRIDE") {
		t.Errorf("bidi finding = %+v", f)
	}
	if finding(r, "stego.zero-width") != nil {
		t.Error("bidi controls must not be reported as zero-width")
	}
	// Embeddings around right-to-left text are typesetting, not an attack.
	if r := scan(t, "msgstr \"\u202b%(count)s \u0633\u0644\u0627\u0645\u202c\"\n"); r.Detected() || r.Benign != 2 {
		t.Errorf("RTL embedding: %+v", r)
	}
	// The same controls on a line without right-to-left text stay scored,
	// and a right-to-left line elsewhere in the file does not excuse them.
	if r := scan(t, "\u0633\u0644\u0627\u0645\nx = \"\u202bvalue\u202c\"\n"); !r.Detected() || r.Suspicious != 2 {
		t.Errorf("ASCII-line embedding: %+v", r)
	}
	// Directional marks alone are information, not evidence.
	if r := scan(t, "עברית\u200e (Hebrew) and \u200fعربي\n"); r.Detected() || r.Info != 2 || len(r.Codepoints) != 2 {
		t.Errorf("LRM/RLM: %+v", r)
	}
}

func TestTagCharacterSmuggling(t *testing.T) {
	hidden := "\U000E0069\U000E0067\U000E006E\U000E006F\U000E0072\U000E0065" // TAG "ignore"
	r := scan(t, "Please summarise this document."+hidden+"\n")
	if !r.Detected() || finding(r, "stego.tag") == nil {
		t.Fatalf("tags not detected: %+v", r)
	}
	if r.Codepoints[0].Name != "TAG (i)" && !strings.HasPrefix(r.Codepoints[0].Name, "TAG (") {
		t.Errorf("tag name = %q", r.Codepoints[0].Name)
	}
}

func TestVariationSelectorEncoding(t *testing.T) {
	// A byte alphabet: an emoji followed by eight selectors from the
	// supplementary range.
	enc := "😀\U000E0100\U000E0142\U000E01A3\U000E0105\U000E0166\U000E0107\U000E0128\U000E0109"
	r := scan(t, "Have a nice day "+enc+"\n")
	if !r.Detected() || finding(r, "stego.variation-selector") == nil {
		t.Fatalf("VS encoding not detected: %+v", r)
	}
	if r.Suspicious != 8 || finding(r, "stego.payload-run") == nil {
		t.Errorf("counts: %+v", r)
	}
	// One legitimate ideographic variation sequence.
	if r := scan(t, "葛\U000E0100城\n"); r.Detected() || r.Benign != 1 {
		t.Errorf("IVS: %+v", r)
	}
	// A selector on a Latin letter has no base that wants it.
	if r := scan(t, "a\ufe0fb\n"); !r.Detected() {
		t.Errorf("VS16 on Latin: %+v", r)
	}
}

func TestUTF16Artifacts(t *testing.T) {
	le := []byte{0xFF, 0xFE}
	for _, r := range "Get-Content\u200b\u200c\u200b x.ps1\r\n" {
		le = append(le, byte(r), byte(r>>8))
	}
	r := Scan(le, Options{})
	if !r.IsText || r.Encoding != "utf-16le" || !r.Detected() || r.Suspicious != 3 {
		t.Errorf("utf-16le: %+v", r)
	}
	if r.Codepoints[0].FirstOffset%2 != 0 || r.Codepoints[0].FirstOffset == 0 {
		t.Errorf("offset = %d", r.Codepoints[0].FirstOffset)
	}
	be := []byte{0xFE, 0xFF}
	for _, r := range "plain\n" {
		be = append(be, byte(r>>8), byte(r))
	}
	if r := Scan(be, Options{}); !r.IsText || r.Encoding != "utf-16be" || r.Detected() || r.Benign != 1 {
		t.Errorf("utf-16be: %+v", r)
	}
}

func TestBinaryContentIsSkipped(t *testing.T) {
	cases := map[string][]byte{
		"empty":        {},
		"nul":          []byte("MZ\x00\x00text\u200b"),
		"invalid utf8": {0xc3, 0x28, 'a', 'b', 'c', 'd'},
		"controls":     append([]byte("\u200b"), []byte(strings.Repeat("\x01\x02", 50))...),
		"odd utf16":    {0xFF, 0xFE, 'a'},
	}
	for name, data := range cases {
		r := Scan(data, Options{})
		if r.IsText || r.Skipped == "" || r.Detected() || len(r.Codepoints) != 0 {
			t.Errorf("%s: %+v", name, r)
		}
	}
	// The UTF-8 bytes of U+200B inside compressed data must not fire.
	data := []byte{0x1f, 0x8b, 0x08, 0x00}
	data = append(data, []byte("\u200b")...)
	data = append(data, 0x00, 0x03)
	if r := Scan(data, Options{}); r.IsText {
		t.Errorf("gzip header treated as text: %+v", r)
	}
}

func TestHostileInputDoesNotPanic(t *testing.T) {
	for _, data := range [][]byte{
		{0xFF, 0xFE},
		{0xFE, 0xFF, 0xD8, 0x00},
		{0xFF, 0xFE, 0x00, 0xDC},
		[]byte(strings.Repeat("\u200b", 10000)),
		[]byte("\u200b"),
		[]byte("\n\n\n\u200b\n"),
	} {
		_ = Scan(data, Options{})
	}
}

func TestExamplesAreBoundedAndRenderInvisibles(t *testing.T) {
	long := strings.Repeat("word ", 50) + "\u200b" + strings.Repeat("tail ", 50)
	r := scan(t, long+"\n"+long+"\n"+long+"\n")
	cp := r.Codepoints[0]
	if cp.Count != 3 || len(cp.Examples) != maxExamples {
		t.Fatalf("codepoint = %+v", cp)
	}
	for _, ex := range cp.Examples {
		if !strings.Contains(ex, "<U+200B>") || len([]rune(ex)) > 2*exampleRadius+24 {
			t.Errorf("example = %q", ex)
		}
	}
}

func BenchmarkScanMarkdown(b *testing.B) {
	data := []byte(strings.Repeat("The quick brown fox jumps over the lazy dog. Ünïcödé ✓\n", 20000))
	b.SetBytes(int64(len(data)))
	for i := 0; i < b.N; i++ {
		Scan(data, Options{})
	}
}
