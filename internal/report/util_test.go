package report

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestTruncateString(t *testing.T) {
	cases := []struct {
		in      string
		max     int
		want    string
		wantCut bool
	}{
		{"hello", 0, "hello", false},
		{"hello", -1, "hello", false},
		{"hello", 5, "hello", false},
		{"hello", 4, "hell" + TruncationMarker, true},
		{"héllo wörld", 6, "héllo " + TruncationMarker, true},
		{"", 3, "", false},
		{"ab\xffcd", 0, "ab�cd", false},
		{"ab\xffcd", 3, "ab�" + TruncationMarker, true},
	}
	for _, tc := range cases {
		got, cut := truncateString(tc.in, tc.max)
		if got != tc.want || cut != tc.wantCut {
			t.Errorf("truncateString(%q, %d) = (%q, %v), want (%q, %v)", tc.in, tc.max, got, cut, tc.want, tc.wantCut)
		}
		if !utf8.ValidString(got) {
			t.Errorf("truncateString(%q, %d) produced invalid UTF-8", tc.in, tc.max)
		}
	}
}

func TestTruncateBytesAndPreview(t *testing.T) {
	b := []byte("abc\x00\x01def\xff")
	if got, cut := truncateBytes(b, 0); cut || len(got) != len(b) {
		t.Errorf("unlimited truncateBytes cut the input")
	}
	if got, cut := truncateBytes(b, 3); !cut || string(got) != "abc" {
		t.Errorf("truncateBytes(3) = %q cut=%v", got, cut)
	}
	if got := preview(b, 0); got != "abc..def." {
		t.Errorf("preview = %q, want %q", got, "abc..def.")
	}
	if got := preview(b, 4); got != "abc." {
		t.Errorf("preview(4) = %q, want %q", got, "abc.")
	}
	if got := hexString([]byte{0xde, 0xad}); got != "dead" {
		t.Errorf("hexString = %q", got)
	}
}

func TestSlug(t *testing.T) {
	cases := map[string]string{
		"WannaCry Ransomware":      "wannacry-ransomware",
		"  Cobalt Strike (beacon)": "cobalt-strike-beacon",
		"":                         "unnamed",
		"---":                      "unnamed",
		"a\xffb":                   "a-b",
		"Emotet_Trojan.v2":         "emotet-trojan-v2",
	}
	for in, want := range cases {
		if got := slug(in); got != want {
			t.Errorf("slug(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRelativeURI(t *testing.T) {
	cases := []struct {
		name    string
		root    string
		path    string
		wantURI string
		wantRel bool
	}{
		{"no root, relative path", "", "samples/a.exe", "samples/a.exe", false},
		{"no root, absolute path", "", "/srv/samples/a.exe", "file:///srv/samples/a.exe", false},
		{"inside root", "/srv/samples", "/srv/samples/sub/a.exe", "sub/a.exe", true},
		{"inside root, trailing slash on root", "/srv/samples/", "/srv/samples/a.exe", "a.exe", true},
		{"is root", "/srv/samples", "/srv/samples", ".", true},
		{"outside root", "/srv/samples", "/etc/passwd", "file:///etc/passwd", false},
		{"sibling with shared prefix is outside", "/srv/samples", "/srv/samples2/a.exe", "file:///srv/samples2/a.exe", false},
		{"dot-dot escape", "/srv/samples", "/srv/samples/../secret", "file:///srv/secret", false},
		{"relative root, relative path", "samples", "samples/a.exe", "a.exe", true},
		{"relative root, escaping relative path", "samples", "../other.exe", "../other.exe", false},
		{"dot root", ".", "a/b.exe", "a/b.exe", true},
		{"dot root, absolute path", ".", "/a/b.exe", "file:///a/b.exe", false},
		{"windows inside root", `C:\repo`, `C:\repo\bin\a.exe`, "bin/a.exe", true},
		{"windows outside root", `C:\repo`, `D:\x\a.exe`, "file:///D:/x/a.exe", false},
		{"windows no root", "", `C:\x\a b.exe`, "file:///C:/x/a%20b.exe", false},
		{"space inside root is escaped", "/r", "/r/my dir/a b.exe", "my%20dir/a%20b.exe", true},
		{"hash sign is escaped", "/r", "/r/a#1.exe", "a%231.exe", true},
		{"empty path", "/r", "", "", false},
	}
	for _, tc := range cases {
		uri, rel := relativeURI(tc.root, tc.path)
		if uri != tc.wantURI || rel != tc.wantRel {
			t.Errorf("%s: relativeURI(%q, %q) = (%q, %v), want (%q, %v)", tc.name, tc.root, tc.path, uri, rel, tc.wantURI, tc.wantRel)
		}
		if strings.Contains(uri, `\`) {
			t.Errorf("%s: URI contains a backslash: %q", tc.name, uri)
		}
	}
}

func TestRootURI(t *testing.T) {
	cases := map[string]string{
		"":              "",
		"relative":      "",
		"/srv/samples":  "file:///srv/samples/",
		"/srv/samples/": "file:///srv/samples/",
		`C:\repo`:       "file:///C:/repo/",
		"/":             "file:///",
	}
	for in, want := range cases {
		if got := rootURI(in); got != want {
			t.Errorf("rootURI(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalizeLevel(t *testing.T) {
	for _, l := range []string{LevelError, LevelWarning, LevelNote, LevelNone} {
		if got := normalizeLevel(l, LevelError); got != l {
			t.Errorf("normalizeLevel(%q) = %q", l, got)
		}
	}
	if got := normalizeLevel("fatal", LevelNote); got != LevelNote {
		t.Errorf("normalizeLevel(fatal) = %q, want note", got)
	}
}

func TestNegativeLimitsFallBackToDefaults(t *testing.T) {
	c := buildConfig([]Option{
		WithMaxMatchStringBytes(-1), WithMaxHashChars(-5), WithMaxMessageRunes(-9), WithMaxPreviewBytes(-2),
		WithToolName(""), WithToolVersion(""), WithInformationURI(""), WithStatFunc(nil), WithClock(nil),
	})
	if c.maxMatchStringBytes != DefaultMaxMatchStringBytes || c.maxHashChars != DefaultMaxHashChars ||
		c.maxMessageRunes != DefaultMaxMessageRunes || c.maxPreviewBytes != DefaultMaxPreviewBytes {
		t.Errorf("negative limits were not reset: %+v", c)
	}
	if c.toolName != DefaultToolName || c.toolVersion != DefaultToolVersion || c.informationURI != DefaultInformationURI {
		t.Errorf("empty branding was not reset: %+v", c)
	}
	if c.stat == nil || c.now == nil {
		t.Error("nil stat/clock were not reset")
	}
}
