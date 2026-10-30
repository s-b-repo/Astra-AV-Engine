package encchain

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

// minimal valid headers the detector should recognise.
// Headers are padded to ~512 bytes so the base64/hex run clears MinRun, as a
// real executable always would.
func elfHeader() []byte {
	b := make([]byte, 512)
	copy(b, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	return b
}

func peHeader() []byte {
	b := make([]byte, 512)
	b[0], b[1] = 'M', 'Z'
	e := 0x40
	b[0x3C] = byte(e)
	b[0x40], b[0x41], b[0x42], b[0x43] = 'P', 'E', 0, 0
	return b
}

func wrap(s string, width int) string {
	var out strings.Builder
	for i := 0; i < len(s); i += width {
		end := i + width
		if end > len(s) {
			end = len(s)
		}
		out.WriteString(s[i:end])
		out.WriteByte('\n')
	}
	return out.String()
}

func TestDecodesToExecutable(t *testing.T) {
	cases := []struct {
		name  string
		data  []byte
		class string
		enc   string
		depth int
	}{
		{"base64 elf", []byte("prefix text\n" + base64.StdEncoding.EncodeToString(elfHeader()) + "\nsuffix"), "encchain.elf", "base64", 1},
		{"base64 pe", []byte(base64.StdEncoding.EncodeToString(peHeader())), "encchain.pe", "base64", 1},
		{"hex elf", []byte("payload = " + hex.EncodeToString(elfHeader())), "encchain.elf", "hex", 1},
		{"mime-wrapped base64 elf", []byte(wrap(base64.StdEncoding.EncodeToString(elfHeader()), 76)), "encchain.elf", "base64", 1},
		{"url base64 elf", []byte(base64.URLEncoding.EncodeToString(elfHeader())), "encchain.elf", "base64", 1},
		{"double base64 elf", []byte(base64.StdEncoding.EncodeToString([]byte(base64.StdEncoding.EncodeToString(elfHeader())))), "encchain.elf", "base64", 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := Analyze(tc.data, Options{})
			if !r.Detected() {
				t.Fatalf("not detected: score %d, findings %+v", r.Score, r.Findings)
			}
			var f *Finding
			for i := range r.Findings {
				if r.Findings[i].Class == tc.class {
					f = &r.Findings[i]
				}
			}
			if f == nil {
				t.Fatalf("no %s finding; got %+v", tc.class, r.Findings)
			}
			if f.Encoding != tc.enc || f.Depth != tc.depth {
				t.Errorf("finding = %+v, want encoding %s depth %d", *f, tc.enc, tc.depth)
			}
			if f.Technique == "" || f.Novel != novelChain {
				t.Errorf("finding missing technique/novel: %+v", *f)
			}
		})
	}
}

func TestNoFalsePositives(t *testing.T) {
	prose := strings.Repeat("The quick brown fox jumps over the lazy dog, and then some. ", 200)
	cases := []struct {
		name string
		data []byte
	}{
		{"plain prose", []byte(prose)},
		{"base64 of text", []byte(base64.StdEncoding.EncodeToString([]byte(prose)))},
		{"base64 of random-nonexe", []byte(base64.StdEncoding.EncodeToString(append([]byte{0x00, 0x01, 0x02, 0x03}, bytes.Repeat([]byte("data"), 300)...)))},
		{"der-like cert blob", []byte(base64.StdEncoding.EncodeToString(append([]byte{0x30, 0x82, 0x03, 0x00}, bytes.Repeat([]byte{0xAB}, 800)...)))},
		{"hex of text", []byte(hex.EncodeToString([]byte(prose)))},
		{"empty", nil},
		{"MZ-without-PE", []byte(base64.StdEncoding.EncodeToString(append([]byte("MZ"), bytes.Repeat([]byte{0x00}, 800)...)))},
		{"short base64 elf (under floor)", []byte(base64.StdEncoding.EncodeToString(elfHeader()[:20]))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if r := Analyze(tc.data, Options{}); r.Detected() {
				t.Errorf("false positive: score %d, findings %+v", r.Score, r.Findings)
			}
		})
	}
}

func TestBounded(t *testing.T) {
	// A pathological input (a huge base64 blob that decodes to more base64)
	// must terminate within the caps, not loop or exhaust memory.
	big := strings.Repeat("QUFBQUFBQUFBQUFBQUFBQQ", 200000) // ~4MB of base64 chars
	r := Analyze([]byte(big), Options{MaxDecoded: 1 << 20})
	if r == nil {
		t.Fatal("nil result")
	}
	// Many identical runs collapse under the candidate cap.
	if r.Candidates > DefaultMaxCandidates {
		t.Errorf("candidate cap exceeded: %d", r.Candidates)
	}
	// Depth is bounded.
	for _, f := range r.Findings {
		if f.Depth > DefaultMaxLayers {
			t.Errorf("layer cap exceeded: %+v", f)
		}
	}
}

func TestThreshold(t *testing.T) {
	r := Analyze([]byte(base64.StdEncoding.EncodeToString(elfHeader())), Options{})
	if r.EffectiveThreshold() != Threshold || !r.Detected() {
		t.Errorf("threshold/detect: %+v", r)
	}
	var nilr *Result
	if nilr.Detected() || nilr.EffectiveThreshold() != Threshold {
		t.Error("nil result handling")
	}
}
