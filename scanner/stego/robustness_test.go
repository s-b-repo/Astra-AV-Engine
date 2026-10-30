package stego

import (
	"encoding/base64"
	"testing"
	"unicode/utf16"
)

// Stego-detection robustness: an invisible-codepoint dead drop must keep
// being detected when wrapped in more text or re-encoded as UTF-16, because
// the pass is presence-based and decodes UTF-16. base64 is the expected loss
// (the codepoints become ASCII), recorded as the documented gap, not a
// regression. Synthetic fixtures only.
func wideEncode(b []byte) []byte {
	out := make([]byte, 0, len(b)*2+2)
	out = append(out, 0xff, 0xfe) // UTF-16LE BOM
	for _, r := range utf16.Encode([]rune(string(b))) {
		out = append(out, byte(r), byte(r>>8))
	}
	return out
}

func TestStegoDetectionRobustness(t *testing.T) {
	zwsp := string(rune(0x200B))
	zwnj := string(rune(0x200C))
	payload := zwsp + zwnj + zwnj + zwsp + zwsp + zwnj + zwsp + zwnj
	sample := []byte("install the " + payload + " tool from the readme\n")

	detect := func(b []byte) bool { return Scan(b, Options{}).Detected() }
	if !detect(sample) {
		t.Fatal("dead-drop baseline not detected")
	}

	surround := func(b []byte) []byte {
		return append([]byte("line one\nline two\n"), append(b, []byte("trailing line\n")...)...)
	}
	preserving := []struct {
		name string
		fn   func([]byte) []byte
	}{
		{"identity", func(b []byte) []byte { return b }},
		{"surround-text", surround},
		{"utf16le", wideEncode},
	}
	for _, tr := range preserving {
		if !detect(tr.fn(sample)) {
			t.Errorf("BRITTLE: benign transform %q hid the invisible codepoints", tr.name)
		}
	}
	// base64 turns the codepoints into ASCII: the documented encoding gap.
	if detect([]byte(base64.StdEncoding.EncodeToString(sample))) {
		t.Log("note: base64 unexpectedly still detected (fine, stronger than documented)")
	}
}
