package stego

import "testing"

// FuzzScan checks that the invisible-codepoint pass never panics, on bytes,
// valid UTF-8, UTF-16 with a BOM, and arbitrary mutations of each. Seeds that
// carry invisible codepoints are built from runes so the source stays ASCII.
func FuzzScan(f *testing.F) {
	zwsp := string(rune(0x200B))
	bom := string(rune(0xFEFF))
	rlo := string(rune(0x202E))
	zwj := string(rune(0x200D))
	tagA := string(rune(0xE0041)) + string(rune(0xE0042))
	for _, s := range []string{
		"", "hello world", "clean ascii line\n",
		"zero" + zwsp + "width",
		bom + "bom start",
		"trojan " + rlo + "source",
		"tag" + tagA,
		"emoji " + string(rune(0x1F468)) + zwj + string(rune(0x1F469)),
	} {
		f.Add([]byte(s))
	}
	// A UTF-16LE BOM followed by ASCII text, as raw bytes.
	f.Add([]byte{0xff, 0xfe, 'U', 0, 'T', 0, 'F', 0, '1', 0, '6', 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		r := Scan(data, Options{})
		if r == nil {
			t.Fatal("Scan returned nil")
		}
	})
}
