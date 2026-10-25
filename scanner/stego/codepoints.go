package stego

// Classes of invisible codepoint. They are stable identifiers: SARIF rule ids,
// JSON fields and eval signals key on them.
const (
	// ClassZeroWidth is a codepoint with no glyph and no width: the carrier
	// alphabet of zero-width steganography.
	ClassZeroWidth = "zero-width"
	// ClassBidiControl is an explicit directional embedding, override or
	// isolate: the Trojan Source class (CVE-2021-42574).
	ClassBidiControl = "bidi-control"
	// ClassTag is a Unicode TAG character (U+E0000-U+E007F): invisible copies
	// of ASCII used to smuggle text past filters and language models.
	ClassTag = "tag"
	// ClassVariationSelector is a variation selector used where no base
	// character wants one: 256 invisible values make a byte alphabet.
	ClassVariationSelector = "variation-selector"
	// ClassInfo is recorded but never scored (BOM, directional marks, soft
	// hyphen).
	ClassInfo = "info"
)

// kind describes one recognised invisible codepoint.
type kind struct {
	name  string
	class string
}

// table lists the individual codepoints the detector knows by name. Ranges
// (TAG characters, variation selectors) are handled in classify.
var table = map[rune]kind{
	0x034F: {"COMBINING GRAPHEME JOINER", ClassZeroWidth},
	0x180E: {"MONGOLIAN VOWEL SEPARATOR", ClassZeroWidth},
	0x200B: {"ZERO WIDTH SPACE", ClassZeroWidth},
	0x200C: {"ZERO WIDTH NON-JOINER", ClassZeroWidth},
	0x200D: {"ZERO WIDTH JOINER", ClassZeroWidth},
	0x2060: {"WORD JOINER", ClassZeroWidth},
	0x2061: {"FUNCTION APPLICATION", ClassZeroWidth},
	0x2062: {"INVISIBLE TIMES", ClassZeroWidth},
	0x2063: {"INVISIBLE SEPARATOR", ClassZeroWidth},
	0x2064: {"INVISIBLE PLUS", ClassZeroWidth},
	0xFEFF: {"ZERO WIDTH NO-BREAK SPACE", ClassZeroWidth},

	0x202A: {"LEFT-TO-RIGHT EMBEDDING", ClassBidiControl},
	0x202B: {"RIGHT-TO-LEFT EMBEDDING", ClassBidiControl},
	0x202C: {"POP DIRECTIONAL FORMATTING", ClassBidiControl},
	0x202D: {"LEFT-TO-RIGHT OVERRIDE", ClassBidiControl},
	0x202E: {"RIGHT-TO-LEFT OVERRIDE", ClassBidiControl},
	0x2066: {"LEFT-TO-RIGHT ISOLATE", ClassBidiControl},
	0x2067: {"RIGHT-TO-LEFT ISOLATE", ClassBidiControl},
	0x2068: {"FIRST STRONG ISOLATE", ClassBidiControl},
	0x2069: {"POP DIRECTIONAL ISOLATE", ClassBidiControl},

	0x00AD: {"SOFT HYPHEN", ClassInfo},
	0x061C: {"ARABIC LETTER MARK", ClassInfo},
	0x200E: {"LEFT-TO-RIGHT MARK", ClassInfo},
	0x200F: {"RIGHT-TO-LEFT MARK", ClassInfo},
}

// classify reports whether r is an invisible codepoint the detector tracks.
func classify(r rune) (kind, bool) {
	if k, ok := table[r]; ok {
		return k, true
	}
	switch {
	case r >= 0xE0000 && r <= 0xE007F:
		return kind{"TAG " + tagName(r), ClassTag}, true
	case r >= 0xFE00 && r <= 0xFE0F:
		return kind{"VARIATION SELECTOR-" + itoa(int(r-0xFE00)+1), ClassVariationSelector}, true
	case r >= 0xE0100 && r <= 0xE01EF:
		return kind{"VARIATION SELECTOR-" + itoa(int(r-0xE0100)+17), ClassVariationSelector}, true
	}
	return kind{}, false
}

func tagName(r rune) string {
	switch {
	case r == 0xE0001:
		return "LANGUAGE TAG"
	case r == 0xE007F:
		return "CANCEL TAG"
	case r >= 0xE0020 && r <= 0xE007E:
		return "(" + string(rune(r-0xE0000)) + ")"
	}
	return "(unassigned)"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// isPictographic is a deliberately generous test for emoji and the symbols
// that take emoji presentation. Generous is the safe direction here: it only
// ever excuses a joiner or a selector, never creates a finding.
func isPictographic(r rune) bool {
	switch {
	case r >= 0x1F000 && r <= 0x1FAFF: // Mahjong .. Symbols and Pictographs Extended-A
		return true
	case r >= 0x2600 && r <= 0x27BF: // Misc Symbols, Dingbats
		return true
	case r >= 0x2300 && r <= 0x23FF: // Misc Technical (⌚ ⏰ ...)
		return true
	case r >= 0x2B00 && r <= 0x2BFF: // Misc Symbols and Arrows
		return true
	case r >= 0x2190 && r <= 0x21FF: // Arrows
		return true
	case r >= 0x25A0 && r <= 0x25FF: // Geometric Shapes
		return true
	case r >= 0x2100 && r <= 0x214F: // Letterlike (™ ℹ)
		return true
	case r >= 0x1F1E6 && r <= 0x1F1FF: // regional indicators
		return true
	}
	switch r {
	case 0x00A9, 0x00AE, 0x203C, 0x2049, 0x24C2, 0x2934, 0x2935, 0x3030, 0x303D, 0x3297, 0x3299, 0x0023, 0x002A:
		return true
	}
	return r >= '0' && r <= '9' // keycap sequences: digit + FE0F + 20E3
}

// isJoiningScript reports whether r belongs to a script in which ZERO WIDTH
// JOINER / NON-JOINER are ordinary typography (cursive joining control,
// conjunct formation).
func isJoiningScript(r rune) bool {
	switch {
	case r >= 0x0590 && r <= 0x05FF: // Hebrew
		return true
	case r >= 0x0600 && r <= 0x08FF: // Arabic, Syriac, Arabic Supplement, Thaana, NKo, Samaritan, Mandaic, Arabic Extended
		return true
	case r >= 0x0900 && r <= 0x0DFF: // Devanagari .. Malayalam, Sinhala
		return true
	case r >= 0x0F00 && r <= 0x0FFF: // Tibetan
		return true
	case r >= 0x1000 && r <= 0x109F: // Myanmar
		return true
	case r >= 0x1780 && r <= 0x17FF: // Khmer
		return true
	case r >= 0x1800 && r <= 0x18AF: // Mongolian
		return true
	case r >= 0xA980 && r <= 0xA9DF: // Javanese
		return true
	case r >= 0xFB50 && r <= 0xFDFF: // Arabic Presentation Forms-A
		return true
	case r >= 0xFE70 && r <= 0xFEFE: // Arabic Presentation Forms-B
		return true
	case r >= 0x11000 && r <= 0x11FFF: // Brahmic scripts (SMP)
		return true
	}
	return false
}

// isSpacelessScript reports whether r belongs to a script written without
// spaces between words, in which ZERO WIDTH SPACE is the ordinary word
// separator (Khmer, Thai, Lao, Myanmar, Tibetan).
func isSpacelessScript(r rune) bool {
	switch {
	case r >= 0x0E00 && r <= 0x0EFF: // Thai, Lao
		return true
	case r >= 0x0F00 && r <= 0x0FFF: // Tibetan
		return true
	case r >= 0x1000 && r <= 0x109F: // Myanmar
		return true
	case r >= 0x1780 && r <= 0x17FF: // Khmer
		return true
	}
	return false
}

// isRTLScript reports whether r belongs to a right-to-left script, next to
// which explicit directional embeddings and isolates are ordinary
// bidirectional typesetting rather than a display attack on source code.
func isRTLScript(r rune) bool {
	switch {
	case r >= 0x0590 && r <= 0x08FF: // Hebrew, Arabic, Syriac, Thaana, NKo, Samaritan, Mandaic
		return true
	case r >= 0xFB1D && r <= 0xFDFF, r >= 0xFE70 && r <= 0xFEFE: // presentation forms
		return true
	case r >= 0x10800 && r <= 0x10FFF: // historic RTL scripts
		return true
	}
	return false
}

// isCJKIdeograph reports whether r is a Han ideograph (the base characters of
// ideographic variation sequences).
func isCJKIdeograph(r rune) bool {
	switch {
	case r >= 0x3400 && r <= 0x4DBF, r >= 0x4E00 && r <= 0x9FFF, r >= 0xF900 && r <= 0xFAFF:
		return true
	case r >= 0x20000 && r <= 0x3134F:
		return true
	}
	return false
}

// isEmojiModifier covers the skin-tone modifiers and the combining enclosing
// keycap, which sit between an emoji and a joiner inside one sequence.
func isEmojiModifier(r rune) bool {
	return (r >= 0x1F3FB && r <= 0x1F3FF) || r == 0x20E3
}

// isASCIIText is the "dead-drop carrier" test: printable ASCII or the usual
// whitespace.
func isASCIIText(r rune) bool {
	return (r >= 0x20 && r <= 0x7E) || r == '\t' || r == '\n' || r == '\r'
}
