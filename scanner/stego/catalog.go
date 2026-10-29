package stego

// FindingClass describes one finding class the stego pass can emit.
type FindingClass struct {
	// Class is the stable identifier ("stego.zero-width").
	Class string `json:"class"`
	// Weight is the score the class contributes.
	Weight int `json:"weight"`
	// Technique is the ATT&CK technique id; Novel the plan's NOVEL id when
	// the class belongs to a technique without an ATT&CK entry of its own.
	Technique string `json:"technique,omitempty"`
	Novel     string `json:"novel,omitempty"`
	// Modifier marks a class that raises the score without being a finding
	// on its own.
	Modifier    bool   `json:"modifier,omitempty"`
	Description string `json:"description"`
}

// Classes returns every finding class the pass can emit, in report order.
func Classes() []FindingClass {
	return []FindingClass{
		{"stego." + ClassZeroWidth, weightZeroWidth, techObfuscation, novelDeadDrop, false, "zero-width codepoints outside any excusing context: the carrier alphabet of zero-width steganography"},
		{"stego." + ClassBidiControl, weightBidi, techObfuscation, "", false, "directional embeddings, overrides or isolates on a line without right-to-left text (Trojan Source)"},
		{"stego." + ClassTag, weightTag, techObfuscation, novelDeadDrop, false, "Unicode TAG characters outside a subdivision-flag sequence: invisible copies of ASCII"},
		{"stego." + ClassVariationSelector, weightVS, techObfuscation, novelDeadDrop, false, "variation selectors where no base character wants them: a 256-value invisible byte alphabet"},
		{"stego.payload-run", weightRun, techObfuscation, "", true, "a run of eight or more consecutive invisible codepoints (encoded payload length)"},
		{"stego.ascii-carrier", weightASCII, techObfuscation, "", true, "invisible codepoints whose visible neighbours on both sides are ASCII (dead-drop carrier pattern)"},
	}
}
