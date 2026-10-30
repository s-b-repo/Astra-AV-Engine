package encchain

// Class describes one finding class the encoded-executable detector can emit,
// per technique it is evidence for, for the ATT&CK coverage matrix. A single
// decoded header is an encoded file (T1027.013); reaching it through more than
// one layer is the decode activity itself (T1140).
type Class struct {
	Class       string `json:"class"`
	Technique   string `json:"technique"`
	Novel       string `json:"novel,omitempty"`
	Weight      int    `json:"weight"`
	Description string `json:"description"`
}

// Classes returns the catalog in a stable order.
func Classes() []Class {
	return []Class{
		{"encchain.pe", techEncoded, novelChain, weightPE, "a base64/hex run decodes to a PE image"},
		{"encchain.elf", techEncoded, novelChain, weightPE, "a base64/hex run decodes to an ELF image"},
		{"encchain.pe", techDecode, novelChain, weightPE + weightNested, "a PE image reached through more than one decode layer"},
		{"encchain.elf", techDecode, novelChain, weightPE + weightNested, "an ELF image reached through more than one decode layer"},
	}
}
