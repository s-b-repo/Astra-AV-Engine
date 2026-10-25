package static

import (
	"encoding/binary"
	"math/bits"
)

// RichEntry is one @comp.id record: which Microsoft tool (product id + build)
// contributed how many objects to the link.
type RichEntry struct {
	ProductID uint16 `json:"product_id"`
	Build     uint16 `json:"build"`
	Count     uint32 `json:"count"`
}

// RichHeader is the undocumented linker record MSVC places between the DOS
// stub and the PE header. Its XOR key doubles as a checksum over the DOS header
// and the entries, which is why a copied or hand-edited Rich header fails
// validation: tooling that forges a build record rarely recomputes it.
type RichHeader struct {
	Offset        int         `json:"offset"`
	XorKey        uint32      `json:"xor_key"`
	ChecksumValid bool        `json:"checksum_valid"`
	Entries       []RichEntry `json:"entries"`
}

const (
	richMarker = 0x68636952 // "Rich"
	dansMarker = 0x536e6144 // "DanS"
	maxRich    = 256        // entries; real headers have a few dozen at most
)

// parseRich locates and validates the Rich header. It returns nil when there
// is none.
func parseRich(data []byte, peOff int) *RichHeader {
	// The header lives after the DOS header (0x40) and before e_lfanew.
	if peOff > len(data) {
		peOff = len(data)
	}
	richOff := -1
	for i := 0x40; i+8 <= peOff; i += 4 {
		if binary.LittleEndian.Uint32(data[i:]) == richMarker {
			richOff = i
			break
		}
	}
	if richOff < 0 {
		return nil
	}
	key := binary.LittleEndian.Uint32(data[richOff+4:])

	// Walk backwards to DanS.
	start := -1
	for i := richOff - 4; i >= 0x40; i -= 4 {
		if binary.LittleEndian.Uint32(data[i:])^key == dansMarker {
			start = i
			break
		}
	}
	if start < 0 {
		return nil
	}
	h := &RichHeader{Offset: start, XorKey: key}

	// DanS is followed by three padding dwords (key ^ 0), then entries.
	for i := start + 16; i+8 <= richOff && len(h.Entries) < maxRich; i += 8 {
		compid := binary.LittleEndian.Uint32(data[i:]) ^ key
		count := binary.LittleEndian.Uint32(data[i+4:]) ^ key
		h.Entries = append(h.Entries, RichEntry{
			ProductID: uint16(compid >> 16),
			Build:     uint16(compid & 0xFFFF),
			Count:     count,
		})
	}

	// Checksum: offset of DanS, plus every DOS-header byte rotated by its
	// position (skipping e_lfanew), plus every compid rotated by its count.
	sum := uint32(start)
	for i := 0; i < start; i++ {
		if i >= 0x3c && i < 0x40 {
			continue
		}
		sum += bits.RotateLeft32(uint32(data[i]), i%32)
	}
	for _, e := range h.Entries {
		compid := uint32(e.ProductID)<<16 | uint32(e.Build)
		sum += bits.RotateLeft32(compid, int(e.Count%32))
	}
	h.ChecksumValid = sum == key
	return h
}
