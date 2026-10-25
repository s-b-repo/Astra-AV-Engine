package static

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// Parsing limits. They exist so a hostile header cannot make the parser walk
// the whole address space; each one is generous for real software.
const (
	maxSections         = 96 // the PE specification's own maximum
	maxImportDLLs       = 512
	maxImportsPerDLL    = 16384
	maxImportsTotal     = 1 << 16
	maxNameLen          = 512
	maxTLSCallbacks     = 64
	maxDataDirectories  = 16
	maxCertificateBytes = 1 << 20 // 1 MiB: the largest WIN_CERTIFICATE we will parse
)

// Data directory indices (IMAGE_DIRECTORY_ENTRY_*).
const (
	dirExport     = 0
	dirImport     = 1
	dirResource   = 2
	dirSecurity   = 4
	dirDebug      = 6
	dirTLS        = 9
	dirDelayImprt = 13
	dirCLR        = 14
)

// Section characteristics.
const (
	scnCode              = 0x00000020
	scnInitializedData   = 0x00000040
	scnUninitializedData = 0x00000080
	scnExecute           = 0x20000000
	scnRead              = 0x40000000
	scnWrite             = 0x80000000
)

// File header characteristics.
const (
	charDLL = 0x2000
)

// delphiTimestamp is the constant link time Borland/Embarcadero toolchains
// stamp into every binary (1992-06-19 22:22:17 UTC). It is the single most
// common "ancient timestamp" in benign software and must not score.
const delphiTimestamp = 0x2A425E19

// DataDir is one IMAGE_DATA_DIRECTORY entry. For the security directory the
// address is a file offset, for every other entry it is an RVA.
type DataDir struct {
	VirtualAddress uint32 `json:"virtual_address"`
	Size           uint32 `json:"size"`
}

// Section is one section header plus what the parser derived from it.
type Section struct {
	Name            string  `json:"name"`
	VirtualAddress  uint32  `json:"virtual_address"`
	VirtualSize     uint32  `json:"virtual_size"`
	RawOffset       uint32  `json:"raw_offset"`
	RawSize         uint32  `json:"raw_size"`
	Characteristics uint32  `json:"characteristics"`
	Entropy         float64 `json:"entropy"`
	// Perms renders the access bits as "rwx" with '-' for a cleared bit.
	Perms string `json:"perms"`
	// Entry is true for the section that contains the entry point.
	Entry bool `json:"entry,omitempty"`
	// Truncated is true when the raw range runs past the end of the file.
	Truncated bool `json:"truncated,omitempty"`
}

// Executable reports whether the section is mapped executable.
func (s Section) Executable() bool { return s.Characteristics&scnExecute != 0 }

// Writable reports whether the section is mapped writable.
func (s Section) Writable() bool { return s.Characteristics&scnWrite != 0 }

// Uninitialized reports whether the section is declared as uninitialized data
// (a legitimate reason for RawSize to be zero).
func (s Section) Uninitialized() bool { return s.Characteristics&scnUninitializedData != 0 }

// ImportedFunc is one entry of an import address table.
type ImportedFunc struct {
	Name      string `json:"name,omitempty"`
	Ordinal   uint16 `json:"ordinal,omitempty"`
	ByOrdinal bool   `json:"by_ordinal,omitempty"`
}

// ImportedDLL is one import descriptor and its functions.
type ImportedDLL struct {
	Name      string         `json:"name"`
	Functions []ImportedFunc `json:"functions"`
}

// ExportInfo summarises the export directory.
type ExportInfo struct {
	Present   bool   `json:"present"`
	Functions uint32 `json:"functions,omitempty"`
	Names     uint32 `json:"names,omitempty"`
	Timestamp uint32 `json:"timestamp,omitempty"`
	Name      string `json:"name,omitempty"`
}

// DebugInfo summarises the debug directory.
type DebugInfo struct {
	Present   bool   `json:"present"`
	Timestamp uint32 `json:"timestamp,omitempty"`
	// Reproducible is true when an IMAGE_DEBUG_TYPE_REPRO entry exists: the
	// header timestamp is then a content hash, not a time, and every
	// timestamp consistency check must be skipped.
	Reproducible bool `json:"reproducible,omitempty"`
	// PDBPath is the CodeView RSDS path. Reported as metadata only; it is an
	// attacker-controlled string and never anchors a detection.
	PDBPath string `json:"pdb_path,omitempty"`
	GUID    string `json:"guid,omitempty"`
	Age     uint32 `json:"age,omitempty"`
}

// Overlay describes data appended after the last section.
type Overlay struct {
	Offset int64 `json:"offset"`
	// Size excludes the Authenticode certificate table, which legitimately
	// lives in the overlay.
	Size    int64   `json:"size"`
	Entropy float64 `json:"entropy"`
	// CertificateBytes is the size of the security directory found inside the
	// overlay region, if any.
	CertificateBytes int64 `json:"certificate_bytes,omitempty"`
}

// PE is the parsed structure of a Portable Executable.
type PE struct {
	// Format is "pe32" or "pe32+".
	Format             string `json:"format"`
	Machine            uint16 `json:"machine"`
	MachineName        string `json:"machine_name"`
	Characteristics    uint16 `json:"characteristics"`
	IsDLL              bool   `json:"is_dll"`
	IsCLR              bool   `json:"is_clr"`
	Subsystem          uint16 `json:"subsystem"`
	SubsystemName      string `json:"subsystem_name"`
	DLLCharacteristics uint16 `json:"dll_characteristics"`
	Timestamp          uint32 `json:"timestamp"`
	EntryPoint         uint32 `json:"entry_point"`
	// EntrySection is the name of the section containing the entry point, or
	// "" when it falls outside every section.
	EntrySection        string `json:"entry_section,omitempty"`
	ImageBase           uint64 `json:"image_base"`
	SectionAlignment    uint32 `json:"section_alignment"`
	FileAlignment       uint32 `json:"file_alignment"`
	SizeOfImage         uint32 `json:"size_of_image"`
	SizeOfHeaders       uint32 `json:"size_of_headers"`
	Checksum            uint32 `json:"checksum"`
	NumberOfRvaAndSizes uint32 `json:"number_of_rva_and_sizes"`

	DataDirs []DataDir `json:"-"`
	Sections []Section `json:"sections"`

	Imports      []ImportedDLL `json:"imports"`
	ImportCount  int           `json:"import_count"`
	DelayImports []string      `json:"delay_imports,omitempty"`
	Exports      ExportInfo    `json:"exports"`
	Debug        DebugInfo     `json:"debug"`
	TLSCallbacks int           `json:"tls_callbacks"`
	Overlay      Overlay       `json:"overlay"`
	// Security is the IMAGE_DIRECTORY_ENTRY_SECURITY entry (file offset + size).
	Security DataDir `json:"security"`

	// Rich is the parsed Rich header, nil when absent.
	Rich *RichHeader `json:"rich,omitempty"`
	// Authenticode is the parsed signature, nil when absent.
	Authenticode *Authenticode `json:"authenticode,omitempty"`
	// Imphash is the import hash (pefile-compatible algorithm), "" without imports.
	Imphash string `json:"imphash,omitempty"`
	// Packer is the identified packer, nil when none matched.
	Packer *Packer `json:"packer,omitempty"`

	// Warnings records structural problems the parser tolerated.
	Warnings []string `json:"warnings,omitempty"`

	size       int
	optOffset  int
	sectOffset int
}

// TimestampTime converts the header timestamp.
func (p *PE) TimestampTime() time.Time { return time.Unix(int64(p.Timestamp), 0).UTC() }

// DLLNames returns the imported DLL names, lower-cased and sorted.
func (p *PE) DLLNames() []string {
	out := make([]string, 0, len(p.Imports))
	for _, d := range p.Imports {
		out = append(out, strings.ToLower(d.Name))
	}
	sortStrings(out)
	return out
}

// ImportNames returns every import as "dll.func" (or "dll.ord123"), lower-cased.
// This is the input to clustering.
func (p *PE) ImportNames() []string {
	var out []string
	for _, d := range p.Imports {
		dll := normalizeDLL(d.Name)
		for _, f := range d.Functions {
			if f.ByOrdinal {
				out = append(out, fmt.Sprintf("%s.ord%d", dll, f.Ordinal))
			} else {
				out = append(out, dll+"."+strings.ToLower(f.Name))
			}
		}
	}
	return out
}

func (p *PE) warn(format string, a ...interface{}) {
	p.Warnings = append(p.Warnings, fmt.Sprintf(format, a...))
}

// IsPE reports whether data starts like a PE image: MZ, a sane e_lfanew and
// the PE\0\0 signature.
func IsPE(data []byte) bool {
	if len(data) < 0x40 || data[0] != 'M' || data[1] != 'Z' {
		return false
	}
	off := int(binary.LittleEndian.Uint32(data[0x3c:]))
	if off < 0x40 || off+4 > len(data) {
		return false
	}
	return data[off] == 'P' && data[off+1] == 'E' && data[off+2] == 0 && data[off+3] == 0
}

// ParsePE parses the PE structure of an in-memory image. It returns an error
// only when the buffer is not a PE file or its headers are too short to hold
// the mandatory fields; everything after that is tolerated and recorded in
// Warnings so a damaged sample still yields a result.
func ParsePE(data []byte) (*PE, error) {
	if !IsPE(data) {
		return nil, fmt.Errorf("not a PE image")
	}
	p := &PE{size: len(data)}
	peOff := int(binary.LittleEndian.Uint32(data[0x3c:]))
	coff := peOff + 4
	if coff+20 > len(data) {
		return nil, fmt.Errorf("truncated COFF header")
	}
	p.Machine = le16(data, coff)
	p.MachineName = machineName(p.Machine)
	nSections := int(le16(data, coff+2))
	p.Timestamp = le32(data, coff+4)
	optSize := int(le16(data, coff+16))
	p.Characteristics = le16(data, coff+18)
	p.IsDLL = p.Characteristics&charDLL != 0

	p.optOffset = coff + 20
	if p.optOffset+2 > len(data) {
		return nil, fmt.Errorf("truncated optional header")
	}
	magic := le16(data, p.optOffset)
	var dirOff int
	switch magic {
	case 0x10b:
		p.Format = "pe32"
		if p.optOffset+96 > len(data) {
			return nil, fmt.Errorf("truncated PE32 optional header")
		}
		p.EntryPoint = le32(data, p.optOffset+16)
		p.ImageBase = uint64(le32(data, p.optOffset+28))
		p.SectionAlignment = le32(data, p.optOffset+32)
		p.FileAlignment = le32(data, p.optOffset+36)
		p.SizeOfImage = le32(data, p.optOffset+56)
		p.SizeOfHeaders = le32(data, p.optOffset+60)
		p.Checksum = le32(data, p.optOffset+64)
		p.Subsystem = le16(data, p.optOffset+68)
		p.DLLCharacteristics = le16(data, p.optOffset+70)
		p.NumberOfRvaAndSizes = le32(data, p.optOffset+92)
		dirOff = p.optOffset + 96
	case 0x20b:
		p.Format = "pe32+"
		if p.optOffset+112 > len(data) {
			return nil, fmt.Errorf("truncated PE32+ optional header")
		}
		p.EntryPoint = le32(data, p.optOffset+16)
		p.ImageBase = binary.LittleEndian.Uint64(data[p.optOffset+24:])
		p.SectionAlignment = le32(data, p.optOffset+32)
		p.FileAlignment = le32(data, p.optOffset+36)
		p.SizeOfImage = le32(data, p.optOffset+56)
		p.SizeOfHeaders = le32(data, p.optOffset+60)
		p.Checksum = le32(data, p.optOffset+64)
		p.Subsystem = le16(data, p.optOffset+68)
		p.DLLCharacteristics = le16(data, p.optOffset+70)
		p.NumberOfRvaAndSizes = le32(data, p.optOffset+108)
		dirOff = p.optOffset + 112
	default:
		return nil, fmt.Errorf("unknown optional header magic 0x%x", magic)
	}
	p.SubsystemName = subsystemName(p.Subsystem)

	// Data directories.
	nDirs := int(p.NumberOfRvaAndSizes)
	if nDirs > maxDataDirectories {
		p.warn("NumberOfRvaAndSizes %d exceeds %d; extra entries ignored", nDirs, maxDataDirectories)
		nDirs = maxDataDirectories
	}
	p.DataDirs = make([]DataDir, maxDataDirectories)
	for i := 0; i < nDirs; i++ {
		o := dirOff + i*8
		if o+8 > len(data) {
			p.warn("data directory table truncated at entry %d", i)
			break
		}
		p.DataDirs[i] = DataDir{VirtualAddress: le32(data, o), Size: le32(data, o+4)}
	}
	p.Security = p.DataDirs[dirSecurity]
	p.IsCLR = p.DataDirs[dirCLR].VirtualAddress != 0 && p.DataDirs[dirCLR].Size != 0

	// Section table.
	p.sectOffset = p.optOffset + optSize
	if nSections > maxSections {
		p.warn("NumberOfSections %d exceeds %d; extra sections ignored", nSections, maxSections)
		nSections = maxSections
	}
	for i := 0; i < nSections; i++ {
		o := p.sectOffset + i*40
		if o+40 > len(data) {
			p.warn("section table truncated at entry %d of %d", i, nSections)
			break
		}
		s := Section{
			Name:            cstringFixed(data[o : o+8]),
			VirtualSize:     le32(data, o+8),
			VirtualAddress:  le32(data, o+12),
			RawSize:         le32(data, o+16),
			RawOffset:       le32(data, o+20),
			Characteristics: le32(data, o+36),
		}
		s.Perms = perms(s.Characteristics)
		start, end := int64(s.RawOffset), int64(s.RawOffset)+int64(s.RawSize)
		if s.RawSize > 0 {
			if start >= int64(len(data)) {
				s.Truncated = true
			} else if end > int64(len(data)) {
				s.Truncated = true
				end = int64(len(data))
			}
			if !s.Truncated || start < int64(len(data)) {
				s.Entropy = Entropy(data[start:end])
			}
		}
		p.Sections = append(p.Sections, s)
	}

	// Entry point section.
	if idx := p.sectionIndexForRVA(p.EntryPoint); idx >= 0 {
		p.Sections[idx].Entry = true
		p.EntrySection = p.Sections[idx].Name
	}

	p.parseImports(data)
	p.parseDelayImports(data)
	p.parseExports(data)
	p.parseDebug(data)
	p.parseTLS(data)
	p.computeOverlay(data)
	p.Rich = parseRich(data, peOff)
	p.Authenticode = parseAuthenticode(data, p.Security)
	p.Imphash = Imphash(p.Imports)
	p.Packer = identifyPacker(p, data)
	return p, nil
}

// sectionIndexForRVA returns the section containing rva, or -1.
func (p *PE) sectionIndexForRVA(rva uint32) int {
	for i, s := range p.Sections {
		size := s.VirtualSize
		if s.RawSize > size {
			size = s.RawSize
		}
		if size == 0 {
			continue
		}
		if rva >= s.VirtualAddress && rva < s.VirtualAddress+size {
			return i
		}
	}
	return -1
}

// rvaToOffset maps an RVA onto a file offset that lies inside the buffer and
// inside the section's raw data. ok is false for RVAs that map to nothing on
// disk (zero-filled virtual tail, out of image).
func (p *PE) rvaToOffset(rva uint32) (int, bool) {
	if rva < p.SizeOfHeaders && int(rva) < p.size {
		// Headers are mapped 1:1. Only honour this when no section claims the
		// RVA, since a bogus SizeOfHeaders could otherwise shadow a section.
		if p.sectionIndexForRVA(rva) < 0 {
			return int(rva), true
		}
	}
	idx := p.sectionIndexForRVA(rva)
	if idx < 0 {
		return 0, false
	}
	s := p.Sections[idx]
	delta := rva - s.VirtualAddress
	if delta >= s.RawSize {
		return 0, false
	}
	off := int64(s.RawOffset) + int64(delta)
	if off < 0 || off >= int64(p.size) {
		return 0, false
	}
	return int(off), true
}

// vaToOffset maps a virtual address (ImageBase-relative) to a file offset.
func (p *PE) vaToOffset(va uint64) (int, bool) {
	if va < p.ImageBase {
		return 0, false
	}
	rva := va - p.ImageBase
	if rva > 0xFFFFFFFF {
		return 0, false
	}
	return p.rvaToOffset(uint32(rva))
}

func (p *PE) parseImports(data []byte) {
	dir := p.DataDirs[dirImport]
	if dir.VirtualAddress == 0 {
		return
	}
	off, ok := p.rvaToOffset(dir.VirtualAddress)
	if !ok {
		p.warn("import directory RVA 0x%x maps outside the file", dir.VirtualAddress)
		return
	}
	ptrSize := 4
	if p.Format == "pe32+" {
		ptrSize = 8
	}
	total := 0
	for n := 0; n < maxImportDLLs; n++ {
		d := off + n*20
		if d+20 > len(data) {
			p.warn("import descriptor table truncated after %d entries", n)
			return
		}
		oft := le32(data, d) // OriginalFirstThunk (import lookup table)
		nameRVA := le32(data, d+12)
		ft := le32(data, d+16) // FirstThunk (IAT)
		if oft == 0 && nameRVA == 0 && ft == 0 {
			return // terminator
		}
		nameOff, ok := p.rvaToOffset(nameRVA)
		if !ok {
			p.warn("import descriptor %d: DLL name RVA 0x%x maps outside the file", n, nameRVA)
			continue
		}
		dll := ImportedDLL{Name: cstring(data, nameOff, maxNameLen)}
		thunk := oft
		if thunk == 0 {
			thunk = ft // bound imports: only the IAT survives
		}
		toff, ok := p.rvaToOffset(thunk)
		if !ok {
			p.warn("import descriptor %d (%s): thunk RVA 0x%x maps outside the file", n, dll.Name, thunk)
			p.Imports = append(p.Imports, dll)
			continue
		}
		for i := 0; i < maxImportsPerDLL && total < maxImportsTotal; i++ {
			e := toff + i*ptrSize
			if e+ptrSize > len(data) {
				p.warn("import thunks for %s truncated", dll.Name)
				break
			}
			var v uint64
			var ordinalFlag uint64
			if ptrSize == 8 {
				v = binary.LittleEndian.Uint64(data[e:])
				ordinalFlag = 1 << 63
			} else {
				v = uint64(le32(data, e))
				ordinalFlag = 1 << 31
			}
			if v == 0 {
				break
			}
			var f ImportedFunc
			if v&ordinalFlag != 0 {
				f.ByOrdinal = true
				f.Ordinal = uint16(v & 0xFFFF)
			} else {
				hintOff, ok := p.rvaToOffset(uint32(v & 0xFFFFFFFF))
				if !ok || hintOff+2 >= len(data) {
					// A bound/forwarded IAT holds addresses, not RVAs. Stop
					// reading this DLL rather than inventing names.
					p.warn("import thunk for %s holds a non-RVA value 0x%x", dll.Name, v)
					break
				}
				f.Name = cstring(data, hintOff+2, maxNameLen)
				if f.Name == "" {
					p.warn("import thunk for %s has an empty name", dll.Name)
					break
				}
			}
			dll.Functions = append(dll.Functions, f)
			total++
		}
		p.Imports = append(p.Imports, dll)
	}
	p.warn("import descriptor table exceeds %d DLLs; remainder ignored", maxImportDLLs)
}

func (p *PE) parseDelayImports(data []byte) {
	dir := p.DataDirs[dirDelayImprt]
	if dir.VirtualAddress == 0 {
		return
	}
	off, ok := p.rvaToOffset(dir.VirtualAddress)
	if !ok {
		p.warn("delay-import directory RVA 0x%x maps outside the file", dir.VirtualAddress)
		return
	}
	for n := 0; n < maxImportDLLs; n++ {
		d := off + n*32
		if d+32 > len(data) {
			return
		}
		attrs := le32(data, d)
		nameRVA := le32(data, d+4)
		if nameRVA == 0 {
			return
		}
		// Attribute bit 0 set means RVAs; clear means VAs (legacy).
		if attrs&1 == 0 && p.ImageBase != 0 {
			if uint64(nameRVA) >= p.ImageBase {
				nameRVA = uint32(uint64(nameRVA) - p.ImageBase)
			}
		}
		nameOff, ok := p.rvaToOffset(nameRVA)
		if !ok {
			p.warn("delay-import %d: name RVA 0x%x maps outside the file", n, nameRVA)
			continue
		}
		p.DelayImports = append(p.DelayImports, cstring(data, nameOff, maxNameLen))
	}
}

func (p *PE) parseExports(data []byte) {
	dir := p.DataDirs[dirExport]
	if dir.VirtualAddress == 0 {
		return
	}
	off, ok := p.rvaToOffset(dir.VirtualAddress)
	if !ok || off+40 > len(data) {
		p.warn("export directory RVA 0x%x maps outside the file", dir.VirtualAddress)
		return
	}
	p.Exports.Present = true
	p.Exports.Timestamp = le32(data, off+4)
	if nameOff, ok := p.rvaToOffset(le32(data, off+12)); ok {
		p.Exports.Name = cstring(data, nameOff, maxNameLen)
	}
	p.Exports.Functions = le32(data, off+20)
	p.Exports.Names = le32(data, off+24)
}

func (p *PE) parseDebug(data []byte) {
	dir := p.DataDirs[dirDebug]
	if dir.VirtualAddress == 0 || dir.Size == 0 {
		return
	}
	off, ok := p.rvaToOffset(dir.VirtualAddress)
	if !ok {
		p.warn("debug directory RVA 0x%x maps outside the file", dir.VirtualAddress)
		return
	}
	n := int(dir.Size / 28)
	if n > 32 {
		n = 32
	}
	for i := 0; i < n; i++ {
		e := off + i*28
		if e+28 > len(data) {
			break
		}
		p.Debug.Present = true
		ts := le32(data, e+4)
		typ := le32(data, e+12)
		size := le32(data, e+16)
		raw := le32(data, e+24)
		if p.Debug.Timestamp == 0 {
			p.Debug.Timestamp = ts
		}
		switch typ {
		case 16: // IMAGE_DEBUG_TYPE_REPRO
			p.Debug.Reproducible = true
		case 2: // IMAGE_DEBUG_TYPE_CODEVIEW
			r := int(raw)
			if raw == 0 || r+24 > len(data) || size < 24 {
				continue
			}
			if string(data[r:r+4]) == "RSDS" {
				g := data[r+4 : r+20]
				p.Debug.GUID = fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
					le32(g, 0), le16(g, 4), le16(g, 6), binary.BigEndian.Uint16(g[8:10]), g[10:16])
				p.Debug.Age = le32(data, r+20)
				p.Debug.PDBPath = cstring(data, r+24, maxNameLen)
			}
		}
	}
}

func (p *PE) parseTLS(data []byte) {
	dir := p.DataDirs[dirTLS]
	if dir.VirtualAddress == 0 {
		return
	}
	off, ok := p.rvaToOffset(dir.VirtualAddress)
	if !ok {
		p.warn("TLS directory RVA 0x%x maps outside the file", dir.VirtualAddress)
		return
	}
	var cbVA uint64
	ptr := 4
	if p.Format == "pe32+" {
		ptr = 8
	}
	if off+4*ptr > len(data) {
		p.warn("TLS directory truncated")
		return
	}
	if ptr == 8 {
		cbVA = binary.LittleEndian.Uint64(data[off+24:])
	} else {
		cbVA = uint64(le32(data, off+12))
	}
	if cbVA == 0 {
		return
	}
	cbOff, ok := p.vaToOffset(cbVA)
	if !ok {
		p.warn("TLS callback table VA 0x%x maps outside the file", cbVA)
		return
	}
	for i := 0; i < maxTLSCallbacks; i++ {
		e := cbOff + i*ptr
		if e+ptr > len(data) {
			break
		}
		var v uint64
		if ptr == 8 {
			v = binary.LittleEndian.Uint64(data[e:])
		} else {
			v = uint64(le32(data, e))
		}
		if v == 0 {
			break
		}
		p.TLSCallbacks++
	}
}

// computeOverlay finds data past the end of the last section and separates
// the Authenticode blob (expected there) from everything else.
func (p *PE) computeOverlay(data []byte) {
	var end int64 = int64(p.SizeOfHeaders)
	for _, s := range p.Sections {
		if s.RawSize == 0 {
			continue
		}
		if e := int64(s.RawOffset) + int64(s.RawSize); e > end {
			end = e
		}
	}
	if end >= int64(len(data)) || end <= 0 {
		return
	}
	p.Overlay.Offset = end
	size := int64(len(data)) - end
	// The certificate table is addressed by file offset. If it starts inside
	// the overlay, it is not "appended data" in the suspicious sense.
	if sec := p.Security; sec.VirtualAddress != 0 && sec.Size != 0 {
		cs, ce := int64(sec.VirtualAddress), int64(sec.VirtualAddress)+int64(sec.Size)
		if cs >= end && cs < int64(len(data)) {
			if ce > int64(len(data)) {
				ce = int64(len(data))
			}
			p.Overlay.CertificateBytes = ce - cs
			// Data before the certificate counts as overlay; data after it does too.
			size -= p.Overlay.CertificateBytes
			if size > 0 {
				buf := make([]byte, 0, size)
				buf = append(buf, data[end:cs]...)
				buf = append(buf, data[ce:]...)
				p.Overlay.Size = size
				p.Overlay.Entropy = Entropy(buf)
			}
			return
		}
	}
	p.Overlay.Size = size
	p.Overlay.Entropy = Entropy(data[end:])
}

// ── helpers ──────────────────────────────────────────────────────────────────

func le16(b []byte, off int) uint16 { return binary.LittleEndian.Uint16(b[off:]) }
func le32(b []byte, off int) uint32 { return binary.LittleEndian.Uint32(b[off:]) }

// cstring reads a NUL-terminated string at off, bounded by max and the buffer.
// Non-printable bytes are replaced so the value is safe to render.
func cstring(b []byte, off, max int) string {
	if off < 0 || off >= len(b) {
		return ""
	}
	end := off
	for end < len(b) && end-off < max && b[end] != 0 {
		end++
	}
	return printable(b[off:end])
}

// cstringFixed reads a fixed-width, optionally NUL-padded field (section names).
func cstringFixed(b []byte) string {
	end := len(b)
	for i, c := range b {
		if c == 0 {
			end = i
			break
		}
	}
	return printable(b[:end])
}

func printable(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		if c >= 0x20 && c <= 0x7e {
			sb.WriteByte(c)
		} else {
			sb.WriteByte('?')
		}
	}
	return sb.String()
}

func perms(ch uint32) string {
	out := []byte("---")
	if ch&scnRead != 0 {
		out[0] = 'r'
	}
	if ch&scnWrite != 0 {
		out[1] = 'w'
	}
	if ch&scnExecute != 0 {
		out[2] = 'x'
	}
	return string(out)
}

func machineName(m uint16) string {
	switch m {
	case 0x14c:
		return "i386"
	case 0x8664:
		return "amd64"
	case 0x1c0, 0x1c4:
		return "arm"
	case 0xaa64:
		return "arm64"
	case 0x200:
		return "ia64"
	case 0:
		return "unknown"
	}
	return fmt.Sprintf("0x%x", m)
}

func subsystemName(s uint16) string {
	switch s {
	case 1:
		return "native"
	case 2:
		return "windows-gui"
	case 3:
		return "windows-cui"
	case 9:
		return "windows-ce"
	case 10:
		return "efi-application"
	case 11:
		return "efi-boot-driver"
	case 12:
		return "efi-runtime-driver"
	case 13:
		return "efi-rom"
	case 14:
		return "xbox"
	case 16:
		return "windows-boot-application"
	case 0:
		return "unknown"
	}
	return fmt.Sprintf("0x%x", s)
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
