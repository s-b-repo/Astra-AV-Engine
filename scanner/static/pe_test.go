package static

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"math/big"
	"math/bits"
	"strings"
	"testing"
	"time"
)

// ── synthetic PE builder ─────────────────────────────────────────────────────
//
// The fixtures below are hand-built PE images: real headers, real section
// tables, real import directories, optional Rich header, TLS directory and
// Authenticode blob. They contain no code that does anything (the entry
// point is a RET), which is the point: the tests exercise structure, and the
// corpus policy forbids real samples in the repository.

type secSpec struct {
	name    string
	data    []byte
	virt    uint32 // virtual size; 0 = len(data)
	chars   uint32
	rawZero bool // declare SizeOfRawData = 0 (unpack target)
}

type peSpec struct {
	pe32plus  bool
	dll       bool
	sections  []secSpec
	imports   [][2]string // {dll, func}; func "#N" = ordinal N
	entryRVA  uint32      // 0 = start of the first executable section
	entryIn   string      // or: name of the section to put the entry point in
	timestamp uint32
	overlay   []byte
	rich      *richSpec
	tls       int    // TLS callbacks
	cert      []byte // PKCS#7 blob for the security directory
	fileAlign uint32
	sectAlign uint32
	debugTS   uint32 // emit a debug directory with this timestamp
	repro     bool   // emit an IMAGE_DEBUG_TYPE_REPRO entry
	sectCount int    // override NumberOfSections (hostile headers)
	exportsTS uint32 // emit an export directory with this timestamp
}

type richSpec struct {
	entries []RichEntry
	corrupt bool
}

func align(v, a uint32) uint32 {
	if a == 0 {
		return v
	}
	return (v + a - 1) / a * a
}

func rotl32(x uint32, n int) uint32 { return bits.RotateLeft32(x, n%32) }

// buildPE assembles an image. It is deliberately independent from the parser
// so a bug in one does not hide in the other.
func buildPE(t testing.TB, s peSpec) []byte {
	t.Helper()
	if s.fileAlign == 0 {
		s.fileAlign = 0x200
	}
	if s.sectAlign == 0 {
		s.sectAlign = 0x1000
	}
	ptr := uint32(4)
	optSize := uint32(224)
	if s.pe32plus {
		ptr = 8
		optSize = 240
	}
	imageBase := uint64(0x400000)
	if s.pe32plus {
		imageBase = 0x140000000
	}

	// DOS header (+ optional Rich block).
	dos := make([]byte, 0x40)
	copy(dos, "MZ")
	var richBlock []byte
	if s.rich != nil {
		richBlock = buildRich(dos, s.rich)
	}
	peOff := uint32(len(dos) + len(richBlock))
	binary.LittleEndian.PutUint32(dos[0x3c:], peOff)
	if s.rich != nil {
		// The checksum covers the DOS header with e_lfanew zeroed, which is
		// how buildRich computed it; now fix e_lfanew in.
	}

	// Decide which extra sections the spec implies.
	sections := append([]secSpec(nil), s.sections...)
	var idataIdx, tlsIdx, debugIdx, edataIdx = -1, -1, -1, -1
	if len(s.imports) > 0 {
		idataIdx = len(sections)
		sections = append(sections, secSpec{name: ".idata", chars: scnInitializedData | scnRead | scnWrite})
	}
	if s.tls > 0 {
		tlsIdx = len(sections)
		sections = append(sections, secSpec{name: ".tls", chars: scnInitializedData | scnRead | scnWrite})
	}
	if s.debugTS != 0 || s.repro {
		debugIdx = len(sections)
		sections = append(sections, secSpec{name: ".dbg", chars: scnInitializedData | scnRead})
	}
	if s.exportsTS != 0 {
		edataIdx = len(sections)
		sections = append(sections, secSpec{name: ".edata", chars: scnInitializedData | scnRead})
	}

	nSec := uint32(len(sections))
	headersEnd := peOff + 4 + 20 + optSize + nSec*40
	sizeOfHeaders := align(headersEnd, s.fileAlign)

	// Lay out virtual addresses first; data for synthetic sections depends on
	// its own VA, so compute VAs with provisional sizes, build, then fix sizes.
	vas := make([]uint32, nSec)
	raws := make([]uint32, nSec)
	va := s.sectAlign
	raw := sizeOfHeaders
	datas := make([][]byte, nSec)
	for i := range sections {
		vas[i] = va
		raws[i] = raw
		switch i {
		case idataIdx:
			datas[i] = buildImports(va, ptr, s.imports)
		case tlsIdx:
			datas[i] = buildTLS(va, imageBase, ptr, s.tls)
		case debugIdx:
			datas[i] = buildDebug(va, s.debugTS, s.repro)
		case edataIdx:
			datas[i] = buildExports(va, s.exportsTS)
		default:
			datas[i] = sections[i].data
		}
		vs := sections[i].virt
		if vs == 0 {
			vs = uint32(len(datas[i]))
		}
		if vs == 0 {
			vs = 1
		}
		va = align(va+vs, s.sectAlign)
		if !sections[i].rawZero {
			raw += align(uint32(len(datas[i])), s.fileAlign)
		}
	}
	sizeOfImage := va

	// Entry point.
	entry := s.entryRVA
	if entry == 0 {
		for i, sec := range sections {
			if s.entryIn != "" && sec.name == s.entryIn || s.entryIn == "" && sec.chars&scnExecute != 0 {
				entry = vas[i]
				break
			}
		}
	}

	// Headers.
	var b bytes.Buffer
	b.Write(dos)
	b.Write(richBlock)
	b.WriteString("PE\x00\x00")
	coff := make([]byte, 20)
	machine := uint16(0x14c)
	if s.pe32plus {
		machine = 0x8664
	}
	binary.LittleEndian.PutUint16(coff[0:], machine)
	nDeclared := uint16(nSec)
	if s.sectCount != 0 {
		nDeclared = uint16(s.sectCount)
	}
	binary.LittleEndian.PutUint16(coff[2:], nDeclared)
	binary.LittleEndian.PutUint32(coff[4:], s.timestamp)
	binary.LittleEndian.PutUint16(coff[16:], uint16(optSize))
	chars := uint16(0x0102) // EXECUTABLE_IMAGE | 32BIT_MACHINE
	if s.dll {
		chars |= charDLL
	}
	binary.LittleEndian.PutUint16(coff[18:], chars)
	b.Write(coff)

	opt := make([]byte, optSize)
	if s.pe32plus {
		binary.LittleEndian.PutUint16(opt[0:], 0x20b)
		binary.LittleEndian.PutUint32(opt[16:], entry)
		binary.LittleEndian.PutUint64(opt[24:], imageBase)
	} else {
		binary.LittleEndian.PutUint16(opt[0:], 0x10b)
		binary.LittleEndian.PutUint32(opt[16:], entry)
		binary.LittleEndian.PutUint32(opt[28:], uint32(imageBase))
	}
	binary.LittleEndian.PutUint32(opt[32:], s.sectAlign)
	binary.LittleEndian.PutUint32(opt[36:], s.fileAlign)
	binary.LittleEndian.PutUint32(opt[56:], sizeOfImage)
	binary.LittleEndian.PutUint32(opt[60:], sizeOfHeaders)
	binary.LittleEndian.PutUint16(opt[68:], 3) // console
	dirOff := 96
	if s.pe32plus {
		binary.LittleEndian.PutUint32(opt[108:], 16)
		dirOff = 112
	} else {
		binary.LittleEndian.PutUint32(opt[92:], 16)
	}
	setDir := func(i int, rva, size uint32) {
		binary.LittleEndian.PutUint32(opt[dirOff+i*8:], rva)
		binary.LittleEndian.PutUint32(opt[dirOff+i*8+4:], size)
	}
	if idataIdx >= 0 {
		setDir(dirImport, vas[idataIdx], uint32(20*(countDLLs(s.imports)+1)))
	}
	if tlsIdx >= 0 {
		setDir(dirTLS, vas[tlsIdx], 24)
	}
	if debugIdx >= 0 {
		setDir(dirDebug, vas[debugIdx], uint32(len(datas[debugIdx])))
	}
	if edataIdx >= 0 {
		setDir(dirExport, vas[edataIdx], 40)
	}

	// Security directory: appended after everything else.
	fileEnd := raw
	overlayStart := fileEnd
	certStart := overlayStart + uint32(len(s.overlay))
	if len(s.cert) > 0 {
		certStart = align(certStart, 8)
		wc := 8 + uint32(len(s.cert))
		setDir(dirSecurity, certStart, align(wc, 8))
	}
	b.Write(opt)

	for i, sec := range sections {
		h := make([]byte, 40)
		copy(h, sec.name)
		vs := sec.virt
		if vs == 0 {
			vs = uint32(len(datas[i]))
		}
		binary.LittleEndian.PutUint32(h[8:], vs)
		binary.LittleEndian.PutUint32(h[12:], vas[i])
		if sec.rawZero {
			binary.LittleEndian.PutUint32(h[16:], 0)
			binary.LittleEndian.PutUint32(h[20:], 0)
		} else {
			binary.LittleEndian.PutUint32(h[16:], align(uint32(len(datas[i])), s.fileAlign))
			binary.LittleEndian.PutUint32(h[20:], raws[i])
		}
		binary.LittleEndian.PutUint32(h[36:], sec.chars)
		b.Write(h)
	}
	pad(&b, int(sizeOfHeaders))
	for i, sec := range sections {
		if sec.rawZero {
			continue
		}
		if uint32(b.Len()) != raws[i] {
			t.Fatalf("layout bug: section %d at %d, want %d", i, b.Len(), raws[i])
		}
		b.Write(datas[i])
		pad(&b, int(align(uint32(b.Len()), s.fileAlign)))
	}
	b.Write(s.overlay)
	if len(s.cert) > 0 {
		pad(&b, int(certStart))
		wc := make([]byte, 8)
		binary.LittleEndian.PutUint32(wc, uint32(8+len(s.cert)))
		binary.LittleEndian.PutUint16(wc[4:], 0x0200)
		binary.LittleEndian.PutUint16(wc[6:], 0x0002)
		b.Write(wc)
		b.Write(s.cert)
		pad(&b, int(align(uint32(b.Len()), 8)))
	}
	return b.Bytes()
}

func pad(b *bytes.Buffer, to int) {
	for b.Len() < to {
		b.WriteByte(0)
	}
}

func countDLLs(imports [][2]string) int {
	seen := map[string]bool{}
	for _, im := range imports {
		seen[im[0]] = true
	}
	return len(seen)
}

// buildImports lays out descriptors, ILT+IAT thunks, hint/name entries and
// DLL names inside one section starting at base.
func buildImports(base uint32, ptr uint32, imports [][2]string) []byte {
	var dlls []string
	byDLL := map[string][]string{}
	for _, im := range imports {
		if _, ok := byDLL[im[0]]; !ok {
			dlls = append(dlls, im[0])
		}
		byDLL[im[0]] = append(byDLL[im[0]], im[1])
	}
	descSize := uint32(20 * (len(dlls) + 1))
	var thunks, names bytes.Buffer
	// Thunk area size: for each DLL, (n+1)*ptr for ILT, same for IAT.
	thunkSize := uint32(0)
	for _, d := range dlls {
		thunkSize += 2 * uint32(len(byDLL[d])+1) * ptr
	}
	thunkBase := base + descSize
	namesBase := thunkBase + thunkSize

	desc := make([]byte, descSize)
	thunkOff := uint32(0)
	for i, d := range dlls {
		iltRVA := thunkBase + thunkOff
		var ilt bytes.Buffer
		for _, fn := range byDLL[d] {
			var v uint64
			if strings.HasPrefix(fn, "#") {
				var ord uint64
				for _, c := range fn[1:] {
					ord = ord*10 + uint64(c-'0')
				}
				if ptr == 8 {
					v = 1<<63 | ord
				} else {
					v = 1<<31 | ord
				}
			} else {
				v = uint64(namesBase + uint32(names.Len()))
				names.Write([]byte{0, 0}) // hint
				names.WriteString(fn)
				names.WriteByte(0)
				if names.Len()%2 == 1 {
					names.WriteByte(0)
				}
			}
			writePtr(&ilt, ptr, v)
		}
		writePtr(&ilt, ptr, 0)
		iatRVA := iltRVA + uint32(ilt.Len())
		thunks.Write(ilt.Bytes())
		thunks.Write(ilt.Bytes()) // IAT mirrors ILT on disk
		thunkOff += 2 * uint32(ilt.Len())

		nameRVA := namesBase + uint32(names.Len())
		names.WriteString(d)
		names.WriteByte(0)

		o := i * 20
		binary.LittleEndian.PutUint32(desc[o:], iltRVA)
		binary.LittleEndian.PutUint32(desc[o+12:], nameRVA)
		binary.LittleEndian.PutUint32(desc[o+16:], iatRVA)
	}
	var out bytes.Buffer
	out.Write(desc)
	out.Write(thunks.Bytes())
	out.Write(names.Bytes())
	return out.Bytes()
}

func writePtr(b *bytes.Buffer, ptr uint32, v uint64) {
	if ptr == 8 {
		var x [8]byte
		binary.LittleEndian.PutUint64(x[:], v)
		b.Write(x[:])
	} else {
		var x [4]byte
		binary.LittleEndian.PutUint32(x[:], uint32(v))
		b.Write(x[:])
	}
}

// buildTLS writes an IMAGE_TLS_DIRECTORY followed by n callback pointers.
func buildTLS(base uint32, imageBase uint64, ptr uint32, n int) []byte {
	dirSize := uint32(24)
	if ptr == 8 {
		dirSize = 40
	}
	var b bytes.Buffer
	cbVA := imageBase + uint64(base+dirSize)
	if ptr == 8 {
		writePtr(&b, 8, 0)
		writePtr(&b, 8, 0)
		writePtr(&b, 8, 0)
		writePtr(&b, 8, cbVA)
		b.Write(make([]byte, 8))
	} else {
		writePtr(&b, 4, 0)
		writePtr(&b, 4, 0)
		writePtr(&b, 4, 0)
		writePtr(&b, 4, cbVA)
		b.Write(make([]byte, 8))
	}
	for i := 0; i < n; i++ {
		writePtr(&b, ptr, imageBase+0x1000+uint64(i*16))
	}
	writePtr(&b, ptr, 0)
	return b.Bytes()
}

// buildDebug writes debug directory entries.
func buildDebug(base uint32, ts uint32, repro bool) []byte {
	var b bytes.Buffer
	entry := func(typ, ts uint32) {
		e := make([]byte, 28)
		binary.LittleEndian.PutUint32(e[4:], ts)
		binary.LittleEndian.PutUint32(e[12:], typ)
		b.Write(e)
	}
	if ts != 0 {
		entry(2, ts) // CODEVIEW without RSDS data
	}
	if repro {
		entry(16, 0)
	}
	return b.Bytes()
}

func buildExports(base uint32, ts uint32) []byte {
	e := make([]byte, 40)
	binary.LittleEndian.PutUint32(e[4:], ts)
	binary.LittleEndian.PutUint32(e[20:], 1)
	return e
}

// buildRich produces a DanS..Rich block with a valid (or corrupted) checksum
// for the given DOS header.
func buildRich(dos []byte, spec *richSpec) []byte {
	// Checksum over the DOS header with e_lfanew zeroed, as if DanS starts
	// right after it.
	start := len(dos)
	sum := uint32(start)
	for i := 0; i < start; i++ {
		if i >= 0x3c && i < 0x40 {
			continue
		}
		sum += rotl32(uint32(dos[i]), i)
	}
	for _, e := range spec.entries {
		compid := uint32(e.ProductID)<<16 | uint32(e.Build)
		sum += rotl32(compid, int(e.Count))
	}
	key := sum
	if spec.corrupt {
		key ^= 0xDEADBEEF
	}
	var b bytes.Buffer
	put := func(v uint32) {
		var x [4]byte
		binary.LittleEndian.PutUint32(x[:], v^key)
		b.Write(x[:])
	}
	put(dansMarker)
	put(0)
	put(0)
	put(0)
	for _, e := range spec.entries {
		put(uint32(e.ProductID)<<16 | uint32(e.Build))
		put(e.Count)
	}
	var x [4]byte
	binary.LittleEndian.PutUint32(x[:], richMarker)
	b.Write(x[:])
	binary.LittleEndian.PutUint32(x[:], key)
	b.Write(x[:])
	// Pad to 16 bytes so e_lfanew stays aligned.
	for b.Len()%16 != 0 {
		b.WriteByte(0)
	}
	return b.Bytes()
}

// ── Authenticode fixture ─────────────────────────────────────────────────────

type certOpts struct {
	subject     string
	notBefore   time.Time
	notAfter    time.Time
	codeSigning bool
}

// selfSignedPKCS7 builds a PKCS#7 SignedData carrying one self-signed
// certificate and a SignerInfo that names it. The encrypted digest is random:
// nothing verifies it, by design, and the parser must not pretend otherwise.
func selfSignedPKCS7(t testing.TB, o certOpts) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0x1234abcd),
		Subject:      pkix.Name{CommonName: o.subject, Organization: []string{o.subject}},
		NotBefore:    o.notBefore,
		NotAfter:     o.notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if o.codeSigning {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	sha256OID := asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	ecdsaOID := asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	type alg struct {
		Algorithm  asn1.ObjectIdentifier
		Parameters asn1.RawValue `asn1:"optional"`
	}
	type ias struct {
		Issuer asn1.RawValue
		Serial *big.Int
	}
	type si struct {
		Version         int
		IssuerAndSerial ias
		DigestAlgorithm alg
		DigestEncAlg    alg
		EncryptedDigest []byte
	}
	type sd struct {
		Version          int
		DigestAlgorithms []alg `asn1:"set"`
		ContentInfo      struct {
			ContentType asn1.ObjectIdentifier
		}
		Certificates asn1.RawValue `asn1:"tag:0"`
		SignerInfos  []si          `asn1:"set"`
	}
	digest := sha256.Sum256([]byte("not a real digest"))
	body := sd{
		Version:          1,
		DigestAlgorithms: []alg{{Algorithm: sha256OID}},
		Certificates:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: der},
		SignerInfos: []si{{
			Version:         1,
			IssuerAndSerial: ias{Issuer: asn1.RawValue{FullBytes: cert.RawIssuer}, Serial: cert.SerialNumber},
			DigestAlgorithm: alg{Algorithm: sha256OID},
			DigestEncAlg:    alg{Algorithm: ecdsaOID},
			EncryptedDigest: digest[:],
		}},
	}
	body.ContentInfo.ContentType = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 4} // SPC_INDIRECT_DATA
	sdDER, err := asn1.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	// asn1.Marshal ignores "explicit" on a RawValue field, so the [0] wrapper
	// that every real Authenticode ContentInfo carries is built by hand.
	type ci struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue
	}
	out, err := asn1.Marshal(ci{ContentType: oidSignedData, Content: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: sdDER}})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// ── fixtures ─────────────────────────────────────────────────────────────────

var (
	textChars  = uint32(scnCode | scnExecute | scnRead)
	dataChars  = uint32(scnInitializedData | scnRead | scnWrite)
	rdataChars = uint32(scnInitializedData | scnRead)
)

// plainCode is low-entropy "code": a RET followed by NOP padding and some
// text, which is what a tiny real program looks like.
func plainCode(n int) []byte {
	b := make([]byte, n)
	b[0] = 0xC3
	for i := 1; i < n; i++ {
		b[i] = byte(0x90 + (i % 7))
	}
	copy(b[n/2:], "Hello from a boring console program. Nothing to see here.")
	return b
}

// randomBytes is maximum-entropy content: compressed or encrypted payload.
func randomBytes(t testing.TB, n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

var normalImports = [][2]string{
	{"KERNEL32.dll", "GetStdHandle"}, {"KERNEL32.dll", "WriteFile"}, {"KERNEL32.dll", "ExitProcess"},
	{"KERNEL32.dll", "GetCommandLineA"}, {"KERNEL32.dll", "GetLastError"},
	{"USER32.dll", "MessageBoxA"},
	{"ADVAPI32.dll", "RegOpenKeyExA"}, {"ADVAPI32.dll", "RegCloseKey"},
}

var sane = uint32(time.Date(2024, 3, 1, 12, 0, 0, 0, time.UTC).Unix())

func benignSpec() peSpec {
	return peSpec{
		sections: []secSpec{
			{name: ".text", data: plainCode(0x800), chars: textChars},
			{name: ".rdata", data: []byte(strings.Repeat("const data ", 50)), chars: rdataChars},
			{name: ".data", data: make([]byte, 0x200), chars: dataChars},
		},
		imports:   normalImports,
		timestamp: sane,
		rich:      &richSpec{entries: []RichEntry{{ProductID: 0x104, Build: 30146, Count: 12}, {ProductID: 0x102, Build: 30146, Count: 1}}},
	}
}

func upxSpec() peSpec {
	return peSpec{
		sections: []secSpec{
			{name: "UPX0", virt: 0x20000, chars: scnUninitializedData | scnExecute | scnRead | scnWrite, rawZero: true},
			{name: "UPX1", data: append([]byte{0x60, 0xBE, 0x00, 0x90, 0x40, 0x00, 0x8D, 0xBE, 0x00, 0x80, 0xFF, 0xFF}, randomBytes(nil, 0x3000)...), chars: scnCode | scnExecute | scnRead | scnWrite},
			{name: ".rsrc", data: make([]byte, 0x200), chars: dataChars},
		},
		entryIn:   "UPX1",
		imports:   [][2]string{{"KERNEL32.DLL", "LoadLibraryA"}, {"KERNEL32.DLL", "GetProcAddress"}, {"KERNEL32.DLL", "VirtualProtect"}, {"KERNEL32.DLL", "ExitProcess"}},
		timestamp: sane,
	}
}

func fixtureNow() time.Time { return time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC) }

func analyze(t testing.TB, data []byte) *Result {
	t.Helper()
	return Analyze(data, Options{Now: fixtureNow()})
}

func classes(r *Result) []string {
	var out []string
	for _, a := range r.Anomalies {
		out = append(out, a.Class)
	}
	return out
}

func hasClass(r *Result, class string) bool {
	for _, a := range r.Anomalies {
		if a.Class == class {
			return true
		}
	}
	return false
}
