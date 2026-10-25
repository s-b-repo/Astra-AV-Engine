// Package scanner is the CAU EDR detection engine: it reads a file once and
// runs every configured detector over the same bytes.
//
// # Detectors and tiers
//
//   - Hash signatures (SignatureDB): MD5 / SHA-1 / SHA-256 against a validated,
//     de-duplicated database. A hit is MALICIOUS.
//   - YARA (YaraScanner): rules compiled once with libyara, matched in memory
//     with a per-file timeout; rule meta and namespaces are kept. A match is
//     MALICIOUS.
//   - Heuristics (ScanHeuristicsData): suspicious PE imports and strings,
//     scored once per pattern with per-category caps and a shared budget for
//     the weak categories; every category carries an ATT&CK technique. A
//     score at or above the threshold is SUSPICIOUS.
//   - Static structure (package static): entropy, fuzzy digests and a
//     bounds-checked PE pass producing labeled anomaly classes. SUSPICIOUS.
//   - Stego (package stego): invisible Unicode codepoints in text and code
//     artifacts, presence-based with named context exceptions. SUSPICIOUS.
//   - Fusion (package fusion): the lattice over all of the above. It never
//     lowers a verdict and can raise CLEAN to SUSPICIOUS when sub-threshold
//     sources corroborate each other; it reports which sources agreed.
//
// # Entry points
//
// Engine is the type to use: configure the detectors, then call ScanFile or
// ScanDirectory. ScanFile returns the ScanResult (hash, YARA, static, stego
// and fusion outcomes) and the HeuristicResult as a separate value, because
// heuristics produce a score rather than a verdict. ScanFile and ScanDirectory
// at package level are thin compatibility wrappers over an Engine with hashes
// and YARA only.
//
// Files larger than Engine.MaxInMemory are streamed: hashing streams, YARA
// memory-maps, and the heuristic, static and stego passes record that they
// were skipped and why. An Engine is safe for concurrent use.
//
// # Rendering
//
// Nothing here prints. internal/report turns ScanResult and HeuristicResult
// into text, JSON and SARIF and decides the exit code; internal/eval measures
// the detectors against a labeled corpus.
package scanner
