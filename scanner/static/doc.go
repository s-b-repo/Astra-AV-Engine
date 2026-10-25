// Package static is the structural (Phase 2) analysis layer of the CAU engine:
// entropy, fuzzy hashes, PE and ELF anatomy and the anomalies that fall out
// of them.
//
// It answers a different question from the other detectors. Hash signatures
// say "this exact file is known"; YARA says "this content pattern is known";
// the string/API heuristics say "this file names suspicious capabilities".
// This package says "this file is *built* like something that is hiding":
// packed, appended to, mis-signed, stripped of its build record, or
// structurally impossible for a compiler to have produced.
//
// # Design rules
//
//   - Own parsers, bounds-checked everywhere. The standard library's debug/pe
//     drops imports by ordinal (which breaks imphash) and trusts header sizes;
//     debug/elf allocates whatever the header declares. Every offset read
//     here is checked against the buffer and every table is capped; a
//     malformed file yields a Result with Warnings, never a panic.
//   - Anomalies are labeled sub-rows, not one opaque score. Each carries a
//     stable class name, a category, a weight and a human detail so a report
//     can say *which* anomaly fired. Scoring reuses the heuristic model: one
//     score per class per file, a cap per category, a threshold.
//   - Packed is not malicious. A packer verdict is evidence that the content
//     could not be inspected, which raises the score, but the report says
//     "packed with UPX", not "malware".
//   - Interposition is not infection. A shared object that redefines libc's
//     readdir/open/accept and resolves the originals with dlsym has the
//     shape of an LD_PRELOAD rootkit; sanitizer runtimes, fakeroot and
//     sudo's noexec shim have the same shape on purpose and are named, not
//     scored. A kernel module's appended signature is reported as present or
//     absent; nothing here can verify it.
//   - Signature presence is not signature validity. The Authenticode blob is
//     parsed for its certificate chain and the chain is examined for
//     implausibility (self-signed, vendor name on a self-signed leaf, compiled
//     outside the certificate's validity). Nothing is verified against a trust
//     store and the result says so explicitly.
//   - Fuzzy hashes are inputs to the score, never a verdict alone. A close
//     TLSH or ssdeep match to a known sample reaches the threshold on its own,
//     but it lands in the SUSPICIOUS tier with its distance attached, not in
//     the MALICIOUS tier that exact hashes and YARA occupy.
//
// Every threshold and weight in this package was measured against the Windows
// tool set shipped with Kali (/usr/share/windows-resources) and against the
// ELF population of a Kali install (/usr/bin, /usr/sbin, /usr/lib, kernel
// modules) so that ordinary unpacked software stays below the threshold; see
// static_test.go, elf_test.go and measure_test.go.
package static
