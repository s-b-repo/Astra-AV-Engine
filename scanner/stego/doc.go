// Package stego detects invisible Unicode codepoints hidden in text and code
// artifacts: the carrier used by zero-width steganography (README dead-drop
// command channels, encoded payloads between the words of a comment), by
// Trojan Source bidirectional-override attacks on source code, by Unicode
// TAG-character "ASCII smuggling" and by variation-selector byte encoding.
//
// This is the engine half of the plan's NOVEL-001 / NOVEL-002 rows (Phase 10)
// and the T1027 row of the Linux coverage matrix (Phase 11).
//
// # Detection policy
//
// The detector is presence-based, not density-based. Density thresholds are
// the first thing an encoder drops below, so any invisible codepoint that has
// no legitimate reason to be where it is counts. "Legitimate reason" is a
// closed list of context rules, each of which the report names when it
// applies:
//
//   - U+FEFF at offset 0 is a byte-order mark.
//   - ZERO WIDTH JOINER next to a pictographic (emoji) codepoint, a skin-tone
//     modifier or a presentation selector is an emoji sequence.
//   - ZERO WIDTH JOINER / NON-JOINER next to a character of a script that
//     uses joiners (Arabic, Persian, the Indic scripts, Myanmar, Khmer,
//     Mongolian, ...) is typography.
//   - ZERO WIDTH SPACE next to a character of a script written without
//     spaces (Khmer, Thai, Lao, Myanmar, Tibetan) is that script's word
//     separator.
//   - A directional embedding, override or isolate on a line that holds
//     right-to-left text is bidirectional typesetting. On a line of ASCII it
//     is a display attack on source code and stays scored.
//   - VARIATION SELECTOR-15/16 directly after a pictographic codepoint is
//     emoji presentation; the CJK variation selectors directly after a CJK
//     ideograph are ideographic variants. A selector after anything else, or
//     a second selector in a row, carries data.
//   - TAG characters inside a subdivision-flag emoji sequence (after U+1F3F4)
//     are a flag.
//
// Everything else of the kinds listed in codepoints.go is reported, with the
// line it first appears on, how many times, and a bounded example rendering
// the invisible codepoints visibly. Two modifiers raise the score without
// being findings on their own: a run of eight or more consecutive invisible
// codepoints (an encoded payload has length) and invisible codepoints whose
// nearest visible neighbours on both sides are ASCII (the dead-drop pattern:
// English prose or source code is the carrier).
//
// Directional-format marks (LRM, RLM, ALM) and the soft hyphen are recorded
// for completeness but never scored: editors insert them into ordinary
// bidirectional text and HTML, and scoring them would make the detector
// unusable on exactly the documents it is supposed to protect.
//
// # Honesty
//
// The expected false-positive classes, measured on 70,000 benign text
// artifacts from Kali's /usr/share/doc and /usr/lib/python3/dist-packages
// (see PLAN.md): a ZERO WIDTH SPACE pasted from a web page or a word
// processor into documentation or a translation file, and source files that
// enumerate Unicode categories (regular-expression libraries, identifier
// tables) and so contain one or two of every invisible codepoint. The plan handles that with
// package provenance on the sensor side; the engine reports what it saw and
// where, so an analyst can tell a stray U+200B from forty of them between
// every word of a paragraph. The score and threshold exist so an operator can
// require a modifier (--stego-threshold 8) rather than presence.
//
// Only text artifacts are examined: valid UTF-8, or UTF-16 with a byte-order
// mark, without NUL bytes and with a negligible share of control characters.
// Binary files are skipped with the reason recorded, because the UTF-8 byte
// sequence of U+200B occurs by chance inside compressed data.
//
// A YARA rule cannot replace this detector: YARA sees bytes, not context, so
// a rule for the UTF-8 encoding of U+200D would fire on every family emoji.
// The detector is written once here and surfaced through the engine, the
// reports, the fusion lattice and the evaluation harness.
package stego
