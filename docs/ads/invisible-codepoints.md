# ADS: Invisible codepoints (stego)

## Goal
Find text and code artifacts that carry codepoints with no glyph: the
alphabet of zero-width steganography, Trojan Source bidi overrides, TAG
smuggling and data-bearing variation selectors.

## Categorization
T1027 (Obfuscated Files or Information), with the plan's NOVEL-001
(README dead-drop channel) on the zero-width, TAG and variation-selector
classes. Pyramid of Pain: TTPs. Tier: SUSPICIOUS.

## Strategy Abstract
Presence-based: density thresholds are the first thing an encoder drops
below. A closed list of context rules excuses legitimate uses (BOM at offset
0, emoji sequences, joiners beside joining scripts, ZWSP in spaceless scripts,
directional controls on RTL lines, CJK variation sequences, subdivision
flags), each named in the report when it applies. Payload runs and
ASCII-carrier placement raise the score without being findings.

## Technical Context
`scanner/stego`; classes in `stego.Classes()`. Binary content is skipped and
the reason recorded. The default threshold (4) is reached by any scored
class; `--stego-threshold 8` requires a modifier too.

## Blind Spots and Assumptions
A channel that uses visible characters, or lives in a binary format. The
detector sees the carrier, not the plaintext; it cannot say what was
encoded.

## False Positives
70 of 70,102 benign text artifacts (0.10 %): a stray ZERO WIDTH SPACE pasted
into documentation or a translation file, source files that enumerate
Unicode categories, a stray byte-order mark mid-file. 348 legitimate uses
were excused by the context rules; the Khmer and RTL rules exist because
that measurement found them.

## Validation
`scanner/stego/stego_test.go` fixtures for every class and every excuse;
the smoke corpus stego fixtures (`make eval`).

## Priority
Medium; high when a payload run or ASCII carrier is present, which is what
`--stego-threshold 8` selects.

## Response
The report prints the codepoints, their lines and bounded examples with the
invisibles rendered as `<U+200B>`: one stray codepoint with no run is the
documented false-positive class, a run between ASCII words is a channel.
