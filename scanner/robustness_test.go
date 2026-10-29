package scanner

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"sort"
	"testing"
	"unicode/utf16"
)

// Detection-robustness harness.
//
// It measures how much benign, generic, structure-level perturbation each
// string/import detector survives before it stops firing — the "evasion
// distance" the plan asks for (Phase 6), done the defensive way: on SYNTHETIC
// fixtures only, to quantify which detections are brittle so they can be
// hardened, and to catch a detector that silently regresses. It builds no
// real sample and ships no bypass; the transforms below are generic and are
// already named in docs/limitations.md.

type robustSample struct {
	name string
	data []byte
	// wantYara / wantHeur: the detectors expected to fire on the untouched
	// sample (the true positive the harness locks in).
	wantYara, wantHeur bool
}

type transform struct {
	name string
	fn   func([]byte) []byte
	// preserving is true when the transform keeps the malicious indicators a
	// defender should still catch (so a miss is a real robustness gap, not an
	// expected loss from mangling the content).
	preserving bool
}

func toUTF16LE(b []byte) []byte {
	out := make([]byte, 0, len(b)*2)
	for _, r := range utf16.Encode([]rune(string(b))) {
		out = append(out, byte(r), byte(r>>8))
	}
	return out
}

func nulInfix(b []byte) []byte {
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, c, 0x00)
	}
	return out
}

func robustTransforms() []transform {
	junk := bytes.Repeat([]byte("the quick brown fox. "), 200)
	return []transform{
		{"identity", func(b []byte) []byte { return b }, true},
		{"upper", bytes.ToUpper, true},
		{"lower", bytes.ToLower, true},
		{"wide-utf16", toUTF16LE, true},
		{"prefix-junk", func(b []byte) []byte { return append(append([]byte{}, junk...), b...) }, true},
		{"suffix-junk", func(b []byte) []byte { return append(append([]byte{}, b...), junk...) }, true},
		// The classic evasions docs/limitations.md already names: they destroy
		// the contiguous byte sequence a string rule matches. A miss here is
		// expected, not a regression — the harness records it as the gap.
		{"nul-infix", nulInfix, false},
		{"base64", func(b []byte) []byte { return []byte(base64.StdEncoding.EncodeToString(b)) }, false},
	}
}

func TestDetectionRobustnessEnvelope(t *testing.T) {
	ys := loadRepoYara(t)
	measure := func(data []byte) (yara, heur bool) {
		m, _ := ys.ScanMemYaraStrict(data)
		h := ScanHeuristicsData("sample", data, HeuristicOptions{Threshold: HeuristicThreshold})
		return len(m) > 0, h.Detected()
	}

	// Synthetic samples, built here so no real malware is involved.
	mimikatz := []byte("sekurlsa::logonpasswords\nlsadump::sam\nprivilege::debug\nkerberos::tickets\n")
	samples := []robustSample{
		{"wannacry", []byte(wannacrySample), true, false},
		{"mimikatz", mimikatz, true, true},
	}

	transforms := robustTransforms()
	// Report matrix + collect gaps.
	type gap struct{ sample, transform, detector string }
	var gaps []gap
	t.Logf("detection robustness (Y=yara H=heuristic, lowercase=missed):")
	for _, s := range samples {
		// Lock in the baseline true positive.
		by, bh := measure(s.data)
		if by != s.wantYara || bh != s.wantHeur {
			t.Errorf("%s baseline: yara=%v heur=%v, want yara=%v heur=%v", s.name, by, bh, s.wantYara, s.wantHeur)
		}
		var row []string
		for _, tr := range transforms {
			y, h := measure(tr.fn(s.data))
			ymark, hmark := "Y", "H"
			if !y {
				ymark = "y"
			}
			if !h {
				hmark = "h"
			}
			row = append(row, fmt.Sprintf("%s:%s%s", tr.name, ymark, hmark))
			// A preserving transform that drops a baseline-positive detector
			// is a robustness regression we want to know about.
			if tr.preserving {
				if s.wantYara && !y {
					gaps = append(gaps, gap{s.name, tr.name, "yara"})
				}
				if s.wantHeur && !h {
					gaps = append(gaps, gap{s.name, tr.name, "heuristic"})
				}
			}
		}
		t.Logf("  %-9s %s", s.name, row)
	}

	// Sort and report the brittle (preserving-transform) gaps.
	sort.Slice(gaps, func(i, j int) bool {
		return gaps[i].sample+gaps[i].transform+gaps[i].detector < gaps[j].sample+gaps[j].transform+gaps[j].detector
	})
	for _, g := range gaps {
		t.Errorf("BRITTLE: %s evades %s detection under benign transform %q (harden the rule, e.g. add nocase/wide)",
			g.sample, g.detector, g.transform)
	}
}
