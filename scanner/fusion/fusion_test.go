package fusion

import (
	"math/rand"
	"reflect"
	"testing"
)

func src(name string, score, threshold int, ev ...Evidence) Source {
	return Source{Name: name, Score: score, Threshold: threshold, Evidence: ev}
}

func TestSingleSourceAtThresholdStillFires(t *testing.T) {
	// The lattice changes nothing for a detector that fires on its own.
	v := Fuse([]Source{src("heuristic", 7, 7, Evidence{Label: "heuristic/process-injection", Technique: "T1055"}), src("static", 0, 8)})
	if v.Tier != TierSuspicious || v.Score != 1 || v.Corroborated || v.Confidence != "medium" {
		t.Errorf("verdict = %+v", v)
	}
	if !reflect.DeepEqual(v.Agreed, []string{"heuristic"}) || !reflect.DeepEqual(v.Techniques, []string{"T1055"}) {
		t.Errorf("agreed=%v techniques=%v", v.Agreed, v.Techniques)
	}
	if v.Sources[1].Role != RoleSilent {
		t.Errorf("static role = %s", v.Sources[1].Role)
	}
}

func TestCorroborationCrossesWhatNeitherSourceDoes(t *testing.T) {
	v := Fuse([]Source{
		src("heuristic", 5, 7, Evidence{Label: "heuristic/process-injection", Technique: "T1055", Weight: 5}),
		src("static", 6, 8, Evidence{Label: "static/packer.upx", Technique: "T1027.002", Weight: 2}, Evidence{Label: "static/section.rwx", Technique: "T1027.009", Weight: 3}),
	})
	// 5/7 = 0.714 primary; 6/8 = 0.75 is actually the larger ratio, so static
	// is primary: 0.75 + 0.5*0.714 = 1.107.
	if v.Tier != TierSuspicious || !v.Corroborated || v.Score != 1.107 {
		t.Fatalf("verdict = %+v", v)
	}
	if v.Sources[0].Name != "static" || v.Sources[0].Role != RolePrimary || v.Sources[1].Role != RoleCorroborating {
		t.Errorf("roles = %+v", v.Sources)
	}
	if !reflect.DeepEqual(v.Techniques, []string{"T1027.002", "T1027.009", "T1055"}) {
		t.Errorf("techniques = %v", v.Techniques)
	}
	if v.Explanation == "" || v.Explanation[:11] != "SUSPICIOUS:" {
		t.Errorf("explanation = %q", v.Explanation)
	}
}

func TestBelowFloorDoesNotCorroborate(t *testing.T) {
	// 0.857 + nothing: a single Sleep import (1/7) is not corroboration.
	v := Fuse([]Source{src("static", 7, 8), src("heuristic", 1, 7)})
	if v.Tier != TierObserved || v.Score != 0.875 || v.Sources[1].Role != RoleBelowFloor || v.Sources[1].Counted {
		t.Errorf("verdict = %+v", v)
	}
	if len(v.Agreed) != 1 {
		t.Errorf("agreed = %v", v.Agreed)
	}
}

func TestDefinitiveSourceIsNeverDowngraded(t *testing.T) {
	v := Fuse([]Source{
		{Name: "hash", Definitive: true, Hit: true, Evidence: []Evidence{{Label: "hash/sha256", Detail: "WannaCry"}}},
		src("heuristic", 0, 7),
		src("static", 2, 8),
	})
	if v.Tier != TierMalicious || v.Confidence != "high" || v.Sources[0].Role != RoleDefinitive {
		t.Errorf("verdict = %+v", v)
	}
	if v.Explanation != "MALICIOUS: hash (hash/sha256), no other source saw anything" {
		t.Errorf("explanation = %q", v.Explanation)
	}
	// Static at 2/8 is primary among the scored sources but adds no
	// corroboration claim to the explanation because it did not reach the
	// floor... it is primary, so it counts. Check the wording with a real one.
	v = Fuse([]Source{
		{Name: "yara", Definitive: true, Hit: true, Evidence: []Evidence{{Label: "yara/default/mimikatz_strings"}}},
		src("heuristic", 9, 7),
	})
	if v.Explanation != "MALICIOUS: yara (yara/default/mimikatz_strings), corroborated by heuristic 9/7" || v.Confidence != "high" {
		t.Errorf("explanation = %q confidence = %s", v.Explanation, v.Confidence)
	}
	// A lone YARA hit without corroboration is medium confidence; a lone hash
	// hit stays high (a digest is identity).
	if v := Fuse([]Source{{Name: "yara", Definitive: true, Hit: true}}); v.Confidence != "medium" {
		t.Errorf("lone yara confidence = %s", v.Confidence)
	}
	if v := Fuse([]Source{{Name: "hash", Definitive: true, Hit: true}}); v.Confidence != "high" {
		t.Errorf("lone hash confidence = %s", v.Confidence)
	}
}

func TestCapKeepsOneLoudSourceOneSource(t *testing.T) {
	v := Fuse([]Source{src("heuristic", 70, 7)})
	if v.Sources[0].Ratio != Default.Cap || v.Score != Default.Cap || v.Confidence != "high" {
		t.Errorf("verdict = %+v", v)
	}
}

func TestSkippedAndSilentAreReported(t *testing.T) {
	v := Fuse([]Source{
		src("heuristic", 0, 7),
		{Name: "stego", Skipped: "not a text artifact: contains NUL bytes", Threshold: 4},
		{Name: "hash", Definitive: true},
	})
	if v.Tier != TierClean || v.Score != 0 || v.Confidence != "" || len(v.Agreed) != 0 {
		t.Errorf("verdict = %+v", v)
	}
	roles := map[string]Role{}
	for _, s := range v.Sources {
		roles[s.Name] = s.Role
	}
	want := map[string]Role{"heuristic": RoleSilent, "hash": RoleSilent, "stego": RoleSkipped}
	if !reflect.DeepEqual(roles, want) {
		t.Errorf("roles = %v", roles)
	}
	if v.Explanation != "clean: no source recorded evidence" {
		t.Errorf("explanation = %q", v.Explanation)
	}
}

func TestOrderingIsStable(t *testing.T) {
	a := Fuse([]Source{src("static", 4, 8), src("heuristic", 4, 8), src("stego", 2, 4)})
	b := Fuse([]Source{src("stego", 2, 4), src("heuristic", 4, 8), src("static", 4, 8)})
	if !reflect.DeepEqual(a, b) {
		t.Errorf("order-dependent output:\n%+v\n%+v", a, b)
	}
	// Equal ratios: alphabetical, so "heuristic" is primary.
	if a.Sources[0].Name != "heuristic" || a.Sources[1].Name != "static" || a.Sources[2].Name != "stego" {
		t.Errorf("sources = %+v", a.Sources)
	}
}

func TestMonotone(t *testing.T) {
	// Raising any score never lowers the fused score or the tier.
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 2000; i++ {
		s := []Source{src("a", rng.Intn(12), 8), src("b", rng.Intn(12), 8), src("c", rng.Intn(6), 4)}
		base := Fuse(s)
		j := rng.Intn(3)
		s[j].Score++
		up := Fuse(s)
		if up.Score < base.Score || up.Tier.Rank() < base.Tier.Rank() {
			t.Fatalf("not monotone: %+v -> %+v", base, up)
		}
	}
}

func TestParamsAreClamped(t *testing.T) {
	v := FuseWith([]Source{src("a", 4, 8), src("b", 4, 8)}, Params{Threshold: -1, Floor: -1, Weight: -1, Cap: 0})
	if v.Threshold != Default.Threshold || v.Sources[1].Role != RoleBelowFloor || v.Score != 0.5 {
		t.Errorf("verdict = %+v", v)
	}
}
