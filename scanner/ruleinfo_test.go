package scanner

import (
	"reflect"
	"testing"
)

func TestRuleInfos(t *testing.T) {
	src := `
rule beta_rule : tag1 tag2 {
	meta:
		description = "second"
		threat_level = 4
		in_the_wild = true
		mitre_attack = "T1486, T1490"
	strings:
		$a = "beta"
	condition:
		$a
}
rule alpha_rule {
	meta:
		description = "first"
	condition:
		filesize < 10
}
`
	ys, _, err := LoadYaraRuleFiles([]RuleSource{{Text: src, Name: "inline"}}, WithWarnFunc(func(string, ...interface{}) {}))
	if err != nil {
		t.Fatal(err)
	}
	defer ys.Close()
	infos := ys.RuleInfos()
	if len(infos) != 2 || infos[0].Name != "alpha_rule" || infos[1].Name != "beta_rule" {
		t.Fatalf("RuleInfos = %+v", infos)
	}
	b := infos[1]
	if b.Namespace != "default" || !reflect.DeepEqual(b.Tags, []string{"tag1", "tag2"}) || b.Strings != 1 {
		t.Errorf("beta: %+v", b)
	}
	if b.Meta["threat_level"] != "4" || b.Meta["in_the_wild"] != "true" || b.Meta["description"] != "second" {
		t.Errorf("beta meta: %v", b.Meta)
	}
	if !reflect.DeepEqual(b.MetaOrder, []string{"description", "threat_level", "in_the_wild", "mitre_attack"}) {
		t.Errorf("beta meta order: %v", b.MetaOrder)
	}
	if got := b.MetaTechnique(); !reflect.DeepEqual(got, []string{"T1486", "T1490"}) {
		t.Errorf("MetaTechnique = %v", got)
	}
	if infos[0].Strings != 0 || infos[0].MetaTechnique() != nil {
		t.Errorf("alpha: %+v", infos[0])
	}
	var nilScanner *YaraScanner
	if nilScanner.RuleInfos() != nil {
		t.Error("nil scanner should enumerate nothing")
	}
}
