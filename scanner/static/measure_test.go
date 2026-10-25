package static

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const windowsTools = "/usr/share/windows-resources"

// TestMeasureRealBinaries prints the structural score of every PE under the
// Kali Windows tool set. It asserts nothing; run it with -v to retune.
func TestMeasureRealBinaries(t *testing.T) {
	if _, err := os.Stat(windowsTools); err != nil {
		t.Skip("windows-resources not installed")
	}
	var paths []string
	filepath.Walk(windowsTools, func(p string, info os.FileInfo, err error) error {
		if err == nil && info.Mode().IsRegular() {
			l := strings.ToLower(p)
			if strings.HasSuffix(l, ".exe") || strings.HasSuffix(l, ".dll") || strings.HasSuffix(l, ".sys") {
				paths = append(paths, p)
			}
		}
		return nil
	})
	sort.Strings(paths)
	for _, p := range paths {
		r := AnalyzeFile(p, Options{Now: fixtureNow()})
		if r.Error != nil || !r.IsPE {
			t.Logf("%-70s not PE / error: %v", strings.TrimPrefix(p, windowsTools+"/"), r.Error)
			continue
		}
		var cls []string
		for _, a := range r.Anomalies {
			if a.Score > 0 {
				cls = append(cls, a.Class)
			}
		}
		sig := "-"
		if r.PE.Authenticode != nil {
			sig = "signed"
			if r.PE.Authenticode.ParseErr != "" {
				sig = "sig-err:" + r.PE.Authenticode.ParseErr
			} else if r.PE.Authenticode.SignerSubject != "" {
				sig = "signed:" + r.PE.Authenticode.SignerSubject
			}
		}
		rich := "no-rich"
		if r.PE.Rich != nil {
			rich = "rich-ok"
			if !r.PE.Rich.ChecksumValid {
				rich = "rich-BAD"
			}
		}
		t.Logf("%-55s score=%2d imports=%4d imphash=%s %s %s %s", strings.TrimPrefix(p, windowsTools+"/"),
			r.Score, r.PE.ImportCount, r.PE.Imphash[:8], rich, sig, strings.Join(cls, ","))
		for _, w := range r.PE.Warnings {
			t.Logf("      warn: %s", w)
		}
	}
}

// elfMeasureRoots are where this machine keeps its ELF population. The test
// prints a score for every ELF it finds; run it with -v to retune.
var elfMeasureRoots = []string{"/usr/bin", "/usr/sbin", "/usr/lib/x86_64-linux-gnu", "/usr/libexec", "/usr/lib/systemd"}

// TestMeasureRealELF prints the structural score of every ELF under the
// measurement roots. It asserts nothing.
func TestMeasureRealELF(t *testing.T) {
	var paths []string
	for _, root := range elfMeasureRoots {
		filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
			if err == nil && info.Mode().IsRegular() && info.Size() < 48<<20 {
				paths = append(paths, p)
			}
			if err == nil && info.IsDir() && p != root && root != "/usr/lib/x86_64-linux-gnu" {
				return nil
			}
			if err == nil && info.IsDir() && p != root {
				return filepath.SkipDir
			}
			return nil
		})
	}
	if len(paths) == 0 {
		t.Skip("no ELF population to measure")
	}
	sort.Strings(paths)
	total, elf, detected := 0, 0, 0
	hist := map[string]int{}
	for _, p := range paths {
		r := AnalyzeFile(p, Options{NoFuzzy: true})
		total++
		if r.Error != nil || !r.IsELF {
			continue
		}
		elf++
		var cls []string
		for _, a := range r.Anomalies {
			if a.Score > 0 {
				cls = append(cls, a.Class)
				hist[a.Class]++
			}
		}
		if r.Detected() {
			detected++
		}
		if r.Score > 0 || len(r.ELF.Warnings) > 0 {
			t.Logf("%-60s score=%2d type=%-4s imports=%4d %s", p, r.Score, r.ELF.TypeName, r.ELF.ImportCount, strings.Join(cls, ","))
			for _, w := range r.ELF.Warnings {
				t.Logf("      warn: %s", w)
			}
		}
	}
	t.Logf("files=%d elf=%d detected=%d", total, elf, detected)
	var keys []string
	for k := range hist {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		t.Logf("  %-40s %d", k, hist[k])
	}
}
