package encchain

import (
	"os"
	"path/filepath"
	"testing"
)

// TestMeasureRealEncChain measures the false-positive rate on a real benign
// population: every file under the configured roots is scanned and any
// detection is a false positive (these trees ship no malware). It prints the
// offenders so the floor/validation can be tuned. Skipped when the trees are
// absent, like the other measurement tests.
func TestMeasureRealEncChain(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real-population measurement in -short mode")
	}
	roots := []string{
		"/usr/share/doc",
		"/usr/lib/python3/dist-packages",
		"/usr/share/nmap",
		"/usr/share/metasploit-framework",
	}
	const maxFile = 16 << 20

	scanned, detections := 0, 0
	var offenders []string
	for _, root := range roots {
		if _, err := os.Stat(root); err != nil {
			continue
		}
		filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !info.Mode().IsRegular() || info.Size() == 0 || info.Size() > maxFile {
				return nil
			}
			data, rerr := os.ReadFile(p)
			if rerr != nil {
				return nil
			}
			scanned++
			r := Analyze(data, Options{})
			if r.Detected() {
				detections++
				if len(offenders) < 50 {
					offenders = append(offenders, p)
				}
			}
			return nil
		})
	}
	if scanned == 0 {
		t.Skip("no benign population to measure")
	}
	rate := float64(detections) / float64(scanned) * 100
	t.Logf("encchain FP: %d / %d files (%.3f%%)", detections, scanned, rate)
	for _, o := range offenders {
		t.Logf("  detected: %s", o)
	}
}
