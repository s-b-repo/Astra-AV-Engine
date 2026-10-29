package scanner

import "testing"

// FuzzScanHeuristicsData checks that the heuristic pass (PE/ELF import scan
// plus ASCII/UTF-16 string extraction) never panics on malformed input.
func FuzzScanHeuristicsData(f *testing.F) {
	seeds := [][]byte{
		{},
		[]byte("cmd.exe /c whoami http://x.example"),
		append([]byte("MZ"), make([]byte, 256)...),
		{0x7f, 'E', 'L', 'F', 2, 1, 1},
		{0x7f, 'E', 'L', 'F', 1, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0},
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = ScanHeuristicsData("fuzz", data, HeuristicOptions{})
	})
}
