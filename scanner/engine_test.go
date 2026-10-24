package scanner

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestEngineSinglePassMatchesSeparateDetectors(t *testing.T) {
	ys := loadRepoYara(t)
	path := writeTempFile(t, "wannacry.bin", []byte(wannacrySample))
	d, _ := hashFile(path)
	db := NewSignatureDB()
	_ = db.Add(Signature{HashType: "SHA1", Hash: d.sha1, ThreatName: "Synthetic WannaCry"})

	e := &Engine{DB: db, Yara: ys, Heuristics: true}
	res, h := e.ScanFile(path)
	if res.Error != nil {
		t.Fatal(res.Error)
	}
	if !res.Detected || res.MatchType != "SHA1" || res.ThreatName != "Synthetic WannaCry" {
		t.Errorf("hash: %+v", res)
	}
	findMatch(t, res.YaraMatches, "wannacry_ransomware")
	if h == nil {
		t.Fatal("heuristics enabled but no result")
	}
	if h.FilePath != path || h.Error != nil || h.Skipped != "" {
		t.Errorf("heuristic result: %+v", h)
	}

	// Same answers as the independent entry points.
	sep := ScanFile(path, db, ys)
	if sep.SHA256 != res.SHA256 || len(sep.YaraMatches) != len(res.YaraMatches) || sep.Detected != res.Detected {
		t.Errorf("Engine and ScanFile disagree: %+v vs %+v", sep, res)
	}
	hs := ScanHeuristics(path)
	if hs.Score != h.Score || len(hs.Matches) != len(h.Matches) {
		t.Errorf("Engine and ScanHeuristics disagree: %d/%d vs %d/%d", hs.Score, len(hs.Matches), h.Score, len(h.Matches))
	}
}

func TestEngineLargeFileIsStreamed(t *testing.T) {
	const needle = "CAU_ENGINE_STREAM_PROBE"
	ys, _, err := LoadYaraRuleFiles([]RuleSource{{
		Text: "rule stream_probe { strings: $n = \"" + needle + "\" condition: $n }",
	}}, WithWarnFunc(func(string, ...interface{}) {}))
	if err != nil {
		t.Fatal(err)
	}
	defer ys.Close()

	buf := bytes.Repeat([]byte{0x20}, 256*1024)
	copy(buf[100000:], needle)
	path := writeTempFile(t, "big.bin", buf)
	want := hashBytes(buf)

	e := &Engine{DB: NewSignatureDB(), Yara: ys, Heuristics: true, MaxInMemory: 4096}
	res, h := e.ScanFile(path)
	if res.Error != nil {
		t.Fatal(res.Error)
	}
	if res.SHA256 != want.sha256 || res.MD5 != want.md5 {
		t.Errorf("streamed hashes differ from in-memory hashes")
	}
	m := findMatch(t, res.YaraMatches, "stream_probe")
	if s := findString(t, m, "$n"); s.Offset != 100000 {
		t.Errorf("mmap offset = %d, want 100000", s.Offset)
	}
	if h == nil || h.Skipped == "" || h.Detected() || h.Error != nil {
		t.Errorf("heuristics on an oversized file must be skipped with a reason, got %+v", h)
	}
	if !strings.Contains(h.Skipped, "in-memory limit") {
		t.Errorf("skip reason = %q", h.Skipped)
	}
}

func TestEngineScanDirectoryIsDeterministicAndConcurrent(t *testing.T) {
	root := t.TempDir()
	var want []string
	for _, rel := range []string{"a/1.bin", "a/2.bin", "b/x.bin", "c/d/e.bin", "z.bin"} {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("content "+rel), 0o644); err != nil {
			t.Fatal(err)
		}
		want = append(want, p)
	}
	// Things that must be skipped, not errored: a symlink to a directory
	// (loop risk) and a dangling symlink.
	if runtime.GOOS != "windows" {
		if err := os.Symlink(filepath.Join(root, "a"), filepath.Join(root, "link_to_dir")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(root, "nope"), filepath.Join(root, "dangling")); err != nil {
			t.Fatal(err)
		}
	}

	e := &Engine{DB: NewSignatureDB(), Heuristics: true, Jobs: 8}
	var progressCalls int
	results, hs := e.ScanDirectory(root, func(done, total int, path string) { progressCalls++ })

	got := make([]string, 0, len(results))
	for _, r := range results {
		if r.Error != nil {
			t.Errorf("%s: %v", r.FilePath, r.Error)
		}
		got = append(got, r.FilePath)
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("order/content mismatch:\n got %v\nwant %v", got, want)
	}
	if len(hs) != len(want) {
		t.Errorf("%d heuristic results, want %d", len(hs), len(want))
	}
	for i := range hs {
		if hs[i].FilePath != want[i] {
			t.Errorf("heuristic[%d] = %s, want %s (alignment broken)", i, hs[i].FilePath, want[i])
		}
	}
	if progressCalls != len(want) {
		t.Errorf("progress called %d times, want %d", progressCalls, len(want))
	}

	// Repeat with Jobs=1 and compare: concurrency must not change output.
	single, _ := (&Engine{DB: NewSignatureDB(), Heuristics: true, Jobs: 1}).ScanDirectory(root, nil)
	for i := range single {
		if single[i].FilePath != results[i].FilePath || single[i].SHA256 != results[i].SHA256 {
			t.Errorf("Jobs=1 and Jobs=8 disagree at %d", i)
		}
	}
}

func TestEngineScanDirectoryFollowsFileSymlinksOnlyWhenAsked(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks")
	}
	root := t.TempDir()
	target := writeTempFile(t, "target.bin", []byte("linked"))
	if err := os.Symlink(target, filepath.Join(root, "link.bin")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "plain.bin"), []byte("plain"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, _ := (&Engine{}).ScanDirectory(root, nil)
	if len(res) != 1 || filepath.Base(res[0].FilePath) != "plain.bin" {
		t.Errorf("symlink followed by default: %v", paths(res))
	}
	res, _ = (&Engine{FollowSymlinks: true}).ScanDirectory(root, nil)
	if len(res) != 2 {
		t.Errorf("FollowSymlinks: got %v", paths(res))
	}
	for _, r := range res {
		if r.Error != nil {
			t.Errorf("%s: %v", r.FilePath, r.Error)
		}
	}
}

func TestEngineScanDirectoryReportsUnreadableEntries(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read anything")
	}
	root := t.TempDir()
	locked := filepath.Join(root, "locked")
	if err := os.MkdirAll(locked, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(locked, "secret.bin"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
	if err := os.WriteFile(filepath.Join(root, "ok.bin"), []byte("y"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, _ := (&Engine{}).ScanDirectory(root, nil)
	var errs, oks int
	for _, r := range res {
		if r.Error != nil {
			errs++
		} else {
			oks++
		}
	}
	if errs != 1 || oks != 1 {
		t.Errorf("want 1 error + 1 ok, got %d errors, %d ok: %v", errs, oks, paths(res))
	}
}

func paths(rs []ScanResult) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = r.FilePath
	}
	return out
}
