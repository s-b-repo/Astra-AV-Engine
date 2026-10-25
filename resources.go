package main

import (
	"os"
	"path/filepath"
)

// Resource discovery.
//
// The old defaults were "<dir of the binary>/signatures/hashes.txt" and
// "<dir of the binary>/rules", which is right for `go run .` and wrong the
// moment the binary is installed to /usr/bin. Resources are now looked up in
// order through:
//
//  1. an explicit flag (--db / --rules)
//  2. the environment (CAU_SIGNATURES / CAU_RULES)
//  3. next to the binary                     (<exe dir>/signatures/hashes.txt)
//  4. the FHS share dir relative to the binary (<exe dir>/../share/cau/...)
//  5. /usr/local/share/cau and /usr/share/cau
//  6. the current working directory
//
// The first existing path wins; the full search list is reported when nothing
// is found so the error is actionable.

const (
	envSignatures = "CAU_SIGNATURES"
	envRules      = "CAU_RULES"
	envFuzzy      = "CAU_FUZZY"

	relSignatures = "signatures/hashes.txt"
	relRules      = "rules"
	relFuzzy      = "signatures/fuzzy.txt"
)

// resourceRoots returns the directories that are searched for a resource, in
// priority order. Duplicates and empty entries are removed.
func resourceRoots() []string {
	var roots []string
	if exe, err := os.Executable(); err == nil {
		if real, err := filepath.EvalSymlinks(exe); err == nil {
			exe = real
		}
		dir := filepath.Dir(exe)
		roots = append(roots, dir, filepath.Join(dir, "..", "share", "cau"))
	}
	roots = append(roots, "/usr/local/share/cau", "/usr/share/cau")
	if cwd, err := os.Getwd(); err == nil {
		roots = append(roots, cwd)
	}

	seen := make(map[string]bool, len(roots))
	out := roots[:0]
	for _, r := range roots {
		r = filepath.Clean(r)
		if r == "" || seen[r] {
			continue
		}
		seen[r] = true
		out = append(out, r)
	}
	return out
}

// findResource resolves a resource. explicit is the flag value ("" when the
// flag was not given). It returns the chosen path and, when nothing was found,
// the list of locations that were tried.
func findResource(explicit, env, rel string) (path string, searched []string) {
	if explicit != "" {
		return explicit, nil
	}
	if v := os.Getenv(env); v != "" {
		return v, nil
	}
	for _, root := range resourceRoots() {
		candidate := filepath.Join(root, filepath.FromSlash(rel))
		searched = append(searched, candidate)
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}
	return "", searched
}
