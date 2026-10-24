// Command cau is the CAU EDR command line: a transparent, open-source malware
// detection engine (hash signatures, YARA, string/API heuristics) with
// machine-readable output, CI exit codes and a measured evaluation harness.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cau-edr/cau/internal/report"
	"github.com/cau-edr/cau/scanner"
)

// version is overridden at build time: -ldflags "-X main.version=v1.2.3".
var version = "0.4.0-dev"

const (
	toolName    = "CAU EDR"
	toolTagline = "Certs Are Useless — detection that trusts no certificate"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func usage(w io.Writer) {
	fmt.Fprintf(w, `%s %s
%s

Usage:
  cau scan     [flags] [path ...]      scan files and directories
  cau add-hash [flags]                 append a hash signature to the database
  cau eval     <subcommand> [flags]    corpus evaluation harness (see "cau eval help")
  cau version                          print the version

Scan examples:
  cau scan --file suspicious.exe
  cau scan --dir ./samples --format sarif --output cau.sarif
  cau scan ./build --format json --fail-on heuristic
  cau scan --dir / --jobs 16 --no-heuristics --quiet

Exit codes (scan): 0 clean, 1 findings at or above --fail-on, 2 some files
could not be scanned, 3 the run itself failed, 4 usage error.

Resources: the signature database and the YARA rules are found automatically
(next to the binary, <prefix>/share/cau, /usr/share/cau, or the working
directory); override with --db / --rules or %s / %s.
`, toolName, version, toolTagline, envSignatures, envRules)
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 {
		usage(stderr)
		return report.ExitUsage
	}
	switch args[0] {
	case "scan":
		return cmdScan(args[1:], stdout, stderr)
	case "add-hash":
		return cmdAddHash(args[1:], stdout, stderr)
	case "eval":
		return cmdEval(args[1:], stdout, stderr)
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "%s %s\n", toolName, version)
		return report.ExitOK
	case "help", "-h", "--help":
		usage(stdout)
		return report.ExitOK
	default:
		fmt.Fprintf(stderr, "[ERROR] unknown command %q\n\n", args[0])
		usage(stderr)
		return report.ExitUsage
	}
}

// ── scan ─────────────────────────────────────────────────────────────────────

type scanFlags struct {
	file, dir         string
	db, rules         string
	noYara, noHeur    bool
	heurThreshold     int
	format, output    string
	pretty            bool
	failOn            string
	noFailOnScanError bool
	jobs              int
	followSymlinks    bool
	maxInMemoryMiB    int64
	yaraTimeout       time.Duration
	quiet             bool
}

func cmdScan(args []string, stdout, stderr io.Writer) int {
	var f scanFlags
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&f.file, "file", "", "a single file to scan (positional paths are accepted too)")
	fs.StringVar(&f.dir, "dir", "", "a directory to scan recursively")
	fs.StringVar(&f.db, "db", "", "signature database (default: auto-discovered, see 'cau help')")
	fs.StringVar(&f.rules, "rules", "", "YARA rule file or directory (default: auto-discovered)")
	fs.BoolVar(&f.noYara, "no-yara", false, "disable YARA scanning")
	fs.BoolVar(&f.noHeur, "no-heuristics", false, "disable string & API heuristics")
	fs.IntVar(&f.heurThreshold, "heuristic-threshold", scanner.HeuristicThreshold, "heuristic score at which a file is reported suspicious")
	fs.StringVar(&f.format, "format", "text", "output format: "+strings.Join(report.Formats, ", "))
	fs.StringVar(&f.output, "output", "", "write the report to this file instead of stdout")
	fs.BoolVar(&f.pretty, "pretty", false, "indent JSON/SARIF output")
	fs.StringVar(&f.failOn, "fail-on", string(report.FailOnMalicious), "exit 1 at this finding level: none, malicious, heuristic, clean")
	fs.BoolVar(&f.noFailOnScanError, "no-fail-on-scan-error", false, "do not exit 2 when some files could not be scanned")
	fs.IntVar(&f.jobs, "jobs", 0, "files scanned concurrently (default: number of CPUs)")
	fs.BoolVar(&f.followSymlinks, "follow-symlinks", false, "scan the targets of symlinks to files (directory symlinks are never followed)")
	fs.Int64Var(&f.maxInMemoryMiB, "max-in-memory", scanner.DefaultMaxInMemory>>20, "largest file (MiB) read into memory; bigger files are streamed and skip heuristics")
	fs.DurationVar(&f.yaraTimeout, "yara-timeout", scanner.DefaultScanTimeout, "per-file YARA scan budget")
	fs.BoolVar(&f.quiet, "quiet", false, "suppress the banner and progress lines on stderr")
	if err := fs.Parse(args); err != nil {
		return report.ExitUsage
	}

	var targets []string
	if f.file != "" {
		targets = append(targets, f.file)
	}
	if f.dir != "" {
		targets = append(targets, f.dir)
	}
	targets = append(targets, fs.Args()...)
	if len(targets) == 0 {
		fmt.Fprintln(stderr, "[ERROR] nothing to scan: give --file, --dir or a path")
		fs.Usage()
		return report.ExitUsage
	}

	level, err := report.ParseFailOn(f.failOn)
	if err != nil {
		fmt.Fprintf(stderr, "[ERROR] %v\n", err)
		return report.ExitUsage
	}
	if f.heurThreshold < 1 {
		fmt.Fprintln(stderr, "[ERROR] --heuristic-threshold must be at least 1")
		return report.ExitUsage
	}

	opts := []report.Option{
		report.WithToolName(toolName),
		report.WithToolVersion(version),
		report.WithFailOn(level),
		report.WithFailOnScanError(!f.noFailOnScanError),
		report.WithHeuristicThreshold(f.heurThreshold),
		report.WithIndent(f.pretty),
	}
	if f.dir != "" && len(targets) == 1 {
		opts = append(opts, report.WithRoot(f.dir))
	}
	reporter, err := report.NewReporter(f.format, opts...)
	if err != nil {
		fmt.Fprintf(stderr, "[ERROR] %v\n", err)
		return report.ExitUsage
	}
	policy := report.NewExitPolicy(opts...)

	status := func(format string, a ...interface{}) {
		if !f.quiet {
			fmt.Fprintf(stderr, format+"\n", a...)
		}
	}
	if !f.quiet {
		printBanner(stderr)
	}

	// finish writes the report (even when the run failed, so JSON/SARIF
	// consumers always get a document) and returns the exit code.
	finish := func(in report.Input) int {
		out := io.Writer(stdout)
		if f.output != "" {
			fh, err := os.Create(f.output)
			if err != nil {
				fmt.Fprintf(stderr, "[ERROR] cannot write %s: %v\n", f.output, err)
				return report.ExitRunFailed
			}
			defer fh.Close()
			out = fh
		}
		if err := reporter.Write(out, in); err != nil {
			fmt.Fprintf(stderr, "[ERROR] writing report: %v\n", err)
			return report.ExitRunFailed
		}
		if in.RunError != nil {
			fmt.Fprintf(stderr, "[ERROR] %v\n", in.RunError)
		}
		status("[*] %s", policy.Explain(in))
		return policy.Code(in)
	}

	// ── resources ──
	dbPath, searched := findResource(f.db, envSignatures, relSignatures)
	if dbPath == "" {
		return finish(report.Input{RunError: fmt.Errorf("signature database not found; pass --db or set %s (searched: %s)",
			envSignatures, strings.Join(searched, ", "))})
	}
	db, err := scanner.LoadSignatures(dbPath)
	if err != nil {
		return finish(report.Input{RunError: err})
	}
	for _, w := range db.Warnings() {
		status("[WARN] %s", w)
	}
	status("[*] Loaded %d hash signatures from %s", db.Count(), dbPath)

	var ys *scanner.YaraScanner
	if !f.noYara {
		rulesPath, searched := findResource(f.rules, envRules, relRules)
		switch {
		case rulesPath == "" && f.rules == "":
			status("[*] YARA rules not found, YARA disabled (pass --rules or set %s; searched: %s)",
				envRules, strings.Join(searched, ", "))
		case rulesPath == "":
			return finish(report.Input{RunError: fmt.Errorf("YARA rules not found at %s", f.rules)})
		default:
			yopts := []scanner.YaraOption{scanner.WithTimeout(f.yaraTimeout)}
			if f.quiet {
				yopts = append(yopts, scanner.WithWarnFunc(func(string, ...interface{}) {}))
			} else {
				yopts = append(yopts, scanner.WithWarnFunc(func(format string, a ...interface{}) {
					fmt.Fprintf(stderr, "[WARN] "+format+"\n", a...)
				}))
			}
			var files int
			ys, files, err = scanner.LoadYaraRules(rulesPath, yopts...)
			if err != nil {
				return finish(report.Input{RunError: fmt.Errorf("YARA: %w", err)})
			}
			defer ys.Close()
			status("[*] Compiled %d YARA rules from %d file(s) at %s (%d warning(s))",
				ys.RuleCount(), files, rulesPath, len(ys.Warnings()))
		}
	} else {
		status("[*] YARA disabled")
	}
	if f.noHeur {
		status("[*] Heuristics disabled")
	} else {
		status("[*] Heuristics enabled (threshold %d)", f.heurThreshold)
	}

	engine := &scanner.Engine{
		DB:                 db,
		Yara:               ys,
		Heuristics:         !f.noHeur,
		HeuristicThreshold: f.heurThreshold,
		MaxInMemory:        f.maxInMemoryMiB << 20,
		Jobs:               f.jobs,
		FollowSymlinks:     f.followSymlinks,
	}

	// ── scan ──
	start := time.Now()
	in := report.Input{}
	for _, target := range targets {
		info, err := os.Stat(target)
		if err != nil {
			in.Results = append(in.Results, scanner.ScanResult{FilePath: target, Verdict: scanner.VerdictError, Error: err})
			continue
		}
		if info.IsDir() {
			status("[*] Scanning directory %s", target)
			rs, hs := engine.ScanDirectory(target, nil)
			in.Results = append(in.Results, rs...)
			in.Heuristics = append(in.Heuristics, hs...)
			continue
		}
		status("[*] Scanning %s", target)
		r, h := engine.ScanFile(target)
		in.Results = append(in.Results, r)
		if h != nil {
			in.Heuristics = append(in.Heuristics, *h)
		}
	}
	in.Elapsed = time.Since(start)
	return finish(in)
}

func printBanner(w io.Writer) {
	fmt.Fprintln(w, strings.Repeat("=", 60))
	fmt.Fprintf(w, " %s %s\n", toolName, version)
	fmt.Fprintf(w, " %s\n", toolTagline)
	fmt.Fprintln(w, " Detection: Hash Signatures + YARA Rules + Heuristics")
	fmt.Fprintln(w, strings.Repeat("=", 60))
	fmt.Fprintln(w)
}

// ── add-hash ─────────────────────────────────────────────────────────────────

func cmdAddHash(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("add-hash", flag.ContinueOnError)
	fs.SetOutput(stderr)
	hash := fs.String("hash", "", "hash value to add")
	typ := fs.String("type", "", "hash type: MD5, SHA1 or SHA256 (default: inferred from the length)")
	name := fs.String("name", "", "threat name (e.g. \"WannaCry Ransomware\")")
	db := fs.String("db", "", "signature database (default: auto-discovered)")
	if err := fs.Parse(args); err != nil {
		return report.ExitUsage
	}
	if *hash == "" || *name == "" {
		fmt.Fprintln(stderr, "[ERROR] --hash and --name are required")
		fs.Usage()
		return report.ExitUsage
	}
	hashType := *typ
	if hashType == "" {
		t, ok := scanner.HashTypeFor(*hash)
		if !ok {
			fmt.Fprintf(stderr, "[ERROR] cannot infer the hash type of %q from its length; pass --type\n", *hash)
			return report.ExitUsage
		}
		hashType = t
	}
	dbPath, searched := findResource(*db, envSignatures, relSignatures)
	if dbPath == "" {
		fmt.Fprintf(stderr, "[ERROR] signature database not found; pass --db (searched: %s)\n", strings.Join(searched, ", "))
		return report.ExitUsage
	}
	if err := scanner.AddSignature(dbPath, hashType, *hash, *name); err != nil {
		fmt.Fprintf(stderr, "[ERROR] %v\n", err)
		return report.ExitRunFailed
	}
	t, h, _ := scanner.ValidateHash(hashType, *hash)
	fmt.Fprintf(stdout, "[+] Added to %s: %s|%s|%s\n", filepath.Clean(dbPath), t, h, strings.TrimSpace(*name))
	return report.ExitOK
}
