package report

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/cau-edr/cau/scanner"
)

// Reporter is the common shape of every output format.
type Reporter interface {
	Write(w io.Writer, in Input) error
}

// Formats lists the names NewReporter accepts.
var Formats = []string{"text", "json", "sarif"}

// NewReporter selects a reporter by format name ("text", "json", "sarif").
func NewReporter(format string, opts ...Option) (Reporter, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "text":
		return NewTextReporter(opts...), nil
	case "json":
		return NewJSONReporter(opts...), nil
	case "sarif":
		return NewSARIFReporter(opts...), nil
	default:
		return nil, fmt.Errorf("unknown output format %q (want one of %s)", format, strings.Join(Formats, ", "))
	}
}

// TextReporter renders the human-readable output: one block per file followed
// by a summary. It does not print the startup banner; main owns that.
type TextReporter struct {
	cfg config
}

// NewTextReporter builds a reporter from the shared options.
func NewTextReporter(opts ...Option) *TextReporter {
	return &TextReporter{cfg: buildConfig(opts)}
}

// Write renders the run to w.
func (r *TextReporter) Write(w io.Writer, in Input) error {
	bw := bufio.NewWriter(w)
	c := r.cfg

	if in.RunError != nil {
		fmt.Fprintf(bw, " [ERR] %s\n\n", c.errorString(in.RunError))
	}

	byPath := in.HeuristicsByPath()
	results := make(map[string]scanner.ScanResult, len(in.Results))
	for _, res := range in.Results {
		results[res.FilePath] = res
	}

	for _, p := range in.AllPaths() {
		res, hasResult := results[p]
		h, hasHeur := byPath[p]
		if hasResult {
			c.writeResult(bw, res)
		}
		if hasHeur {
			c.writeHeuristic(bw, h, !hasResult)
		}
	}

	c.writeSummary(bw, in)
	if err := bw.Flush(); err != nil {
		return fmt.Errorf("report: write text: %w", err)
	}
	return nil
}

func (c config) writeResult(w io.Writer, r scanner.ScanResult) {
	path := c.boundedMessage(r.FilePath)
	if r.Error != nil {
		fmt.Fprintf(w, " [ERR] %s\n      %s\n\n", path, c.errorString(r.Error))
		return
	}

	// ── Hash match ──
	if r.Detected {
		fmt.Fprintln(w, " [!] DETECTED (Hash) —", path)
		fmt.Fprintf(w, "     %-10s: %s\n", c.boundedMessage(r.MatchType), c.boundedHash(r.MatchHash))
		fmt.Fprintf(w, "     %-10s: %s\n", "Match", c.boundedMessage(r.ThreatName))
		fmt.Fprintf(w, "     %-10s: %s\n", "Verdict", r.Verdict)
		fmt.Fprintf(w, "     %-10s: %s\n\n", "Scan time", elapsedString(r.ScanTime))
	}

	// ── YARA matches ──
	if len(r.YaraMatches) > 0 {
		if !r.Detected {
			fmt.Fprintln(w, " [!] DETECTED (YARA) —", path)
			fmt.Fprintf(w, "     %-10s: %s\n", "Verdict", r.Verdict)
		} else {
			fmt.Fprintf(w, "     Also matched %d YARA rule(s):\n", len(r.YaraMatches))
		}

		for _, m := range r.YaraMatches {
			tags := ""
			if len(m.Tags) > 0 {
				tags = fmt.Sprintf(" [%s]", strings.Join(boundedList(c, m.Tags), ", "))
			}
			fmt.Fprintf(w, "     [YARA] %s::%s%s\n", c.boundedMessage(m.Namespace), c.boundedMessage(m.RuleName), tags)
			if meta := c.metaLine(m); meta != "" {
				fmt.Fprintf(w, "            %s\n", meta)
			}
			for _, s := range m.Strings {
				data, cut := truncateBytes(s.Data, 32)
				suffix := ""
				if cut {
					suffix = "..."
				}
				fmt.Fprintf(w, "            %s @ 0x%x : %q%s\n", c.boundedMessage(s.Name), s.Offset, data, suffix)
			}
		}
		fmt.Fprintf(w, "     %-10s: %s\n\n", "Scan time", elapsedString(r.ScanTime))
	}

	// ── Clean ──
	if !r.Detected && len(r.YaraMatches) == 0 {
		fmt.Fprintf(w, " [CLEAN] %s\n", path)
	}

	for _, warn := range r.Warnings {
		fmt.Fprintf(w, "     [WARN] %s\n", c.boundedMessage(warn))
	}
}

// metaLine renders the meta fields an analyst wants at a glance.
func (c config) metaLine(m scanner.YaraMatch) string {
	var parts []string
	if a := m.MetaString("author"); a != "" {
		parts = append(parts, "author="+c.boundedMessage(a))
	}
	if tl, ok := m.MetaInt("threat_level"); ok {
		parts = append(parts, fmt.Sprintf("threat_level=%d", tl))
	}
	if meta, ok := m.Meta("in_the_wild"); ok {
		parts = append(parts, "in_the_wild="+c.boundedMessage(meta.String()))
	}
	if d := m.MetaString("description"); d != "" {
		parts = append(parts, "desc="+strconvQuote(c.boundedMessage(d)))
	}
	return strings.Join(parts, " ")
}

func strconvQuote(s string) string { return fmt.Sprintf("%q", s) }

func (c config) writeHeuristic(w io.Writer, h scanner.HeuristicResult, standalone bool) {
	path := c.boundedMessage(h.FilePath)
	if h.Error != nil {
		fmt.Fprintf(w, " [ERR] Heuristics on %s: %s\n\n", path, c.errorString(h.Error))
		return
	}

	if h.Skipped != "" {
		fmt.Fprintf(w, " [~] SKIPPED heuristics on %s: %s\n", path, c.boundedMessage(h.Skipped))
		return
	}

	threshold := thresholdFor(h, c.heuristicThreshold)
	switch {
	case h.Score >= threshold:
		fmt.Fprintf(w, " [!] DETECTED (Heuristics) — %s\n", path)
		fmt.Fprintf(w, "     %-10s: %s\n", "Verdict", "SUSPICIOUS")
		fmt.Fprintf(w, "     %-10s: %d / %d threshold\n\n", "Score", h.Score, threshold)

		byCategory := make(map[string][]scanner.HeuristicMatch)
		var order []string
		for _, m := range h.Matches {
			if _, ok := byCategory[m.Category]; !ok {
				order = append(order, m.Category)
			}
			byCategory[m.Category] = append(byCategory[m.Category], m)
		}
		for _, cat := range order {
			fmt.Fprintf(w, "     [%s]\n", c.boundedMessage(cat))
			for _, hit := range byCategory[cat] {
				extra := ""
				if hit.Hits > 1 {
					extra = fmt.Sprintf("  (x%d)", hit.Hits)
				}
				fmt.Fprintf(w, "       %-14s %s%s\n", "["+c.boundedMessage(hit.Source)+"]", c.boundedMessage(hit.Indicator), extra)
			}
		}
		fmt.Fprintln(w)

	case len(h.Matches) > 0:
		fmt.Fprintf(w, " [~] LOW SUSPICION — %s (score: %d)\n", path, h.Score)

	case standalone:
		// No ScanResult printed a verdict for this path, so say something.
		fmt.Fprintf(w, " [CLEAN] %s\n", path)
	}
}

func (c config) writeSummary(w io.Writer, in Input) {
	policy := &ExitPolicy{cfg: c}
	code, reason := policy.decide(in)

	hash := in.HashDetectionCount()
	yara := in.YaraDetectionCount()
	heur := len(in.HeuristicBreach(c.heuristicThreshold))

	fmt.Fprintln(w)
	fmt.Fprintln(w, strings.Repeat("-", 60))
	fmt.Fprintf(w, " Scan complete         : %s\n", elapsedString(in.Elapsed))
	fmt.Fprintf(w, " Files scanned         : %d\n", len(in.AllPaths()))
	fmt.Fprintf(w, " Hash detections       : %d\n", hash)
	fmt.Fprintf(w, " YARA detections       : %d\n", yara)
	fmt.Fprintf(w, " Heuristic detections  : %d\n", heur)
	fmt.Fprintf(w, " Errors                : %d\n", in.ErrorCount())
	fmt.Fprintf(w, " Exit code             : %d (%s)\n", code, reason)
	fmt.Fprintln(w, strings.Repeat("-", 60))

	if hash+yara+heur > 0 {
		fmt.Fprintln(w, "\n *** THREATS DETECTED — DO NOT EXECUTE FLAGGED FILES ***")
	} else if in.RunError != nil {
		fmt.Fprintln(w, "\n Scan did not run.")
	} else {
		fmt.Fprintln(w, "\n No threats detected.")
	}
}
