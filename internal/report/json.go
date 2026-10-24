package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/cau-edr/cau/scanner"
)

// JSONSchemaVersion is the version of the native JSON document. See the
// package doc for the compatibility contract.
const JSONSchemaVersion = "1.0.0"

// Overall and per-file verdict strings carried by the JSON document. They are
// lower-case on purpose: they are enum values for machines, not banners.
const (
	JSONVerdictClean      = "clean"
	JSONVerdictSuspicious = "suspicious"
	JSONVerdictMalicious  = "malicious"
	JSONVerdictError      = "error"
)

// Document is the top-level JSON report.
type Document struct {
	SchemaVersion string   `json:"schema_version"`
	Tool          ToolInfo `json:"tool"`
	GeneratedAt   string   `json:"generated_at"`
	Root          string   `json:"root,omitempty"`
	Summary       Summary  `json:"summary"`
	RunError      string   `json:"run_error,omitempty"`
	Files         []File   `json:"files"`
}

// ToolInfo identifies the producer.
type ToolInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Tagline string `json:"tagline,omitempty"`
}

// Summary is the run-level roll-up.
type Summary struct {
	FilesScanned        int    `json:"files_scanned"`
	HashDetections      int    `json:"hash_detections"`
	YaraDetections      int    `json:"yara_detections"`
	HeuristicDetections int    `json:"heuristic_detections"`
	Errors              int    `json:"errors"`
	ElapsedMS           int64  `json:"elapsed_ms"`
	HeuristicThreshold  int    `json:"heuristic_threshold"`
	Verdict             string `json:"verdict"`
	FailOn              string `json:"fail_on"`
	ExitCode            int    `json:"exit_code"`
	ExitReason          string `json:"exit_reason"`
}

// File is one scanned path.
type File struct {
	Path       string      `json:"path"`
	Size       *int64      `json:"size"`
	Hashes     *Hashes     `json:"hashes,omitempty"`
	Verdict    string      `json:"verdict"`
	HashMatch  *HashMatch  `json:"hash_match,omitempty"`
	Yara       []YaraHit   `json:"yara,omitempty"`
	Heuristics *Heuristics `json:"heuristics,omitempty"`
	Warnings   []string    `json:"warnings,omitempty"`
	Error      string      `json:"error,omitempty"`
	ScanTimeMS int64       `json:"scan_time_ms"`
}

// Hashes are the digests the scanner computed.
type Hashes struct {
	MD5    string `json:"md5,omitempty"`
	SHA1   string `json:"sha1,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
}

// HashMatch describes a signature-database hit.
type HashMatch struct {
	Type   string `json:"type"`
	Hash   string `json:"hash"`
	Threat string `json:"threat"`
}

// YaraHit is one matched rule.
type YaraHit struct {
	Rule      string       `json:"rule"`
	Namespace string       `json:"namespace,omitempty"`
	Tags      []string     `json:"tags,omitempty"`
	Meta      []MetaPair   `json:"meta,omitempty"`
	Strings   []YaraString `json:"strings,omitempty"`
}

// MetaPair is one entry of a rule's meta block. A slice of pairs rather than a
// map keeps the document order deterministic and preserves duplicate keys,
// which YARA allows.
type MetaPair struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// YaraString is one matched string. DataHex is the raw bytes (bounded) as hex;
// Length is the original length so a consumer can tell how much was cut.
type YaraString struct {
	Name      string `json:"name"`
	Offset    uint64 `json:"offset"`
	DataHex   string `json:"data_hex"`
	Preview   string `json:"preview"`
	Truncated bool   `json:"truncated"`
	Length    int    `json:"length"`
	XorKey    uint8  `json:"xor_key,omitempty"`
}

// Heuristics is the per-file heuristic outcome.
type Heuristics struct {
	Score      int                 `json:"score"`
	Threshold  int                 `json:"threshold"`
	Detected   bool                `json:"detected"`
	IsPE       bool                `json:"is_pe"`
	Skipped    string              `json:"skipped,omitempty"`
	Categories []HeuristicCategory `json:"categories,omitempty"`
	Matches    []HeuristicMatch    `json:"matches,omitempty"`
	Error      string              `json:"error,omitempty"`
}

// HeuristicCategory explains how one category contributed to the score.
type HeuristicCategory struct {
	Category string `json:"category"`
	Raw      int    `json:"raw"`
	Applied  int    `json:"applied"`
	Cap      int    `json:"cap,omitempty"`
	Weak     bool   `json:"weak,omitempty"`
}

// HeuristicMatch is one indicator.
type HeuristicMatch struct {
	Indicator string   `json:"indicator"`
	Category  string   `json:"category"`
	Source    string   `json:"source"`
	Pattern   string   `json:"pattern,omitempty"`
	Score     int      `json:"score,omitempty"`
	Hits      int      `json:"hits,omitempty"`
	Examples  []string `json:"examples,omitempty"`
}

// JSONReporter writes the native JSON document.
type JSONReporter struct {
	cfg config
}

// NewJSONReporter builds a reporter from the shared options.
func NewJSONReporter(opts ...Option) *JSONReporter {
	return &JSONReporter{cfg: buildConfig(opts)}
}

// Build assembles the document without encoding it, for callers that want to
// post-process or embed it.
func (r *JSONReporter) Build(in Input) Document {
	return r.cfg.buildDocument(in)
}

// Write encodes the document to w. It fails only if encoding or writing fails.
func (r *JSONReporter) Write(w io.Writer, in Input) error {
	doc := r.Build(in)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	if r.cfg.indent {
		enc.SetIndent("", "  ")
	}
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("report: encode json: %w", err)
	}
	return nil
}

// buildDocument is shared with the text reporter's summary logic.
func (c config) buildDocument(in Input) Document {
	policy := &ExitPolicy{cfg: c}
	code, reason := policy.decide(in)

	doc := Document{
		SchemaVersion: JSONSchemaVersion,
		Tool: ToolInfo{
			Name:    c.toolName,
			Version: c.toolVersion,
			Tagline: c.toolTagline,
		},
		GeneratedAt: c.timestamp(),
		Root:        c.root,
		Summary: Summary{
			FilesScanned:        len(in.AllPaths()),
			HashDetections:      in.HashDetectionCount(),
			YaraDetections:      in.YaraDetectionCount(),
			HeuristicDetections: len(in.HeuristicBreach(c.heuristicThreshold)),
			Errors:              in.ErrorCount(),
			ElapsedMS:           in.Elapsed.Milliseconds(),
			HeuristicThreshold:  c.heuristicThreshold,
			Verdict:             c.overallVerdict(in),
			FailOn:              c.failOn.String(),
			ExitCode:            code,
			ExitReason:          reason,
		},
		RunError: c.errorString(in.RunError),
		Files:    []File{},
	}

	byPath := in.HeuristicsByPath()
	results := make(map[string]scanner.ScanResult, len(in.Results))
	for _, res := range in.Results {
		// Last one wins, mirroring HeuristicsByPath.
		results[res.FilePath] = res
	}

	for _, p := range in.AllPaths() {
		res, hasResult := results[p]
		h, hasHeur := byPath[p]
		var hp *scanner.HeuristicResult
		if hasHeur {
			hp = &h
		}
		var rp *scanner.ScanResult
		if hasResult {
			rp = &res
		}
		doc.Files = append(doc.Files, c.buildFile(p, rp, hp))
	}
	return doc
}

// overallVerdict folds the run into one word. "error" is reserved for a run
// that could not execute; per-file errors are counted in Summary.Errors and
// drive the exit code, but a run that did scan files still gets a verdict for
// the files it did see.
func (c config) overallVerdict(in Input) string {
	switch {
	case in.RunError != nil:
		return JSONVerdictError
	case len(in.Malicious()) > 0:
		return JSONVerdictMalicious
	case len(in.HeuristicBreach(c.heuristicThreshold)) > 0:
		return JSONVerdictSuspicious
	default:
		return JSONVerdictClean
	}
}

func (c config) buildFile(p string, res *scanner.ScanResult, h *scanner.HeuristicResult) File {
	f := File{
		Path:    c.boundedMessage(p),
		Verdict: JSONVerdictClean,
	}

	// The scanner records the size it saw; fall back to stat only when it did
	// not, so the report describes the bytes that were actually scanned.
	if res != nil && res.Size > 0 {
		s := res.Size
		f.Size = &s
	} else if size, err := c.stat(p); err == nil {
		s := size
		f.Size = &s
	}

	if res != nil {
		f.ScanTimeMS = res.ScanTime.Milliseconds()
		for _, w := range res.Warnings {
			f.Warnings = append(f.Warnings, c.boundedMessage(w))
		}
		if res.MD5 != "" || res.SHA1 != "" || res.SHA256 != "" {
			f.Hashes = &Hashes{
				MD5:    c.boundedHash(res.MD5),
				SHA1:   c.boundedHash(res.SHA1),
				SHA256: c.boundedHash(res.SHA256),
			}
		}
		if res.Error != nil {
			f.Error = c.errorString(res.Error)
			f.Verdict = JSONVerdictError
		}
		if res.Detected {
			f.HashMatch = &HashMatch{
				Type:   c.boundedMessage(res.MatchType),
				Hash:   c.boundedHash(res.MatchHash),
				Threat: c.boundedMessage(res.ThreatName),
			}
		}
		for _, m := range res.YaraMatches {
			f.Yara = append(f.Yara, c.buildYara(m))
		}
		if isMalicious(*res) {
			f.Verdict = JSONVerdictMalicious
		}
	}

	if h != nil {
		hh := &Heuristics{
			Score:     h.Score,
			Threshold: thresholdFor(*h, c.heuristicThreshold),
			Detected:  heuristicBreached(*h, c.heuristicThreshold),
			IsPE:      h.IsPE,
			Skipped:   c.boundedMessage(h.Skipped),
		}
		for _, cs := range h.Categories {
			hh.Categories = append(hh.Categories, HeuristicCategory{
				Category: c.boundedMessage(cs.Category),
				Raw:      cs.Raw,
				Applied:  cs.Applied,
				Cap:      cs.Cap,
				Weak:     cs.Weak,
			})
		}
		for _, m := range h.Matches {
			hm := HeuristicMatch{
				Indicator: c.boundedMessage(m.Indicator),
				Category:  c.boundedMessage(m.Category),
				Source:    c.boundedMessage(m.Source),
				Score:     m.Score,
				Hits:      m.Hits,
			}
			if m.Pattern != "" && m.Pattern != m.Indicator {
				hm.Pattern = c.boundedMessage(m.Pattern)
			}
			for _, ex := range m.Examples {
				hm.Examples = append(hm.Examples, c.boundedMessage(ex))
			}
			hh.Matches = append(hh.Matches, hm)
		}
		if h.Error != nil {
			hh.Error = c.errorString(h.Error)
			if f.Verdict == JSONVerdictClean {
				f.Verdict = JSONVerdictError
			}
		}
		f.Heuristics = hh
		if hh.Detected && f.Verdict == JSONVerdictClean {
			f.Verdict = JSONVerdictSuspicious
		}
	}
	return f
}

func (c config) buildYara(m scanner.YaraMatch) YaraHit {
	hit := YaraHit{
		Rule:      c.boundedMessage(m.RuleName),
		Namespace: c.boundedMessage(m.Namespace),
	}
	for _, t := range m.Tags {
		hit.Tags = append(hit.Tags, c.boundedMessage(t))
	}
	sort.Strings(hit.Tags)
	for _, meta := range m.Metas {
		hit.Meta = append(hit.Meta, MetaPair{
			Key:   c.boundedMessage(meta.Identifier),
			Value: c.boundedMessage(meta.String()),
		})
	}
	for _, s := range m.Strings {
		hit.Strings = append(hit.Strings, c.buildYaraString(s))
	}
	return hit
}

func (c config) buildYaraString(s scanner.YaraMatchString) YaraString {
	data, cut := truncateBytes(s.Data, c.maxMatchStringBytes)
	return YaraString{
		Name:      c.boundedMessage(s.Name),
		Offset:    s.Offset,
		DataHex:   hexString(data),
		Preview:   preview(s.Data, c.maxPreviewBytes),
		Truncated: cut,
		Length:    len(s.Data),
		XorKey:    s.XorKey,
	}
}

// elapsedString renders a duration the way the text reporter prints it.
func elapsedString(d time.Duration) string {
	return d.Round(time.Millisecond).String()
}
