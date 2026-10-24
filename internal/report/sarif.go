package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/cau-edr/cau/scanner"
)

// SARIF 2.1.0 constants.
const (
	SARIFSchema  = "https://json.schemastore.org/sarif-2.1.0.json"
	SARIFVersion = "2.1.0"
	// SARIFSrcRoot is the uriBaseId used for paths relative to WithRoot.
	SARIFSrcRoot = "%SRCROOT%"

	// Fixed rule ids. Hash and YARA rules are derived per finding.
	SARIFRuleHeuristic = "heuristic/score"
	SARIFRuleScanError = "scan/error"
)

// ── SARIF object model (only the subset the reporter emits) ──────────────────

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool               sarifTool                   `json:"tool"`
	Invocations        []sarifInvocation           `json:"invocations"`
	OriginalURIBaseIDs map[string]sarifArtifactLoc `json:"originalUriBaseIds,omitempty"`
	Results            []sarifResult               `json:"results"`
	Properties         map[string]interface{}      `json:"properties,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string                 `json:"id"`
	Name             string                 `json:"name,omitempty"`
	ShortDescription *sarifMessage          `json:"shortDescription,omitempty"`
	FullDescription  *sarifMessage          `json:"fullDescription,omitempty"`
	DefaultConfig    *sarifRuleConfig       `json:"defaultConfiguration,omitempty"`
	Properties       map[string]interface{} `json:"properties,omitempty"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifInvocation struct {
	ExecutionSuccessful        bool                `json:"executionSuccessful"`
	ExitCode                   int                 `json:"exitCode"`
	ExitCodeDescription        string              `json:"exitCodeDescription,omitempty"`
	EndTimeUTC                 string              `json:"endTimeUtc,omitempty"`
	ToolExecutionNotifications []sarifNotification `json:"toolExecutionNotifications,omitempty"`
}

type sarifNotification struct {
	Level   string       `json:"level"`
	Message sarifMessage `json:"message"`
}

type sarifResult struct {
	RuleID              string                 `json:"ruleId"`
	RuleIndex           int                    `json:"ruleIndex"`
	Level               string                 `json:"level"`
	Message             sarifMessage           `json:"message"`
	Locations           []sarifLocation        `json:"locations"`
	PartialFingerprints map[string]string      `json:"partialFingerprints,omitempty"`
	Properties          map[string]interface{} `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLoc `json:"artifactLocation"`
	Region           *sarifRegion     `json:"region,omitempty"`
}

type sarifArtifactLoc struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId,omitempty"`
}

type sarifRegion struct {
	ByteOffset int64         `json:"byteOffset"`
	ByteLength int           `json:"byteLength"`
	Snippet    *sarifSnippet `json:"snippet,omitempty"`
}

type sarifSnippet struct {
	Text   string `json:"text,omitempty"`
	Binary string `json:"binary,omitempty"`
}

// SARIFReporter writes a SARIF 2.1.0 log.
type SARIFReporter struct {
	cfg config
}

// NewSARIFReporter builds a reporter from the shared options.
func NewSARIFReporter(opts ...Option) *SARIFReporter {
	return &SARIFReporter{cfg: buildConfig(opts)}
}

// Write encodes the log to w.
func (r *SARIFReporter) Write(w io.Writer, in Input) error {
	log := r.build(in)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	if r.cfg.indent {
		enc.SetIndent("", "  ")
	}
	if err := enc.Encode(log); err != nil {
		return fmt.Errorf("report: encode sarif: %w", err)
	}
	return nil
}

// ruleTable assigns a stable index to every rule id. Rules are sorted so the
// table (and therefore every ruleIndex) does not depend on scan order.
type ruleTable struct {
	rules []sarifRule
	index map[string]int
}

func (t *ruleTable) add(rule sarifRule) {
	if t.index == nil {
		t.index = make(map[string]int)
	}
	if _, ok := t.index[rule.ID]; ok {
		return
	}
	t.index[rule.ID] = len(t.rules)
	t.rules = append(t.rules, rule)
}

func (t *ruleTable) sorted() {
	sort.SliceStable(t.rules, func(i, j int) bool { return t.rules[i].ID < t.rules[j].ID })
	for i, r := range t.rules {
		t.index[r.ID] = i
	}
}

func (r *SARIFReporter) build(in Input) sarifLog {
	c := r.cfg
	policy := &ExitPolicy{cfg: c}
	code, reason := policy.decide(in)

	// ── pass 1: rules ──
	var table ruleTable
	for _, res := range in.Results {
		if res.Detected {
			table.add(c.hashRule(res))
		}
		for _, m := range res.YaraMatches {
			table.add(c.yaraRule(m))
		}
	}
	if c.sarifIncludeHeuristics && len(in.HeuristicBreach(c.heuristicThreshold)) > 0 {
		table.add(sarifRule{
			ID:               SARIFRuleHeuristic,
			Name:             "HeuristicScore",
			ShortDescription: &sarifMessage{Text: "String and API heuristic score reached the alert threshold"},
			FullDescription: &sarifMessage{Text: fmt.Sprintf(
				"The file's imported APIs and embedded strings scored at or above the heuristic threshold (%d). "+
					"This is evidence of suspicious capability, not a confirmed detection.", c.heuristicThreshold)},
			DefaultConfig: &sarifRuleConfig{Level: c.levelHeuristic},
			Properties:    map[string]interface{}{"threshold": c.heuristicThreshold},
		})
	}
	if c.sarifIncludeScanErrors && in.FileErrorCount() > 0 {
		table.add(sarifRule{
			ID:               SARIFRuleScanError,
			Name:             "ScanError",
			ShortDescription: &sarifMessage{Text: "The engine could not scan this file"},
			FullDescription:  &sarifMessage{Text: "An unscanned artifact is a coverage gap, not a clean bill of health."},
			DefaultConfig:    &sarifRuleConfig{Level: c.levelScanError},
		})
	}
	table.sorted()

	// ── pass 2: results ──
	results := []sarifResult{}
	byPath := in.HeuristicsByPath()
	seenHeur := make(map[string]bool)

	for _, res := range in.Results {
		loc := c.location(res.FilePath, nil)

		if res.Detected {
			rule := c.hashRule(res)
			results = append(results, sarifResult{
				RuleID:    rule.ID,
				RuleIndex: table.index[rule.ID],
				Level:     c.levelHash,
				Message: sarifMessage{Text: c.boundedMessage(fmt.Sprintf(
					"%s signature match: %s (%s)", res.MatchType, res.ThreatName, res.MatchHash))},
				Locations:           []sarifLocation{loc},
				PartialFingerprints: c.fingerprints(res),
				Properties: map[string]interface{}{
					"hashType": c.boundedMessage(res.MatchType),
					"hash":     c.boundedHash(res.MatchHash),
					"threat":   c.boundedMessage(res.ThreatName),
				},
			})
		}

		for _, m := range res.YaraMatches {
			rule := c.yaraRule(m)
			locs := make([]sarifLocation, 0, len(m.Strings))
			for _, s := range m.Strings {
				locs = append(locs, c.location(res.FilePath, &s))
			}
			if len(locs) == 0 {
				locs = append(locs, loc)
			}
			text := fmt.Sprintf("YARA rule %s::%s matched", m.Namespace, m.RuleName)
			if d := m.MetaString("description"); d != "" {
				text += ": " + d
			}
			if len(m.Strings) > 0 {
				text += fmt.Sprintf(" (%d string(s))", len(m.Strings))
			}
			props := map[string]interface{}{
				"rule":      c.boundedMessage(m.RuleName),
				"namespace": c.boundedMessage(m.Namespace),
			}
			if len(m.Tags) > 0 {
				props["tags"] = boundedList(c, m.Tags)
			}
			if tl, ok := m.MetaInt("threat_level"); ok {
				props["threat_level"] = tl
			}
			results = append(results, sarifResult{
				RuleID:              rule.ID,
				RuleIndex:           table.index[rule.ID],
				Level:               c.levelYara,
				Message:             sarifMessage{Text: c.boundedMessage(text)},
				Locations:           locs,
				PartialFingerprints: c.fingerprints(res),
				Properties:          props,
			})
		}

		if res.Error != nil && c.sarifIncludeScanErrors {
			results = append(results, sarifResult{
				RuleID:    SARIFRuleScanError,
				RuleIndex: table.index[SARIFRuleScanError],
				Level:     c.levelScanError,
				Message:   sarifMessage{Text: c.boundedMessage("scan failed: " + res.Error.Error())},
				Locations: []sarifLocation{loc},
			})
		}

		if h, ok := byPath[res.FilePath]; ok && !seenHeur[res.FilePath] {
			seenHeur[res.FilePath] = true
			results = c.appendHeuristic(results, &table, h)
		}
	}

	// Heuristic-only paths (no ScanResult), in the sorted tail order AllPaths
	// produces.
	for _, p := range in.AllPaths() {
		if seenHeur[p] {
			continue
		}
		if h, ok := byPath[p]; ok {
			seenHeur[p] = true
			results = c.appendHeuristic(results, &table, h)
		}
	}

	// ── invocation ──
	inv := sarifInvocation{
		ExecutionSuccessful: in.RunError == nil,
		ExitCode:            code,
		ExitCodeDescription: reason,
		EndTimeUTC:          c.timestamp(),
	}
	if in.RunError != nil {
		inv.ToolExecutionNotifications = []sarifNotification{{
			Level:   LevelError,
			Message: sarifMessage{Text: c.errorString(in.RunError)},
		}}
	}

	run := sarifRun{
		Tool: sarifTool{Driver: sarifDriver{
			Name:           c.toolName,
			Version:        c.toolVersion,
			InformationURI: c.informationURI,
			Rules:          table.rules,
		}},
		Invocations: []sarifInvocation{inv},
		Results:     results,
		Properties: map[string]interface{}{
			"filesScanned":        len(in.AllPaths()),
			"hashDetections":      in.HashDetectionCount(),
			"yaraDetections":      in.YaraDetectionCount(),
			"heuristicDetections": len(in.HeuristicBreach(c.heuristicThreshold)),
			"errors":              in.ErrorCount(),
			"elapsedMs":           in.Elapsed.Milliseconds(),
			"failOn":              c.failOn.String(),
		},
	}
	if base := rootURI(c.root); base != "" {
		run.OriginalURIBaseIDs = map[string]sarifArtifactLoc{SARIFSrcRoot: {URI: base}}
	}
	if table.rules == nil {
		run.Tool.Driver.Rules = []sarifRule{}
	}

	return sarifLog{Schema: SARIFSchema, Version: SARIFVersion, Runs: []sarifRun{run}}
}

func (c config) appendHeuristic(results []sarifResult, table *ruleTable, h scanner.HeuristicResult) []sarifResult {
	loc := c.location(h.FilePath, nil)
	if h.Error != nil {
		if c.sarifIncludeScanErrors {
			results = append(results, sarifResult{
				RuleID:    SARIFRuleScanError,
				RuleIndex: table.index[SARIFRuleScanError],
				Level:     c.levelScanError,
				Message:   sarifMessage{Text: c.boundedMessage("heuristics failed: " + h.Error.Error())},
				Locations: []sarifLocation{loc},
			})
		}
		return results
	}
	if !c.sarifIncludeHeuristics || !heuristicBreached(h, c.heuristicThreshold) {
		return results
	}

	threshold := thresholdFor(h, c.heuristicThreshold)
	cats := categories(h)
	text := fmt.Sprintf("heuristic score %d reached threshold %d", h.Score, threshold)
	if len(cats) > 0 {
		text += ": " + strings.Join(cats, ", ")
	}
	indicators := make([]map[string]interface{}, 0, len(h.Matches))
	for _, m := range h.Matches {
		ind := map[string]interface{}{
			"indicator": c.boundedMessage(m.Indicator),
			"category":  c.boundedMessage(m.Category),
			"source":    c.boundedMessage(m.Source),
		}
		if m.Score != 0 {
			ind["score"] = m.Score
		}
		if m.Hits > 1 {
			ind["hits"] = m.Hits
		}
		indicators = append(indicators, ind)
	}
	return append(results, sarifResult{
		RuleID:    SARIFRuleHeuristic,
		RuleIndex: table.index[SARIFRuleHeuristic],
		Level:     c.levelHeuristic,
		Message:   sarifMessage{Text: c.boundedMessage(text)},
		Locations: []sarifLocation{loc},
		Properties: map[string]interface{}{
			"score":      h.Score,
			"threshold":  threshold,
			"indicators": indicators,
		},
	})
}

// categories lists the distinct heuristic categories in first-seen order.
func categories(h scanner.HeuristicResult) []string {
	var out []string
	seen := make(map[string]bool)
	for _, m := range h.Matches {
		if !seen[m.Category] {
			seen[m.Category] = true
			out = append(out, m.Category)
		}
	}
	return out
}

func (c config) hashRule(res scanner.ScanResult) sarifRule {
	threat := c.boundedMessage(res.ThreatName)
	return sarifRule{
		ID:               "hash/" + slug(res.ThreatName),
		Name:             "HashSignature",
		ShortDescription: &sarifMessage{Text: "Known-malware hash signature: " + threat},
		FullDescription: &sarifMessage{Text: fmt.Sprintf(
			"The file's cryptographic digest is listed in the signature database as %q.", threat)},
		DefaultConfig: &sarifRuleConfig{Level: c.levelHash},
		Properties:    map[string]interface{}{"threat": threat, "kind": "hash"},
	}
}

func (c config) yaraRule(m scanner.YaraMatch) sarifRule {
	ns := m.Namespace
	if ns == "" {
		ns = "default"
	}
	rule := sarifRule{
		ID:            "yara/" + slug(ns) + "/" + c.boundedMessage(m.RuleName),
		Name:          c.boundedMessage(m.RuleName),
		DefaultConfig: &sarifRuleConfig{Level: c.levelYara},
		Properties: map[string]interface{}{
			"kind":      "yara",
			"namespace": c.boundedMessage(ns),
		},
	}
	if d := m.MetaString("description"); d != "" {
		rule.ShortDescription = &sarifMessage{Text: c.boundedMessage(d)}
	} else {
		rule.ShortDescription = &sarifMessage{Text: "YARA rule " + c.boundedMessage(m.RuleName)}
	}
	if len(m.Tags) > 0 {
		rule.Properties["tags"] = boundedList(c, m.Tags)
	}
	if tl, ok := m.MetaInt("threat_level"); ok {
		rule.Properties["threat_level"] = tl
	}
	if a := m.MetaString("author"); a != "" {
		rule.Properties["author"] = c.boundedMessage(a)
	}
	return rule
}

func boundedList(c config, in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, c.boundedMessage(s))
	}
	sort.Strings(out)
	return out
}

// location builds a physicalLocation for a path and, when s is non-nil, a
// byte region for a matched string.
func (c config) location(p string, s *scanner.YaraMatchString) sarifLocation {
	uri, rel := relativeURI(c.root, p)
	art := sarifArtifactLoc{URI: uri}
	if rel {
		art.URIBaseID = SARIFSrcRoot
	}
	pl := sarifPhysicalLocation{ArtifactLocation: art}
	if s != nil {
		data, _ := truncateBytes(s.Data, c.maxMatchStringBytes)
		pl.Region = &sarifRegion{
			ByteOffset: int64(s.Offset),
			ByteLength: len(s.Data),
			Snippet:    &sarifSnippet{Binary: hexString(data)},
		}
		if pv := preview(s.Data, c.maxPreviewBytes); pv != "" {
			pl.Region.Snippet.Text = pv
		}
	}
	return sarifLocation{PhysicalLocation: pl}
}

// fingerprints lets a code-scanning UI recognise the same file across runs
// even when it moves: the content hash is the identity.
func (c config) fingerprints(res scanner.ScanResult) map[string]string {
	if res.SHA256 == "" {
		return nil
	}
	return map[string]string{"sha256/v1": c.boundedHash(res.SHA256)}
}
