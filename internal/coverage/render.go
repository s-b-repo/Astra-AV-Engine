package coverage

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"
)

// Output formats.
var Formats = []string{"text", "json", "navigator", "sarif"}

// WriteText renders the matrix for a terminal.
func WriteText(dst io.Writer, m *Matrix) error {
	w := &errWriter{w: dst}
	fmt.Fprintf(w, "ATT&CK coverage of the shipped detection content (%s %s)\n\n", m.Tool, m.Version)
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "Source\tPyramid of Pain\tTier\tEntries\tMapped\tContent\tNote")
	for _, s := range m.Sources {
		content := ""
		if s.Content > 0 {
			content = fmt.Sprint(s.Content)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%d\t%s\t%s\n", s.Name, s.Pyramid, s.Tier, s.Entries, s.Mapped, content, s.Note)
	}
	flush(tw, w)

	fmt.Fprintf(w, "\n%d technique(s) with detection content:\n\n", len(m.Techniques))
	tw = tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "Technique\tName\tState\tTier\tSources\tContent")
	for _, t := range m.Techniques {
		labels := make([]string, 0, len(t.Entries))
		for _, e := range t.Entries {
			labels = append(labels, e.Label)
		}
		name := t.Name
		if name == "" {
			name = "(not in the engine's ATT&CK catalog)"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", t.ID, name, t.State(), t.Tier, strings.Join(t.Sources, ", "), strings.Join(labels, "; "))
	}
	flush(tw, w)

	if len(m.Gaps) > 0 {
		fmt.Fprintf(w, "\n%d technique(s) with no engine content (planned, or owned by the sensor/console):\n\n", len(m.Gaps))
		tw = tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "Technique\tName\tState\tNote")
		for _, g := range m.Gaps {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", g.ID, g.Name, g.State, g.Note)
		}
		flush(tw, w)
	}

	if len(m.Unmapped) > 0 {
		fmt.Fprintf(w, "\n%d content entr%s with no ATT&CK technique (reported, never padded with a loose fit):\n\n",
			len(m.Unmapped), plural(len(m.Unmapped), "y", "ies"))
		tw = tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		for _, e := range m.Unmapped {
			fmt.Fprintf(tw, "%s\t%s\t%s\n", e.Source, e.Label, e.Description)
		}
		flush(tw, w)
	}
	return w.err
}

// errWriter records the first write error and drops later writes, so a
// renderer that fans out across many Fprintf/Flush calls still reports a
// broken pipe or a full disk instead of returning success.
type errWriter struct {
	w   io.Writer
	err error
}

func (e *errWriter) Write(p []byte) (int, error) {
	if e.err != nil {
		return len(p), nil
	}
	n, err := e.w.Write(p)
	if err != nil {
		e.err = err
	}
	return n, err
}

// flush flushes a tabwriter, recording any error on the errWriter it feeds.
func flush(tw *tabwriter.Writer, w *errWriter) {
	if err := tw.Flush(); err != nil && w.err == nil {
		w.err = err
	}
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// WriteJSON renders the matrix as JSON.
func WriteJSON(w io.Writer, m *Matrix, indent bool) error {
	enc := json.NewEncoder(w)
	if indent {
		enc.SetIndent("", "  ")
	}
	return enc.Encode(m)
}

// Navigator layer format (MITRE ATT&CK Navigator, layer schema 4.5).
const (
	NavigatorLayerVersion = "4.5"
	NavigatorVersion      = "4.9.1"
	NavigatorATTACK       = "15"
	NavigatorDomain       = "enterprise-attack"
)

type navLayer struct {
	Name                          string         `json:"name"`
	Versions                      navVersions    `json:"versions"`
	Domain                        string         `json:"domain"`
	Description                   string         `json:"description"`
	Filters                       navFilters     `json:"filters"`
	Sorting                       int            `json:"sorting"`
	Layout                        navLayout      `json:"layout"`
	HideDisabled                  bool           `json:"hideDisabled"`
	Techniques                    []navTechnique `json:"techniques"`
	Gradient                      navGradient    `json:"gradient"`
	LegendItems                   []navLegend    `json:"legendItems"`
	Metadata                      []navMeta      `json:"metadata"`
	ShowTacticRowBackground       bool           `json:"showTacticRowBackground"`
	SelectTechniquesAcrossTactics bool           `json:"selectTechniquesAcrossTactics"`
	SelectSubtechniquesWithParent bool           `json:"selectSubtechniquesWithParent"`
}

type navVersions struct {
	Attack    string `json:"attack"`
	Navigator string `json:"navigator"`
	Layer     string `json:"layer"`
}

type navFilters struct {
	Platforms []string `json:"platforms"`
}

type navLayout struct {
	Layout              string `json:"layout"`
	ShowID              bool   `json:"showID"`
	ShowName            bool   `json:"showName"`
	ShowAggregateScores bool   `json:"showAggregateScores"`
}

type navTechnique struct {
	TechniqueID       string    `json:"techniqueID"`
	Score             int       `json:"score"`
	Color             string    `json:"color,omitempty"`
	Comment           string    `json:"comment"`
	Enabled           bool      `json:"enabled"`
	Metadata          []navMeta `json:"metadata"`
	ShowSubtechniques bool      `json:"showSubtechniques"`
}

type navGradient struct {
	Colors   []string `json:"colors"`
	MinValue int      `json:"minValue"`
	MaxValue int      `json:"maxValue"`
}

type navLegend struct {
	Label string `json:"label"`
	Color string `json:"color"`
}

type navMeta struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// WriteNavigator renders the matrix as an ATT&CK Navigator layer. The score
// of a technique is the number of independent detectors with content for
// it; declared gaps are present with score 0 and a grey colour so the gap is
// visible rather than blank.
func WriteNavigator(w io.Writer, m *Matrix, indent bool) error {
	layer := navLayer{
		Name:        m.Tool + " coverage",
		Versions:    navVersions{Attack: NavigatorATTACK, Navigator: NavigatorVersion, Layer: NavigatorLayerVersion},
		Domain:      NavigatorDomain,
		Description: "Techniques the shipped detection content maps to. Score = number of independent detectors with content for the technique. Derived from the content by `cau coverage --format navigator`, never typed in.",
		Filters:     navFilters{Platforms: []string{"Windows", "Linux"}},
		Layout:      navLayout{Layout: "side", ShowID: true, ShowName: true},
		Gradient:    navGradient{Colors: []string{"#ffe766", "#8ec843"}, MinValue: 1, MaxValue: 3},
		LegendItems: []navLegend{
			{Label: "one detector", Color: "#ffe766"},
			{Label: "three or more detectors", Color: "#8ec843"},
			{Label: "declared gap", Color: "#d9d9d9"},
		},
		Metadata:                      []navMeta{{Name: "tool", Value: m.Tool}, {Name: "version", Value: m.Version}},
		SelectTechniquesAcrossTactics: true,
	}
	maxSources := 1
	for _, t := range m.Techniques {
		labels := make([]string, 0, len(t.Entries))
		for _, e := range t.Entries {
			labels = append(labels, e.Label)
		}
		if n := len(t.Sources); n > maxSources {
			maxSources = n
		}
		layer.Techniques = append(layer.Techniques, navTechnique{
			TechniqueID: t.ID, Score: len(t.Sources), Enabled: true,
			Comment: strings.Join(labels, "; "),
			Metadata: []navMeta{
				{Name: "sources", Value: strings.Join(t.Sources, ", ")},
				{Name: "tier", Value: t.Tier},
			},
		})
	}
	for _, g := range m.Gaps {
		layer.Techniques = append(layer.Techniques, navTechnique{
			TechniqueID: g.ID, Score: 0, Color: "#d9d9d9", Enabled: true,
			Comment:  "gap: " + g.Note,
			Metadata: []navMeta{{Name: "state", Value: "gap"}},
		})
	}
	if maxSources > layer.Gradient.MaxValue {
		layer.Gradient.MaxValue = maxSources
	}
	sort.Slice(layer.Techniques, func(i, j int) bool { return layer.Techniques[i].TechniqueID < layer.Techniques[j].TechniqueID })
	enc := json.NewEncoder(w)
	if indent {
		enc.SetIndent("", "  ")
	}
	return enc.Encode(layer)
}
