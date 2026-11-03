package ctis

import (
	"encoding/json"
	"sort"
	"strings"
)

// SARIF codeFlows to the finding's data_flow.
//
// A result's codeFlows (SARIF 2.1.0 section 3.36) hold one or more taint
// paths, each a list of threadFlows whose locations are the steps from the
// source of the data to the sink. A CTIS finding carries one data flow: the
// first threadFlow with a location is taken (a tool lists its primary path
// first). Each step's role is read from the threadFlowLocation's kinds,
// then from its message ("Source: ...", "Sink: ...", "Sanitizer ..."),
// then from its position: the first unmarked step is the source and the
// last the sink when no step is marked as such.
//
// The input is not trusted. The trace is decoded on its own and leniently
// (a malformed trace leaves the finding without a data flow, never fails
// it); at most maxSARIFCodeFlows codeFlows and maxSARIFThreadFlows
// threadFlows of each are looked at, and NormalizeDataFlow bounds the steps,
// cuts the text, makes paths repository-relative and masks credentials in
// the snippets.

// Bounds on how much of a result's codeFlows is looked at.
const (
	maxSARIFCodeFlows   = 10
	maxSARIFThreadFlows = 10
)

type sarifCodeFlow struct {
	ThreadFlows []json.RawMessage `json:"threadFlows"`
}

type sarifThreadFlow struct {
	Locations []json.RawMessage `json:"locations"`
}

type sarifThreadFlowLocation struct {
	Location *sarifFlowLocation `json:"location"`
	Kinds    []string           `json:"kinds"`
}

type sarifFlowLocation struct {
	PhysicalLocation *SARIFPhysicalLocation `json:"physicalLocation"`
	LogicalLocations []SARIFLogicalLocation `json:"logicalLocations"`
	Message          *SARIFMessage          `json:"message"`
}

// sarifRoots returns the absolute locations a run's originalUriBaseIds name,
// longest first, so the deepest root a path lies under is stripped.
func sarifRoots(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var bases map[string]json.RawMessage
	if json.Unmarshal(raw, &bases) != nil {
		return nil
	}
	var roots []string
	for _, b := range bases {
		var al struct {
			URI string `json:"uri"`
		}
		if json.Unmarshal(b, &al) != nil {
			continue
		}
		if p, abs := flowPath(al.URI); abs && p != "" && p != "/" {
			roots = append(roots, p)
		}
		if len(roots) >= maxSARIFCodeFlows {
			break
		}
	}
	sort.Slice(roots, func(i, j int) bool {
		if len(roots[i]) != len(roots[j]) {
			return len(roots[i]) > len(roots[j])
		}
		return roots[i] < roots[j]
	})
	return roots
}

// sarifDataFlow maps a result's codeFlows to a data flow, or nil.
func sarifDataFlow(raw json.RawMessage, roots []string) *DataFlow {
	if len(raw) == 0 {
		return nil
	}
	var flows []json.RawMessage
	if json.Unmarshal(raw, &flows) != nil {
		return nil
	}
	for i, cfRaw := range flows {
		if i >= maxSARIFCodeFlows {
			break
		}
		var cf sarifCodeFlow
		if json.Unmarshal(cfRaw, &cf) != nil {
			continue
		}
		for j, tfRaw := range cf.ThreadFlows {
			if j >= maxSARIFThreadFlows {
				break
			}
			var tf sarifThreadFlow
			if json.Unmarshal(tfRaw, &tf) != nil {
				continue
			}
			if df := sarifThreadFlowToDataFlow(tf.Locations, roots); df != nil {
				return df
			}
		}
	}
	return nil
}

type flowRole int

const (
	roleUnmarked flowRole = iota
	roleSource
	roleIntermediate
	roleSanitizer
	roleSink
)

func sarifThreadFlowToDataFlow(raws []json.RawMessage, roots []string) *DataFlow {
	type step struct {
		loc  DataFlowLocation
		role flowRole
	}
	var steps []step
	for _, r := range raws {
		if len(steps) >= MaxDataFlowSteps {
			break
		}
		var tfl sarifThreadFlowLocation
		if json.Unmarshal(r, &tfl) != nil || tfl.Location == nil {
			continue
		}
		loc, ok := sarifFlowStep(tfl.Location)
		if !ok {
			continue
		}
		steps = append(steps, step{loc, sarifStepRole(tfl.Kinds, loc.Label)})
	}
	if len(steps) == 0 {
		return nil
	}
	hasSource, hasSink := false, false
	for _, s := range steps {
		hasSource = hasSource || s.role == roleSource
		hasSink = hasSink || s.role == roleSink
	}
	// Position decides for unmarked steps: the first is the source and the
	// last the sink when no step says so; a one-step flow is its sink.
	first, last := -1, -1
	for i, s := range steps {
		if s.role == roleUnmarked {
			if first < 0 {
				first = i
			}
			last = i
		}
	}
	if !hasSink && last >= 0 {
		steps[last].role = roleSink
		if last == first {
			first = -1
		}
	}
	if !hasSource && first >= 0 {
		steps[first].role = roleSource
	}
	df := &DataFlow{}
	for i, s := range steps {
		l := s.loc
		l.Index = i
		switch s.role {
		case roleSource:
			l.Type = DataFlowLocationSource
			df.Sources = append(df.Sources, l)
		case roleSink:
			l.Type = DataFlowLocationSink
			df.Sinks = append(df.Sinks, l)
		case roleSanitizer:
			l.Type = DataFlowLocationSanitizer
			l.TaintState = "sanitized"
			df.Sanitizers = append(df.Sanitizers, l)
		default:
			l.Type = DataFlowLocationPropagator
			df.Intermediates = append(df.Intermediates, l)
		}
	}
	return NormalizeDataFlow(df, roots...)
}

// sarifFlowStep reads one threadFlowLocation's location. A location with no
// file, line, snippet or message says nothing and is skipped.
func sarifFlowStep(fl *sarifFlowLocation) (DataFlowLocation, bool) {
	var l DataFlowLocation
	if pl := fl.PhysicalLocation; pl != nil {
		if pl.ArtifactLocation != nil {
			l.Path = pl.ArtifactLocation.URI
		}
		if r := pl.Region; r != nil {
			l.Line, l.EndLine = r.StartLine, r.EndLine
			l.Column, l.EndColumn = r.StartColumn, r.EndColumn
			if r.Snippet != nil {
				l.Content = r.Snippet.Text
			}
		}
	}
	if len(fl.LogicalLocations) > 0 {
		ll := fl.LogicalLocations[0]
		l.Function = ll.FullyQualifiedName
		if l.Function == "" {
			l.Function = ll.Name
		}
	}
	if fl.Message != nil {
		l.Label = fl.Message.Text
	}
	ok := strings.TrimSpace(l.Path) != "" || l.Line > 0 || strings.TrimSpace(l.Content) != "" || strings.TrimSpace(l.Label) != ""
	return l, ok
}

// sarifStepRole reads a step's role from its kinds (SARIF 2.1.0 section
// 3.38.8; taint tools write "source", "sink", "sanitizer") and, failing
// that, from its message: a message that starts with "Source" or "Sink"
// (the form semgrep and opengrep write), "Propagator", or that says the
// data is sanitized.
func sarifStepRole(kinds []string, message string) flowRole {
	role := roleUnmarked
	for i, k := range kinds {
		if i >= 16 {
			break
		}
		switch k = strings.ToLower(strings.TrimSpace(k)); {
		case k == "source":
			role = roleSource
		case k == "sink":
			role = roleSink
		case strings.HasPrefix(k, "sanitiz"), strings.HasPrefix(k, "sanitis"):
			return roleSanitizer
		}
	}
	if role != roleUnmarked {
		return role
	}
	m := strings.ToLower(strings.TrimSpace(message))
	switch {
	case strings.Contains(m, "sanitiz"), strings.Contains(m, "sanitis"):
		return roleSanitizer
	case hasWordPrefix(m, "source"):
		return roleSource
	case hasWordPrefix(m, "sink"):
		return roleSink
	case hasWordPrefix(m, "propagator"):
		return roleIntermediate
	}
	return roleUnmarked
}

// hasWordPrefix reports whether s starts with the word w ("source:",
// "source '...'", not "sourceFile").
func hasWordPrefix(s, w string) bool {
	if !strings.HasPrefix(s, w) {
		return false
	}
	if len(s) == len(w) {
		return true
	}
	c := s[len(w)]
	return (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_'
}
