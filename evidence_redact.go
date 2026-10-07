package ctis

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"
)

// Secret masking inside evidence items.
//
// Evidence may carry a sensitive value inside a span its Sensitive list
// marks: the tool marked it so the receiver can mask it for display and
// still reveal it to an authorized reader. RedactSecretFinding therefore
// leaves marked spans alone on purpose, and masks the known raw values
// everywhere else in the item (an unmarked copy of the secret in a response
// body is masked like in any other member). A span that a replacement moves
// is shifted with it; match offsets are not, and receivers recompute them
// after masking.

// redactEvidenceItems masks the candidates in every string of the items
// outside their marked spans.
func redactEvidenceItems(items []EvidenceItem, c candidates) {
	if len(c) == 0 {
		return
	}
	raws := make([]string, 0, len(c))
	for k := range c {
		raws = append(raws, k)
	}
	// Longest first, so a whole line is masked before its words.
	sort.Slice(raws, func(i, j int) bool {
		if len(raws[i]) != len(raws[j]) {
			return len(raws[i]) > len(raws[j])
		}
		return raws[i] < raws[j]
	})
	for i := range items {
		redactEvidenceItem(&items[i], raws, c)
	}
}

func redactEvidenceItem(it *EvidenceItem, raws []string, c candidates) {
	raw, err := json.Marshal(it)
	if err != nil {
		return
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return
	}
	spans := map[string][]*SensitiveSpan{}
	for i := range it.Sensitive {
		s := &it.Sensitive[i]
		spans[s.Pointer] = append(spans[s.Pointer], s)
	}
	doc = walkEvidence(doc, "", spans, raws, c, 0)
	out, err := json.Marshal(doc)
	if err != nil {
		return
	}
	var masked EvidenceItem
	if err := json.Unmarshal(out, &masked); err != nil {
		return
	}
	masked.Sensitive = it.Sensitive // shifted in place by walkEvidence
	*it = masked
}

func walkEvidence(v any, ptr string, spans map[string][]*SensitiveSpan, raws []string, c candidates, depth int) any {
	if depth > maxRedactDepth {
		return v
	}
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			if ptr == "" && k == "sensitive" {
				continue
			}
			x[k] = walkEvidence(e, ptr+"/"+escapePointer(k), spans, raws, c, depth+1)
		}
		return x
	case []any:
		for i, e := range x {
			x[i] = walkEvidence(e, ptr+"/"+strconv.Itoa(i), spans, raws, c, depth+1)
		}
		return x
	case string:
		return maskOutsideSpans(x, spans[ptr], raws, c)
	}
	return v
}

func escapePointer(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "~", "~0"), "/", "~1")
}

// maskOutsideSpans replaces every occurrence of a raw value that does not
// overlap a marked span, and shifts the spans that follow a replacement.
func maskOutsideSpans(s string, marked []*SensitiveSpan, raws []string, c candidates) string {
	for _, sp := range marked {
		if sp.Start == nil && sp.End == nil {
			return s // the whole string is marked
		}
	}
	for _, raw := range raws {
		mask := c[raw]
		from := 0
		for from <= len(s) {
			i := strings.Index(s[from:], raw)
			if i < 0 {
				break
			}
			start, end := from+i, from+i+len(raw)
			if overlapsSpan(start, end, marked) {
				from = end
				continue
			}
			s = s[:start] + mask + s[end:]
			delta := len(mask) - len(raw)
			for _, sp := range marked {
				if sp.Start != nil && *sp.Start >= end {
					v := *sp.Start + delta
					sp.Start = &v
				}
				if sp.End != nil && *sp.End >= end {
					v := *sp.End + delta
					sp.End = &v
				}
			}
			from = start + len(mask)
		}
	}
	return s
}

func overlapsSpan(start, end int, marked []*SensitiveSpan) bool {
	for _, sp := range marked {
		lo, hi := 0, int(^uint(0)>>1)
		if sp.Start != nil {
			lo = *sp.Start
		}
		if sp.End != nil {
			hi = *sp.End
		}
		if start < hi && end > lo {
			return true
		}
	}
	return false
}
