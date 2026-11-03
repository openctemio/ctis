package sarif

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/openctemio/ctis/v2"
	"github.com/openctemio/ctis/v2/severity"
)

// The rule catalog: SARIF run.tool.driver.rules[] <-> CTIS rules[].
//
// Import adds one CTIS rule for each SARIF rule a result resolves to (by
// ruleId, else by index when the ids agree) and names it from the finding
// with rule_ref. Rules no result refers to are not copied. The rule's id is
// properties["ctis/id"] when the exporter wrote one (a valid document
// reference not used yet), else rule-N.
//
// Export writes the catalog: in a report with one run every CTIS rule, in
// catalog order; with several runs the rules the run's findings name. A
// finding without a catalog rule gets a rule built from it, after the
// catalog rules, sorted by id. A catalog rule takes the members the catalog
// lacks (precision, the type tag, OWASP ids) from its first finding, so the
// findings read back the same.

// ruleRefKey is the rule property that carries the CTIS rule id.
const ruleRefKey = "ctis/id"

// catalog collects the CTIS rules of one import.
type catalog struct {
	rules []ctis.Rule
	used  map[string]bool
	byPtr map[*Rule]string
}

func newCatalog() *catalog {
	return &catalog{used: map[string]bool{}, byPtr: map[*Rule]string{}}
}

// ref returns the id of the CTIS rule of r, adding it on first use; "" when
// the catalog is full.
func (c *catalog) ref(r *Rule) string {
	if id, ok := c.byPtr[r]; ok {
		return id
	}
	if len(c.rules) >= ctis.MaxRules {
		c.byPtr[r] = ""
		return ""
	}
	id, _ := r.Properties[ruleRefKey].(string)
	if !ctis.IsDocumentRef(id) || c.used[id] {
		for n := len(c.rules) + 1; ; n++ {
			id = fmt.Sprintf("rule-%d", n)
			if !c.used[id] {
				break
			}
		}
	}
	c.used[id] = true
	c.byPtr[r] = id
	c.rules = append(c.rules, ctisRuleOf(r, id))
	return id
}

// ctisRuleOf maps a SARIF rule to a CTIS rule, within the CTIS bounds.
func ctisRuleOf(r *Rule, id string) ctis.Rule {
	out := ctis.Rule{
		ID:     id,
		RuleID: cutRunes(r.ID, ctis.MaxRuleIDLen),
		Name:   cutRunes(r.Name, ctis.MaxRuleNameLen),
	}
	if r.ShortDescription != nil {
		out.ShortDescription = cutRunes(r.ShortDescription.Text, ctis.MaxRuleShortDescLen)
	}
	if r.FullDescription != nil {
		out.FullDescription = cutRunes(r.FullDescription.Text, ctis.MaxRuleTextLen)
	}
	if r.Help != nil {
		out.Help = cutRunes(r.Help.Text, ctis.MaxRuleTextLen)
	}
	if ctis.IsWebURL(r.HelpURI) {
		out.HelpURI = r.HelpURI
	}
	if score, ok := securitySeverity(r.Properties); ok {
		out.DefaultSeverity = ctis.Severity(severity.FromCVSS(score))
	} else if r.DefaultConfiguration != nil && r.DefaultConfiguration.Level != "" {
		sev, _ := imp.Lookup("level_severity", r.DefaultConfiguration.Level)
		out.DefaultSeverity = ctis.Severity(sev)
	}
	seen := map[string]bool{}
	for _, t := range stringOrStrings(r.Properties["tags"]) {
		t = strings.TrimSpace(t)
		if t == "" || utf8.RuneCountInString(t) > ctis.MaxRuleTagLen || seen[t] || len(out.Tags) >= ctis.MaxRuleTags {
			continue
		}
		seen[t] = true
		out.Tags = append(out.Tags, t)
	}
	if cwes := sarifCWEs(r.Properties); len(cwes) > 0 {
		if len(cwes) > ctis.MaxRuleCWEIDs {
			cwes = cwes[:ctis.MaxRuleCWEIDs]
		}
		out.CWEIDs = cwes
	}
	return out
}

func cutRunes(s string, n int) string {
	s = strings.ToValidUTF8(s, "�")
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}

// sarifRuleOfCatalog writes a CTIS rule as a SARIF rule; from, when not nil,
// is the first finding of the rule and fills what the catalog lacks.
func sarifRuleOfCatalog(cr *ctis.Rule, from *ctis.Finding, toolName string) Rule {
	var rule Rule
	if from != nil {
		rule = sarifRuleOf(from, cr.RuleID, toolName)
	}
	rule.ID = cr.RuleID
	rule.Name = cr.Name
	rule.ShortDescription, rule.FullDescription, rule.Help = msg(cr.ShortDescription), msg(cr.FullDescription), msg(cr.Help)
	if from != nil && rule.ShortDescription == nil && from.Description != "" {
		rule.ShortDescription = &Message{Text: from.Description}
	}
	if from != nil && rule.Help == nil && from.Remediation != nil && from.Remediation.Recommendation != "" {
		rule.Help = &Message{Text: from.Remediation.Recommendation}
	}
	if cr.HelpURI != "" {
		rule.HelpURI = cr.HelpURI
	}
	props := rule.Properties
	if props == nil {
		props = map[string]any{}
	}
	// The rule's default severity is the catalog's own, never the first
	// finding's.
	rule.DefaultConfiguration = nil
	delete(props, "security-severity")
	if cr.DefaultSeverity.IsValid() {
		rule.DefaultConfiguration = &RuleConfig{Level: sarifLevel(cr.DefaultSeverity)}
		if s, ok := sarifSecuritySeverity(&ctis.Finding{Severity: cr.DefaultSeverity}); ok {
			props["security-severity"] = s
		}
	}
	tags := append([]string(nil), cr.Tags...)
	if t, ok := props["tags"].([]string); ok {
		tags = append(tags, t...)
	}
	if len(tags) > 0 {
		props["tags"] = tags
	}
	if len(cr.CWEIDs) > 0 {
		props["cwe"] = append([]string(nil), cr.CWEIDs...)
	}
	props[ruleRefKey] = cr.ID
	rule.Properties = props
	return rule
}

func msg(s string) *Message {
	if s == "" {
		return nil
	}
	return &Message{Text: s}
}

// redact masks a secret scanner's raw match in the text of the catalog rule
// id, the way the finding's own text is masked (the rule's description often
// repeats the match).
func (c *catalog) redact(id, rawSnippet string) {
	for i := range c.rules {
		r := &c.rules[i]
		if r.ID != id {
			continue
		}
		f := ctis.Finding{
			Type: ctis.FindingTypeSecret, Title: r.Name, Description: r.ShortDescription, Message: r.FullDescription,
			Remediation: &ctis.Remediation{Recommendation: r.Help}, Tags: r.Tags,
			Location: &ctis.FindingLocation{Snippet: rawSnippet},
		}
		ctis.RedactSecretFindingWith(&f, true, isRedacted)
		r.Name, r.ShortDescription, r.FullDescription, r.Help, r.Tags = f.Title, f.Description, f.Message, f.Remediation.Recommendation, f.Tags
		return
	}
}
