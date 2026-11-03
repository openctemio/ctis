package ctis

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// Bounds on the rule catalog.
const (
	MaxRules            = 10000
	MaxRuleIDLen        = 1024
	MaxRuleNameLen      = 1024
	MaxRuleShortDescLen = 1024
	MaxRuleTextLen      = 32768
	MaxRuleTags         = 64
	MaxRuleTagLen       = 256
	MaxRuleCWEIDs       = MaxCWEIDs
)

// Rule describes a rule or check once. Findings it detected name it with
// finding.rule_ref instead of repeating its text, and keep their own
// rule_id, which MUST equal the rule's rule_id (identity never depends on
// the catalog).
type Rule struct {
	// Document-local reference (required). Findings name the rule by it.
	ID string `json:"id"`

	// The tool's identifier of the rule (required).
	RuleID string `json:"rule_id"`

	// Human-readable rule name.
	Name string `json:"name,omitempty"`

	// One-sentence description (plain text).
	ShortDescription string `json:"short_description,omitempty"`

	// Full description (plain text).
	FullDescription string `json:"full_description,omitempty"`

	// How to fix what the rule finds (plain text).
	Help string `json:"help,omitempty"`

	// Page that documents the rule (http or https). Receivers never fetch it.
	HelpURI string `json:"help_uri,omitempty"`

	// Severity the tool gives the rule when a finding does not override it.
	DefaultSeverity Severity `json:"default_severity,omitempty"`

	// The tool's tags for the rule.
	Tags []string `json:"tags,omitempty"`

	// CWE identifiers the rule checks for.
	CWEIDs []string `json:"cwe_ids,omitempty"`

	// Namespaced producer data.
	Extensions Extensions `json:"extensions,omitempty"`
}

// validateRules checks the catalog and returns rule_id by rule id for the
// finding checks.
func validateRules(rules []Rule, add func(string, ...any)) map[string]string {
	if len(rules) > MaxRules {
		add("rules has %d entries, at most %d", len(rules), MaxRules)
	}
	byID := make(map[string]string, len(rules))
	for i := range rules {
		if i >= MaxRules {
			break
		}
		r := &rules[i]
		where := fmt.Sprintf("rules[%d]", i)
		if r.ID == "" {
			add("%s: id is required", where)
		} else {
			validateDocumentRef(where+".id", r.ID, add)
			if _, dup := byID[r.ID]; dup {
				add("%s: duplicate id %q", where, truncateForError(r.ID))
			}
		}
		switch {
		case strings.TrimSpace(r.RuleID) == "":
			add("%s: rule_id is required", where)
		case utf8.RuneCountInString(r.RuleID) > MaxRuleIDLen:
			add("%s: rule_id longer than %d", where, MaxRuleIDLen)
		}
		if r.ID != "" {
			if _, dup := byID[r.ID]; !dup {
				byID[r.ID] = r.RuleID
			}
		}
		checkRuleText(where+".name", r.Name, MaxRuleNameLen, add)
		checkRuleText(where+".short_description", r.ShortDescription, MaxRuleShortDescLen, add)
		checkRuleText(where+".full_description", r.FullDescription, MaxRuleTextLen, add)
		checkRuleText(where+".help", r.Help, MaxRuleTextLen, add)
		checkWebURL(where+".help_uri", r.HelpURI, add)
		if r.DefaultSeverity != "" && !r.DefaultSeverity.IsValid() {
			add("%s: invalid default_severity %q", where, truncateForError(string(r.DefaultSeverity)))
		}
		if len(r.Tags) > MaxRuleTags {
			add("%s: tags has %d entries, at most %d", where, len(r.Tags), MaxRuleTags)
		}
		for j, tag := range r.Tags {
			if j < MaxRuleTags {
				checkRuleText(fmt.Sprintf("%s.tags[%d]", where, j), tag, MaxRuleTagLen, add)
			}
		}
		if len(r.CWEIDs) > MaxRuleCWEIDs {
			add("%s: cwe_ids has %d entries, at most %d", where, len(r.CWEIDs), MaxRuleCWEIDs)
		}
		for j, c := range r.CWEIDs {
			if j < MaxRuleCWEIDs && !cweIDRE.MatchString(c) {
				add("%s: cwe_ids[%d] %q is not CWE-<n>", where, j, truncateForError(c))
			}
		}
		validateExtensions(where+".extensions", r.Extensions, add)
	}
	return byID
}

// validateRuleRef checks that a finding's rule_ref names a rule of the
// catalog and that the finding's rule_id agrees with it.
func validateRuleRef(i int, f *Finding, rules map[string]string, add func(string, ...any)) {
	if f.RuleRef == "" {
		return
	}
	ruleID, ok := rules[f.RuleRef]
	if !ok {
		validateDocumentRef(fmt.Sprintf("findings[%d].rule_ref", i), f.RuleRef, add)
		add("findings[%d]: rule_ref %q names no rule in this report", i, truncateForError(f.RuleRef))
		return
	}
	if f.RuleID == "" {
		add("findings[%d]: rule_id is required when rule_ref is set", i)
		return
	}
	if f.RuleID != ruleID {
		add("findings[%d]: rule_id %q differs from rule_id %q of rule %q", i, truncateForError(f.RuleID), truncateForError(ruleID), truncateForError(f.RuleRef))
	}
}

func checkRuleText(where, s string, limit int, add func(string, ...any)) {
	switch {
	case !utf8.ValidString(s):
		add("%s is not valid UTF-8", where)
	case utf8.RuneCountInString(s) > limit:
		add("%s longer than %d characters", where, limit)
	}
}
