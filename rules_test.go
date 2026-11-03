package ctis

import (
	"strings"
	"testing"
	"time"
)

func ruleReport(rules []Rule, f Finding) *Report {
	r := NewReport()
	r.Metadata.ID = "019a2b3c-4d5e-7000-8000-000000000001"
	r.Metadata.GeneratedAt = time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
	r.Assets = []Asset{{ID: "a", Type: AssetTypeHost, Value: "web01.example.com"}}
	r.Rules = rules
	if f.AssetRef == "" {
		f.AssetRef = "a"
	}
	if f.Title == "" {
		f.Title = "t"
	}
	if f.Type == "" {
		f.Type = FindingTypeWeakness
	}
	if f.Severity == "" {
		f.Severity = SeverityHigh
	}
	r.Findings = []Finding{f}
	return r
}

func TestRuleCatalog(t *testing.T) {
	good := Rule{ID: "r-1", RuleID: "py.sqli", Name: "SQL injection", HelpURI: "https://example.com/rules/sqli", DefaultSeverity: SeverityHigh, Tags: []string{"security"}, CWEIDs: []string{"CWE-89"}}
	cases := []struct {
		name    string
		rules   []Rule
		finding Finding
		want    string // empty = valid
	}{
		{"valid", []Rule{good}, Finding{RuleID: "py.sqli", RuleRef: "r-1"}, ""},
		{"catalog without refs", []Rule{good}, Finding{RuleID: "other"}, ""},
		{"unknown ref", []Rule{good}, Finding{RuleID: "py.sqli", RuleRef: "r-9"}, `rule_ref "r-9" names no rule`},
		{"rule id differs", []Rule{good}, Finding{RuleID: "py.xss", RuleRef: "r-1"}, `differs from rule_id "py.sqli"`},
		{"ref without rule id", []Rule{good}, Finding{RuleRef: "r-1"}, "rule_id is required when rule_ref is set"},
		{"missing id", []Rule{{RuleID: "x"}}, Finding{}, "rules[0]: id is required"},
		{"missing rule id", []Rule{{ID: "r-1"}}, Finding{}, "rules[0]: rule_id is required"},
		{"duplicate id", []Rule{good, good}, Finding{}, `rules[1]: duplicate id "r-1"`},
		{"uuid-shaped id", []Rule{{ID: "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b", RuleID: "x"}}, Finding{}, "UUID-shaped"},
		{"javascript help uri", []Rule{{ID: "r-1", RuleID: "x", HelpURI: "javascript:alert(1)"}}, Finding{}, "rules[0].help_uri"},
		{"bad severity", []Rule{{ID: "r-1", RuleID: "x", DefaultSeverity: "urgent"}}, Finding{}, "invalid default_severity"},
		{"bad cwe", []Rule{{ID: "r-1", RuleID: "x", CWEIDs: []string{"89"}}}, Finding{}, "cwe_ids[0]"},
		{"too many tags", []Rule{{ID: "r-1", RuleID: "x", Tags: make([]string, MaxRuleTags+1)}}, Finding{}, "tags has 65 entries"},
		{"long name", []Rule{{ID: "r-1", RuleID: "x", Name: strings.Repeat("é", MaxRuleNameLen+1)}}, Finding{}, "rules[0].name longer than 1024 characters"},
		{"name at limit in characters", []Rule{{ID: "r-1", RuleID: "x", Name: strings.Repeat("é", MaxRuleNameLen)}}, Finding{}, ""},
		{"invalid utf-8", []Rule{{ID: "r-1", RuleID: "x", Help: "\xff"}}, Finding{}, "rules[0].help is not valid UTF-8"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ruleReport(tc.rules, tc.finding).Validate()
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("want valid, got %v", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestRuleCatalogTooManyRules(t *testing.T) {
	rules := make([]Rule, MaxRules+1)
	err := ruleReport(rules, Finding{}).Validate()
	if err == nil || !strings.Contains(err.Error(), "rules has 10001 entries") {
		t.Fatalf("want bound error, got %v", err)
	}
}

func TestRuleProvenanceAndToolContent(t *testing.T) {
	digest := strings.Repeat("ab", 32)
	cases := []struct {
		name string
		mod  func(r *Report)
		want string
	}{
		{"valid", func(r *Report) {
			r.Rules = []Rule{{ID: "r-1", RuleID: "cve-2026-1", ContentSHA256: digest, ContentPath: "http/cves/2026/CVE-2026-1.yaml"}}
			r.Tool = &Tool{Name: "scanner", Content: []ToolContent{{Name: "templates", Version: "v10.3.1", SHA256: digest}}}
		}, ""},
		{"rule digest uppercase", func(r *Report) {
			r.Rules = []Rule{{ID: "r-1", RuleID: "x", ContentSHA256: strings.ToUpper(digest)}}
		}, "content_sha256 is not lowercase hex"},
		{"rule path control char", func(r *Report) {
			r.Rules = []Rule{{ID: "r-1", RuleID: "x", ContentPath: "a\nb"}}
		}, "content_path has a control character"},
		{"rule path too long", func(r *Report) {
			r.Rules = []Rule{{ID: "r-1", RuleID: "x", ContentPath: strings.Repeat("a", MaxContentPathLen+1)}}
		}, "content_path longer than 512"},
		{"content without name", func(r *Report) {
			r.Tool = &Tool{Name: "s", Content: []ToolContent{{Version: "1"}}}
		}, "tool.content[0].name is required"},
		{"content bad digest", func(r *Report) {
			r.Tool = &Tool{Name: "s", Content: []ToolContent{{Name: "db", SHA256: "abc"}}}
		}, "tool.content[0].sha256"},
		{"too much content", func(r *Report) {
			r.Tool = &Tool{Name: "s", Content: make([]ToolContent, MaxToolContent+1)}
		}, "tool.content has 17 entries"},
		{"finding tool content checked", func(r *Report) {
			r.Findings[0].Tool = &Tool{Name: "s", Content: []ToolContent{{Name: ""}}}
		}, "content[0].name is required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := ruleReport(nil, Finding{})
			tc.mod(r)
			err := r.Validate()
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("want valid, got %v", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestNetworkDeviceKind(t *testing.T) {
	for _, tc := range []struct {
		name  string
		typ   AssetType
		value string
		kind  NetworkDeviceKind
		want  string
	}{
		{"firewall", AssetTypeNetworkDevice, "fw01.example.com", NetworkDeviceFirewall, ""},
		{"unknown kind", AssetTypeNetworkDevice, "fw01.example.com", "modem", `network_device.kind "modem" is invalid`},
		{"on a host", AssetTypeHost, "web01.example.com", NetworkDeviceRouter, "network_device is only for network_device assets"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := ruleReport(nil, Finding{})
			r.Assets[0].Type = tc.typ
			r.Assets[0].Value = tc.value
			r.Assets[0].Technical = &AssetTechnical{NetworkDevice: &NetworkDeviceTechnical{Kind: tc.kind}}
			err := r.Validate()
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("want valid, got %v", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
}
