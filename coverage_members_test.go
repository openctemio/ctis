package ctis

import (
	"encoding/json"
	"os"
	"sort"
	"strings"
	"testing"
	"time"
)

func minimalReport17() *Report {
	r := NewReport()
	r.Metadata.GeneratedAt = time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
	return r
}

func TestValidateCoverageMembers(t *testing.T) {
	ts := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
	earlier := ts.Add(-time.Hour)
	good := func() *Report {
		r := minimalReport17()
		r.Metadata.StartedAt, r.Metadata.EndedAt = &earlier, &ts
		r.Metadata.Segment = &Segment{Index: 0, Count: 2}
		r.Metadata.Targets = []TargetOutcome{{Target: "example.com", Kind: AssetTypeDomainName, State: TargetDone}}
		r.Assets = []Asset{{ID: "a", Type: AssetTypeContainerImage, Value: "docker.io/library/nginx@sha256:" + strings.Repeat("a", 64),
			Environment: EnvironmentProduction, Owners: []AssetOwner{{Kind: OwnerKindTeam, Ref: "platform", Role: OwnerRoleTechnical}},
			FirstSeenAt: &earlier, LastSeenAt: &ts}, {ID: "b", Type: AssetTypeKubernetesWorkload, Value: "prod/api", State: AssetStateGone, StateReason: StateReasonResourceDeleted}}
		r.Dependencies = []Dependency{{ID: "d", Name: "lodash", AssetRef: "a"}}
		r.Relationships = []Relationship{{Type: RelDeployedFrom, FromRef: "b", ToRef: "a", Confidence: 90, FirstSeenAt: &earlier, LastSeenAt: &ts}}
		r.Findings = []Finding{{Type: FindingTypeMalware, Title: "t", Severity: SeverityUnknown, DependencyRef: "d", AssetRef: "a",
			CAPECIDs:   []string{"CAPEC-66"},
			Tool:       &Tool{Name: "scanner"},
			Validation: &FindingValidation{Status: ValidationExploited, Method: ValidationMethodPentest, EvidenceRefs: []string{"sha256:" + strings.Repeat("b", 64)}},
			Vulnerability: &VulnerabilityDetails{
				ThreatSignals: []ThreatSignal{{Type: ThreatSignalKEV, Source: "kev-catalog", DueOn: "2026-12-01"}}},
			Extensions: Extensions{"com.example.scanner": {"k": "v"}}}}
		r.Extensions = Extensions{"io.openctem": {"capability": "scan.ports@1"}}
		return r
	}
	if err := good().Validate(); err != nil {
		t.Fatalf("valid report rejected: %v", err)
	}
	bad := map[string]func(r *Report){
		"ended before started": func(r *Report) { r.Metadata.StartedAt, r.Metadata.EndedAt = r.Metadata.EndedAt, r.Metadata.StartedAt },
		"segment index":        func(r *Report) { r.Metadata.Segment.Index = 2 },
		"segment count":        func(r *Report) { r.Metadata.Segment.Count = 0 },
		"metadata without id":  func(r *Report) { r.Metadata.ID = "" },
		"duplicate target":     func(r *Report) { r.Metadata.Targets = append(r.Metadata.Targets, r.Metadata.Targets[0]) },
		"target too long":      func(r *Report) { r.Metadata.Targets[0].Target = strings.Repeat("x", MaxTargetLen+1) },
		"done with class":      func(r *Report) { r.Metadata.Targets[0].Class = TargetClassTimeout },
		"skipped timeout": func(r *Report) {
			r.Metadata.Targets[0].State, r.Metadata.Targets[0].Class = TargetSkipped, TargetClassTimeout
		},
		"environment":     func(r *Report) { r.Assets[0].Environment = "prod" },
		"owner kind":      func(r *Report) { r.Assets[0].Owners[0].Kind = "robot" },
		"owner ref empty": func(r *Report) { r.Assets[0].Owners[0].Ref = " " },
		"owner ref long":  func(r *Report) { r.Assets[0].Owners[0].Ref = strings.Repeat("x", MaxOwnerRefLen+1) },
		"too many owners": func(r *Report) { r.Assets[0].Owners = make([]AssetOwner, MaxAssetOwners+1) },
		"asset seen order": func(r *Report) {
			r.Assets[0].FirstSeenAt, r.Assets[0].LastSeenAt = r.Assets[0].LastSeenAt, r.Assets[0].FirstSeenAt
		},
		"gone without reason":    func(r *Report) { r.Assets[1].StateReason = "" },
		"reason without gone":    func(r *Report) { r.Assets[1].State = AssetStateActive },
		"dependency asset_ref":   func(r *Report) { r.Dependencies[0].AssetRef = "nope" },
		"finding dependency_ref": func(r *Report) { r.Findings[0].DependencyRef = "nope" },
		"finding tool name":      func(r *Report) { r.Findings[0].Tool.Name = "" },
		"validation status":      func(r *Report) { r.Findings[0].Validation.Status = "" },
		"validation method":      func(r *Report) { r.Findings[0].Validation.Method = "guess" },
		"validator long":         func(r *Report) { r.Findings[0].Validation.Validator = strings.Repeat("x", MaxValidatorLen+1) },
		"evidence ref":           func(r *Report) { r.Findings[0].Validation.EvidenceRefs = []string{"../etc/passwd"} },
		"capec id":               func(r *Report) { r.Findings[0].CAPECIDs = []string{"CAPEC-0"} },
		"signal type":            func(r *Report) { r.Findings[0].Vulnerability.ThreatSignals[0].Type = "rumour" },
		"signal source":          func(r *Report) { r.Findings[0].Vulnerability.ThreatSignals[0].Source = "" },
		"signal due_on":          func(r *Report) { r.Findings[0].Vulnerability.ThreatSignals[0].DueOn = "2026-02-30" },
		"relationship conf":      func(r *Report) { r.Relationships[0].Confidence = 101 },
		"relationship seen": func(r *Report) {
			r.Relationships[0].FirstSeenAt, r.Relationships[0].LastSeenAt = r.Relationships[0].LastSeenAt, r.Relationships[0].FirstSeenAt
		},
		"extension namespace": func(r *Report) { r.Extensions = Extensions{"openctem": {"a": 1}} },
		"extension upper":     func(r *Report) { r.Findings[0].Extensions = Extensions{"Com.Example": {"a": 1}} },
		"extension nil value": func(r *Report) { r.Extensions = Extensions{"io.openctem": nil} },
		"extension size": func(r *Report) {
			r.Extensions = Extensions{"io.openctem": {"big": strings.Repeat("x", MaxExtensionsBytes)}}
		},
		"extension count": func(r *Report) {
			r.Extensions = Extensions{}
			for i := 0; i <= MaxExtensionNamespaces; i++ {
				r.Extensions["com.example"+itoa(i)+".x"] = map[string]any{}
			}
		},
	}
	s := loadSchemaSet(t)
	for name, mutate := range bad {
		r := good()
		mutate(r)
		if err := r.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	assertReportValid(t, s, good())
}

// PII members carry the x-ctis-pii annotation, and only they do.
func TestSchemaPIIAnnotations(t *testing.T) {
	s := loadSchemaSet(t)
	var got []string
	var walk func(file, path string, node map[string]any)
	walk = func(file, path string, node map[string]any) {
		if node["x-ctis-pii"] == true {
			got = append(got, file+"#"+path)
		}
		for _, k := range []string{"properties", "$defs"} {
			if m, ok := node[k].(map[string]any); ok {
				for name, child := range m {
					walk(file, path+"/"+k+"/"+name, child.(map[string]any))
				}
			}
		}
		if items, ok := node["items"].(map[string]any); ok {
			walk(file, path+"/items", items)
		}
	}
	for file, doc := range s.docs {
		walk(file, "", doc)
	}
	sort.Strings(got)
	want := []string{
		"asset.json#/$defs/AssetOwner/properties/ref",
		"asset.json#/$defs/DomainTechnical/properties/whois",
		"finding.json#/$defs/CommitInfo/properties/author",
		"finding.json#/$defs/CommitInfo/properties/author_email",
		"finding.json#/$defs/FindingValidation/properties/validator",
		"finding.json#/$defs/SecretDetails/properties/scopes",
		"finding.json#/$defs/Suppression/properties/suppressed_by",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("x-ctis-pii members:\n got %v\nwant %v", got, want)
	}
}

func TestExtensionsSchema(t *testing.T) {
	s := loadSchemaSet(t)
	base := `{"version":"2.0","metadata":{"id":"` + testReportID + `","generated_at":"2026-11-03T00:00:00Z"},"extensions":%s}`
	for _, ok := range []string{`{"io.openctem":{"a":1}}`, `{"com.example.scanner":{}}`} {
		if errs := s.validateJSON([]byte(strings.Replace(base, "%s", ok, 1)), "report.json"); len(errs) > 0 {
			t.Errorf("%s rejected: %v", ok, errs)
		}
	}
	for _, bad := range []string{`{"openctem":{}}`, `{"io.openctem":1}`, `{"IO.openctem":{}}`, `{"io..x":{}}`} {
		if errs := s.validateJSON([]byte(strings.Replace(base, "%s", bad, 1)), "report.json"); len(errs) == 0 {
			t.Errorf("%s accepted", bad)
		}
	}
	for _, ns := range []string{"io.openctem", "com.example.scanner", "org.ctis.experimental"} {
		if !IsExtensionNamespace(ns) {
			t.Errorf("%s rejected", ns)
		}
	}
	// The informative namespace schema is valid JSON with the expected keys.
	raw, err := os.ReadFile("schemas/extensions/io.openctem/2.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	props, _ := doc["properties"].(map[string]any)
	for _, k := range []string{"bounty_report", "import_scope", "candidate_exposure", "web_content", "capability"} {
		if props[k] == nil {
			t.Errorf("io.openctem schema lacks %s", k)
		}
	}
}

func TestOpenVocabularies(t *testing.T) {
	r := minimalReport17()
	r.Assets = []Asset{{ID: "a", Type: AssetTypeHost, Value: "h"}}
	r.Findings = []Finding{{Type: FindingTypeVulnerability, Title: "t", Severity: SeverityHigh, AssetRef: "a", Native: &NativeIdentity{Scheme: "some_scanner"}}}
	if err := r.Validate(); err != nil {
		t.Errorf("open native scheme rejected: %v", err)
	}
	s := loadSchemaSet(t)
	assertReportValid(t, s, r)
	doc := `{"version":"2.0","metadata":{"id":"` + testReportID + `","generated_at":"2026-11-03T00:00:00Z"},"assets":[{"id":"a","type":"cloud_resource","value":"v","technical":{"cloud":{"provider":"oci"}}}]}`
	if errs := s.validateJSON([]byte(doc), "report.json"); len(errs) > 0 {
		t.Errorf("open cloud provider rejected: %v", errs)
	}
}
