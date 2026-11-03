package ctis

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func contractReport() *Report {
	return &Report{
		Version:  SchemaVersion,
		Metadata: ReportMetadata{ID: testReportID, GeneratedAt: time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC)},
		Assets: []Asset{
			{ID: "a", Type: AssetTypeDomainName, Value: "a.example.com"},
			{ID: "b", Type: AssetTypeIPAddress, Value: "192.0.2.1"},
			{ID: "c", Type: AssetTypeWebOrigin, Value: "https://a.example.com",
				Technologies: []Technology{{Name: "nginx", Version: "1.25", Categories: []string{"web-server"}, Confidence: 90}}},
		},
		Relationships: []Relationship{{Type: RelResolvesTo, FromRef: "a", ToRef: "b"}, {Type: RelExposes, FromRef: "b", ToRef: "c"}},
		Findings: []Finding{{Type: FindingTypeVulnerability, Title: "t", Severity: SeverityHigh, AssetRef: "c",
			AttackTechniqueIDs: []string{"T1190", "T1595.002"}}},
	}
}

func TestContractMembersRoundTrip(t *testing.T) {
	r := contractReport()
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	back, err := decodeStrict(raw)
	if err != nil {
		t.Fatal(err)
	}
	raw2, _ := json.Marshal(back)
	if string(raw) != string(raw2) {
		t.Fatalf("round trip changed the report:\n%s\n%s", raw, raw2)
	}
	if errs := loadSchemaSet(t).validateJSON(raw, "report.json"); len(errs) > 0 {
		t.Fatalf("schema rejects a valid report: %v", errs)
	}
}

func TestOtherMajorRefused(t *testing.T) {
	raw := []byte(`{"version":"1.6","metadata":{"timestamp":"2026-10-02T00:00:00Z"},"assets":[{"id":"a","type":"domain","value":"example.com"}]}`)
	if _, _, err := Decode(strings.NewReader(string(raw))); err == nil || !strings.Contains(err.Error(), "upgrade") {
		t.Fatalf("Decode(1.6) = %v, want an upgrade error", err)
	}
}

func TestContractMembersRefused(t *testing.T) {
	long := strings.Repeat("x", 300)
	cases := map[string]struct {
		mut  func(r *Report)
		want string
	}{
		"attack tactic":            {func(r *Report) { r.Findings[0].AttackTechniqueIDs = []string{"TA0043"} }, "not an ATT&CK technique id"},
		"attack injection":         {func(r *Report) { r.Findings[0].AttackTechniqueIDs = []string{"T1190<script>"} }, "not an ATT&CK technique id"},
		"attack too many":          {func(r *Report) { r.Findings[0].AttackTechniqueIDs = make([]string, 21) }, "at most 20"},
		"tech no name":             {func(r *Report) { r.Assets[2].Technologies[0].Name = " " }, "name is required"},
		"tech long name":           {func(r *Report) { r.Assets[2].Technologies[0].Name = long }, "name longer"},
		"tech long version":        {func(r *Report) { r.Assets[2].Technologies[0].Version = long }, "version longer"},
		"tech long cpe":            {func(r *Report) { r.Assets[2].Technologies[0].CPE = long }, "cpe longer"},
		"tech confidence":          {func(r *Report) { r.Assets[2].Technologies[0].Confidence = 101 }, "outside 0-100"},
		"tech categories":          {func(r *Report) { r.Assets[2].Technologies[0].Categories = make([]string, 11) }, "categories has 11"},
		"tech category long":       {func(r *Report) { r.Assets[2].Technologies[0].Categories = []string{long} }, "categories[0] longer"},
		"tech too many":            {func(r *Report) { r.Assets[2].Technologies = make([]Technology, 101) }, "technologies has 101"},
		"rel type":                 {func(r *Report) { r.Relationships[0].Type = "owns" }, "invalid type"},
		"rel dangling":             {func(r *Report) { r.Relationships[0].ToRef = "zz" }, "names no asset"},
		"rel empty":                {func(r *Report) { r.Relationships[0].FromRef = "" }, "from_ref is required"},
		"rel long ref":             {func(r *Report) { r.Relationships[0].FromRef = long }, "longer than 255"},
		"rel uuid ref":             {func(r *Report) { r.Relationships[0].FromRef = "6f1c2b0e-4a7d-4e3b-9c1a-2b3c4d5e6f70" }, "UUID-shaped"},
		"rel self":                 {func(r *Report) { r.Relationships[0].ToRef = "a" }, "relate to itself"},
		"rel too many":             {func(r *Report) { r.Relationships = make([]Relationship, MaxRelationships+1) }, "at most 10000"},
		"rel value quoted bounded": {func(r *Report) { r.Relationships[0].ToRef = strings.Repeat("é", 100) }, "..."},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			r := contractReport()
			tc.mut(r)
			err := r.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
			if len(err.Error()) > 20000 {
				t.Fatalf("error not bounded: %d bytes", len(err.Error()))
			}
		})
	}
}

func TestRefHelpers(t *testing.T) {
	if !IsAttackTechniqueID("T1595.001") || IsAttackTechniqueID("T1595.1") {
		t.Fatal("IsAttackTechniqueID")
	}
	if RelationshipType("x").IsValid() || !RelHostedBy.IsValid() {
		t.Fatal("RelationshipType")
	}
	if got := truncateForError("short"); got != "short" {
		t.Fatal(got)
	}
}

func TestContractExampleIsValid(t *testing.T) {
	raw, err := os.ReadFile("examples/discovery-graph.json")
	if err != nil {
		t.Fatal(err)
	}
	r, err := decodeStrict(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
}
