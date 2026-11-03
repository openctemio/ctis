package ctis

import (
	"strings"
	"testing"
	"time"
)

// testReportID is a fixed UUIDv7 for test documents.
const testReportID = "0192f0a0-0000-7000-8000-000000000001"

func TestNewReportIDIsUUIDv7AndMonotonic(t *testing.T) {
	prev := ""
	for i := 0; i < 5000; i++ {
		id := NewReportID()
		if !IsReportID(id) {
			t.Fatalf("NewReportID() = %q, not a lowercase UUIDv7", id)
		}
		if id <= prev {
			t.Fatalf("ids not increasing: %q then %q", prev, id)
		}
		prev = id
	}
	ms := time.Now().UnixMilli()
	id := NewReportID()
	hexms := strings.ReplaceAll(id[:13], "-", "")
	var got int64
	for _, c := range hexms {
		got = got<<4 | int64(strings.IndexRune("0123456789abcdef", c))
	}
	if got < ms-1000 || got > ms+1000 {
		t.Errorf("timestamp of %q is %d, now %d", id, got, ms)
	}
}

func TestDocumentRefs(t *testing.T) {
	for _, ok := range []string{"asset-1", "repo", "sbom-pkg:maven/com.example/billing@2.4.0", "site-https://shop.example.com", "a", "0123456789abcdef0123456789abcdef"} {
		if !IsDocumentRef(ok) {
			t.Errorf("IsDocumentRef(%q) = false", ok)
		}
	}
	for _, bad := range []string{
		"", " asset", "-x", "a b", "6f1c2b0e-4a7d-4e3b-9c1a-2b3c4d5e6f70", "6F1C2B0E-4A7D-4E3B-9C1A-2B3C4D5E6F70",
		"{6f1c2b0e-4a7d-4e3b-9c1a-2b3c4d5e6f70}", "urn:uuid:6f1c2b0e-4a7d-4e3b-9c1a-2b3c4d5e6f70", strings.Repeat("a", 256),
	} {
		if IsDocumentRef(bad) {
			t.Errorf("IsDocumentRef(%q) = true", bad)
		}
	}
	for _, bad := range []string{"", "6f1c2b0e-4a7d-4e3b-9c1a-2b3c4d5e6f70", "0192F0A0-0000-7000-8000-000000000001", "0192f0a0-0000-7000-c000-000000000001"} {
		if IsReportID(bad) {
			t.Errorf("IsReportID(%q) = true", bad)
		}
	}
}

func TestValidateRejectsReceiverKeys(t *testing.T) {
	uuid := "6f1c2b0e-4a7d-4e3b-9c1a-2b3c4d5e6f70"
	r := NewReport()
	r.Assets = []Asset{{ID: uuid, Type: AssetTypeHost, Value: "h1"}}
	r.Findings = []Finding{{ID: uuid, Type: FindingTypeExposure, Title: "t", Severity: SeverityLow, AssetRef: uuid}}
	err := r.Validate()
	if err == nil || !strings.Contains(err.Error(), "UUID-shaped") {
		t.Fatalf("Validate = %v, want a UUID-shaped refusal", err)
	}
	r = NewReport()
	r.Metadata.ID = "import-test"
	if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "UUIDv7") {
		t.Fatalf("Validate = %v, want metadata.id refusal", err)
	}
	r = NewReport()
	r.Assets = []Asset{{ID: "h", Type: AssetTypeHost, Value: "h1", SourceRefs: []SourceRef{{System: "Nessus", ID: "1"}, {System: "nessus", ID: ""}}}}
	if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "source_refs[0].system") || !strings.Contains(err.Error(), "source_refs[1].id is required") {
		t.Fatalf("Validate = %v, want source_refs refusals", err)
	}
}

func f64(v float64) *float64 { return &v }
