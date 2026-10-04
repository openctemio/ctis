package ctis

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Fuzz targets. `go test` runs only the seeds; fuzz with e.g.
//
//	go test -run '^$' -fuzz FuzzValidate -fuzztime 60s .
//
// None of these may panic on any input.

func addTestdataSeeds(f *testing.F, glob string) {
	files, _ := filepath.Glob(filepath.Join("testdata", glob))
	for _, name := range files {
		if b, err := os.ReadFile(name); err == nil {
			f.Add(b)
		}
	}
}

func FuzzValidate(f *testing.F) {
	addTestdataSeeds(f, "sarif/*.golden.json")
	if examples, _ := filepath.Glob("examples/*.json"); len(examples) > 0 {
		for _, name := range examples {
			if b, err := os.ReadFile(name); err == nil {
				f.Add(b)
			}
		}
	}
	f.Add([]byte(`{"version":"1.3","metadata":{"timestamp":"2026-10-02T00:00:00Z"},"findings":[{"type":"vulnerability","title":"t","severity":"high","vulnerability":{"cvss_score":1e308,"epss_percentile":-0}}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var r Report
		if err := json.Unmarshal(data, &r); err != nil {
			return
		}
		_ = r.Validate()
		for _, fd := range r.Findings {
			_ = fd.Severity.Score()
			_ = NormalizeAssetName(fd.AssetType, fd.AssetValue)
			if fd.DataFlow != nil {
				_ = fd.DataFlow.BuildSummary()
				_ = fd.DataFlow.IsCrossFunction()
			}
		}
		for _, a := range r.Assets {
			_ = NormalizeAssetName(a.Type, a.Value)
		}
		if _, err := json.Marshal(&r); err != nil {
			t.Fatalf("a decoded report must marshal again: %v", err)
		}
	})
}

func FuzzFromSARIF(f *testing.F) {
	addTestdataSeeds(f, "sarif/*.sarif")
	f.Add([]byte(`{"runs":[{"tool":{"driver":{"rules":[{"id":"r"}]}},"results":[{"ruleIndex":-1,"rule":{"index":99},"message":{"text":""}}]}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := FromSARIF(data, nil)
		if err != nil {
			return
		}
		if r.Version != SchemaVersion {
			t.Fatalf("version %q", r.Version)
		}
		_ = r.Validate()
		// A secret finding never carries a snippet other than a redaction.
		for _, fd := range r.Findings {
			if fd.Type != FindingTypeSecret || fd.Location == nil || fd.Location.Snippet == "" {
				continue
			}
			s := fd.Location.Snippet
			if !isRedacted(s) && !strings.HasSuffix(s, "********") {
				t.Fatalf("secret finding snippet not redacted: %q", s)
			}
		}
	})
}

func FuzzConvertRecon(f *testing.F) {
	for _, in := range reconFixtures() {
		b, _ := json.Marshal(in)
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var in ReconToCTISInput
		if err := json.Unmarshal(data, &in); err != nil {
			return
		}
		r, err := ConvertReconToCTIS(&in, nil)
		if err != nil {
			t.Fatal(err)
		}
		_ = MergeReconReports([]*Report{r, r})
	})
}

func FuzzParseVersion(f *testing.F) {
	for _, s := range []string{"1.3", "1.0", "", "1", "01.2", "1.2.3", "9999.9999", "-1.0"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		major, minor, ok := ParseVersion(s)
		if ok && (major < 0 || minor < 0) {
			t.Fatalf("negative version parts from %q", s)
		}
		if IsCompatibleVersion(s) && !ok {
			t.Fatalf("compatible but unparsable: %q", s)
		}
	})
}
