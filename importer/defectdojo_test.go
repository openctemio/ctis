package importer

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/ctis"
)

func TestDefectDojo_BadRecordsAreIssuesWithLines(t *testing.T) {
	in := "{\"findings\": [\n" +
		"{\"title\": \"ok\", \"severity\": \"High\"},\n" +
		"{\"title\": \"bad cwe\", \"severity\": \"Low\", \"cwe\": {\"id\": 20}},\n" +
		"{\"title\": \"bad tags\", \"severity\": \"Low\", \"tags\": \"not-a-list\"},\n" +
		"42\n" +
		"]}"
	res, err := Parse(context.Background(), strings.NewReader(in), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Report.Findings) != 1 || res.Stats.Skipped != 3 {
		t.Fatalf("findings %d skipped %d", len(res.Report.Findings), res.Stats.Skipped)
	}
	wantLines := []int{3, 4, 5}
	if len(res.Issues) != 3 {
		t.Fatalf("issues = %+v", res.Issues)
	}
	for i, is := range res.Issues {
		if is.Line != wantLines[i] {
			t.Errorf("issue %d at line %d, want %d (%s)", i, is.Line, wantLines[i], is.Message)
		}
	}
	// The default asset holds records without endpoints.
	if res.Report.Assets[0].Type != ctis.AssetTypeUnclassified || res.Report.Assets[0].Value != "defectdojo-import" {
		t.Fatalf("asset = %+v", res.Report.Assets[0])
	}
}

func TestDefectDojo_DefaultAssetOption(t *testing.T) {
	in := `{"findings": [{"title": "t", "severity": "Low"}]}`
	res, err := Parse(context.Background(), strings.NewReader(in), Options{DefaultAsset: &ctis.Asset{Type: ctis.AssetTypeRepository, Value: "github.com/example/app"}})
	if err != nil {
		t.Fatal(err)
	}
	a := res.Report.Assets[0]
	if a.Type != ctis.AssetTypeRepository || a.ID != "repository-github.com/example/app" || res.Report.Findings[0].AssetRef != a.ID {
		t.Fatalf("asset = %+v", a)
	}
}

func TestDefectDojo_Malformed(t *testing.T) {
	cases := map[string]string{
		"no findings":     `{"name": "x"}`,
		"findings object": `{"findings": {"a": 1}}`,
		"deep":            `{"findings": [` + strings.Repeat("[", 200) + strings.Repeat("]", 200) + `]}`,
		"invalid utf-8":   "{\"findings\": [{\"title\": \"\xff\"}]}",
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse(context.Background(), strings.NewReader(in), Options{Format: FormatDefectDojo})
			if err == nil {
				t.Fatal("parsed")
			}
			var pe *ParseError
			if !errors.As(err, &pe) {
				t.Fatalf("not a ParseError: %v", err)
			}
		})
	}
}

func TestDefectDojo_EndpointUserinfoNeverKept(t *testing.T) {
	in := `{"findings": [{"title": "t", "severity": "Low", "endpoints": ["https://admin:s3cret@app.example.com/x?y=1", {"host": "b.example.com", "userinfo": "u:p", "path": "/p", "protocol": "https"}]}]}`
	res, err := Parse(context.Background(), strings.NewReader(in), Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range res.Report.Findings {
		for _, v := range f.SourceExtra {
			if strings.Contains(v, "s3cret") || strings.Contains(v, "u:p") || strings.Contains(v, "admin") {
				t.Fatalf("credential kept: %q", v)
			}
		}
	}
	if len(res.Report.Findings) != 2 {
		t.Fatalf("findings = %d", len(res.Report.Findings))
	}
}
