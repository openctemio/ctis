package sarif

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openctemio/ctis/v2/importer"
	"github.com/openctemio/ctis/v2/internal/goldencheck"
	"github.com/openctemio/ctis/v2/internal/interoptest"
)

// The fake credentials are assembled at run time so that no secret scanner
// flags this repository.
var leakKey = "AKIA" + "Q3EGRZ7X2MNVBP4L" // 20 characters

func parseString(t *testing.T, in string, opts importer.Options) (*importer.Result, error) {
	t.Helper()
	return interoptest.ParseString(t, in, opts)
}

func requireNoSecret(t *testing.T, res *importer.Result, secrets ...string) {
	t.Helper()
	out, err := json.Marshal(res.Report)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range secrets {
		if strings.Contains(string(out), s) {
			t.Fatalf("raw secret %q is in the report:\n%s", s, out)
		}
	}
	if len(res.Report.Findings) == 0 {
		t.Fatal("no findings")
	}
}

// The repository a receiver passes wins over the one a file names: a CI
// upload cannot file its findings on another repository.
func TestCodeFormats_RepositoryOptionWins(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(importerFixtures, "codeql-provenance.sarif.json"))
	if err != nil {
		t.Fatal(err)
	}
	res, err := importer.Parse(context.Background(), bytes.NewReader(data), importer.Options{Repository: "github.com/example/verified", Branch: "main", CommitSHA: "abc"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Report.Assets) != 1 || res.Report.Assets[0].Value != "github.com/example/verified" {
		t.Fatalf("assets = %+v", res.Report.Assets)
	}
	for _, f := range res.Report.Findings {
		if f.AssetRef != res.Report.Assets[0].ID {
			t.Fatalf("finding on %q", f.AssetRef)
		}
	}
	if res.Report.Metadata.Branch == nil || res.Report.Metadata.Branch.Name != "main" {
		t.Fatalf("branch = %+v", res.Report.Metadata.Branch)
	}
}

// No raw secret, credential in a URL or extracted target data reaches any
// golden output, but typed evidence: an evidence item may hold the exchange
// as captured, with every credential inside a span it marks.
func TestCodeFormats_NoSecretsInOutput(t *testing.T) {
	goldencheck.NoSecretsInOutput(t, importerFixtures)
}

// Evidence items carry the HTTP exchange as captured: every credential in
// them is inside a marked span, and none is anywhere else in the report.
func TestEvidenceSecretsMarked(t *testing.T) {
	cases := map[string][]string{
		"web.sarif.golden.json":        {"EXAMPLEKEY0123456789", "EXAMPLEBEARER0123456789", "EXAMPLEPASS0123", "EXAMPLESESSION0123"},
		"all-fields.sarif.golden.json": nil,
	}
	for file, secrets := range cases {
		goldencheck.EvidenceSecretsMarked(t, filepath.Join(importerFixtures, file), secrets)
	}
}

func TestCodeFormats_Hostile(t *testing.T) {
	deep := strings.Repeat("[", 200) + strings.Repeat("]", 200)
	cases := map[string]struct {
		format importer.Format
		in     string
		kind   error
		line   int
	}{
		"sarif deep":        {importer.FormatSARIF, `{"version":"2.1.0","runs":` + deep + `}`, importer.ErrTooLarge, 0},
		"sarif old version": {importer.FormatSARIF, `{"version":"2.0.0","runs":[]}`, importer.ErrUnknownFormat, 0},
		"sarif bad utf-8":   {importer.FormatSARIF, "{\"version\":\"2.1.0\",\n\"runs\":[{\"x\":\"\xff\"}]}", importer.ErrMalformed, 2},
		"sarif wrong type":  {importer.FormatSARIF, "{\"version\":\"2.1.0\",\n\"runs\":{\"a\":1}}", importer.ErrMalformed, 2},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := importer.Parse(context.Background(), strings.NewReader(c.in), importer.Options{Format: c.format, Limits: importer.Limits{MaxTextBytes: 1024}})
			if !errors.Is(err, c.kind) {
				t.Fatalf("want %v, got %v", c.kind, err)
			}
			var pe *importer.ParseError
			if !errors.As(err, &pe) {
				t.Fatalf("not a ParseError: %T", err)
			}
			if c.line > 0 && pe.Line != c.line {
				t.Errorf("line = %d, want %d", pe.Line, c.line)
			}
		})
	}
}

func TestSecretMaskedEverywhere_SARIF(t *testing.T) {
	for _, driver := range []string{"betterleaks", "gitleaks", "trufflehog"} {
		t.Run(driver, func(t *testing.T) {
			// The snippet is the whole code line; the message and the rule
			// description repeat the bare secret; a property holds it too.
			in := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"` + driver + `","rules":[{"id":"aws-access-token","shortDescription":{"text":"AWS key ` + leakKey + `"}}]}},
			  "results":[{"ruleId":"aws-access-token","message":{"text":"aws-access-token found ` + leakKey + ` in config.py"},
			    "properties":{"match":"` + leakKey + `","tags":["` + leakKey + `"]},
			    "locations":[{"physicalLocation":{"artifactLocation":{"uri":"config.py"},"region":{"startLine":3,"snippet":{"text":"aws_key = \"` + leakKey + `\""}}}}]}]}]}`
			res, err := parseString(t, in, importer.Options{Format: importer.FormatSARIF, Repository: "github.com/example/shop"})
			if err != nil {
				t.Fatal(err)
			}
			requireNoSecret(t, res, leakKey)
			if got := res.Report.Findings[0].Title; !strings.Contains(got, "AKIA********") {
				t.Errorf("title = %q, want the masked secret", got)
			}
		})
	}
}

// A secret shorter than six characters was not masked in the title.
func TestSecretMaskedEverywhere_SARIFShortSecret(t *testing.T) {
	short := "pw" + "12x"
	in := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"gitleaks","rules":[{"id":"generic"}]}},
	  "results":[{"ruleId":"generic","message":{"text":"password ` + short + ` committed"},
	    "locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.env"},"region":{"startLine":1,"snippet":{"text":"` + short + `"}}}}]}]}]}`
	res, err := parseString(t, in, importer.Options{Format: importer.FormatSARIF, Repository: "github.com/example/shop"})
	if err != nil {
		t.Fatal(err)
	}
	requireNoSecret(t, res, short)
}
