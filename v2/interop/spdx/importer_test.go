package spdx

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/openctemio/ctis/v2/importer"
	"github.com/openctemio/ctis/v2/internal/goldencheck"
	"github.com/openctemio/ctis/v2/internal/interoptest"
)

type Options = importer.Options

func parseString(t *testing.T, in string, opts Options) (*importer.Result, error) {
	t.Helper()
	return interoptest.ParseString(t, in, opts)
}

func wantKind(t *testing.T, err, kind error) (p struct{ Line, Column int }) {
	t.Helper()
	p.Line, p.Column = interoptest.WantKind(t, err, kind)
	return p
}

func TestSPDX_Edges(t *testing.T) {
	_, err := parseString(t, `{"spdxVersion":"SPDX-3.0"}`, Options{Format: importer.FormatSPDX})
	wantKind(t, err, importer.ErrMalformed)

	in := `{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","name":"doc",
	"packages":[{"SPDXID":"a","name":"a","supplier":"Person: Jane (jane@example.com)","originator":"Organization: Org (org@example.com)"}],
	"relationships":[{"spdxElementId":"SPDXRef-DOCUMENT","relationshipType":"DESCRIBES","relatedSpdxElement":"missing"},{"spdxElementId":"a","relationshipType":"DEPENDS_ON","relatedSpdxElement":"a"}]}`
	res, err := parseString(t, in, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Report.Assets) != 1 || res.Report.Assets[0].Value != "doc" {
		t.Fatalf("assets = %+v", res.Report.Assets)
	}
	out, _ := json.Marshal(res)
	if bytes.Contains(out, []byte("@example.com")) || bytes.Contains(out, []byte("Jane")) {
		t.Errorf("a person or e-mail address reached the result: %s", out)
	}
	if len(res.Report.Dependencies[0].DependsOn) != 0 {
		t.Error("self dependency kept")
	}

	// DESCRIBED_BY names the subject too.
	in = `{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","packages":[{"SPDXID":"s","name":"s"},{"SPDXID":"a","name":"a"}],
	"relationships":[{"spdxElementId":"s","relationshipType":"DESCRIBED_BY","relatedSpdxElement":"SPDXRef-DOCUMENT"}]}`
	res, err = parseString(t, in, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Report.Assets[0].Value != "s" || len(res.Report.Dependencies) != 1 {
		t.Fatalf("assets=%+v deps=%+v", res.Report.Assets, res.Report.Dependencies)
	}
}

func TestSBOM_NoPeopleInGoldens(t *testing.T) {
	goldencheck.NoPeopleInGoldens(t, importerFixtures)
}
