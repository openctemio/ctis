package importer

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/openctemio/ctis/v2"
)

// Hostile and edge-case input for the OSV importer.

func TestOSV_Edges(t *testing.T) {
	in := "{\"results\": [\n{\"source\": {\"path\": 7}}]}"
	_, err := parseString(t, in, Options{})
	p := wantKind(t, err, ErrMalformed)
	if p.Line != 2 {
		t.Errorf("line = %d, want 2", p.Line)
	}
	// A source path is only a label: control characters are removed and
	// nothing is opened.
	in = `{"results":[{"source":{"path":"../../etc/passwd\u001b[2J"},"packages":[{"package":{"name":"a","version":"1","ecosystem":"npm"},
	"vulnerabilities":[{"id":"GHSA-xxxx-xxxx-xxxx","summary":"s","database_specific":{"severity":"CRITICAL"}}]}]}]}`
	res, err := parseString(t, in, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if v := res.Report.Assets[0].Value; strings.ContainsRune(v, 0x1b) {
		t.Errorf("asset value kept an escape: %q", v)
	}
	if res.Report.Findings[0].Severity != ctis.SeverityCritical {
		t.Errorf("severity = %s", res.Report.Findings[0].Severity)
	}
	if err := res.Report.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestSBOM_NoPeopleInGoldens(t *testing.T) {
	for _, dir := range []string{"osv"} {
		files, _ := os.ReadDir(fixtureRoot + "/" + dir)
		for _, f := range files {
			if !strings.HasSuffix(f.Name(), ".golden.json") && !strings.HasSuffix(f.Name(), ".result.json") {
				continue
			}
			b, err := os.ReadFile(fixtureRoot + "/" + dir + "/" + f.Name())
			if err != nil {
				t.Fatal(err)
			}
			for _, s := range []string{"jane@example.com", "maint@example.com", "researcher@example.com", "Jane Example", "/home/runner", "send [[[["} {
				if bytes.Contains(b, []byte(s)) {
					t.Errorf("%s/%s holds %q", dir, f.Name(), s)
				}
			}
		}
	}
}
