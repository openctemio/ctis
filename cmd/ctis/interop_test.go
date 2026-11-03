package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openctemio/ctis/v2"
)

func runCmd(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, strings.NewReader(stdin), &out, &errb)
	return code, out.String(), errb.String()
}

func TestImportExport(t *testing.T) {
	sarifLog := "../../interop/sarif/testdata/importers/semgrep.sarif"
	code, out, stderr := runCmd(t, "", "import", sarifLog)
	if code != 0 {
		t.Fatalf("import: %d %s", code, stderr)
	}
	var r ctis.Report
	if err := json.Unmarshal([]byte(out), &r); err != nil || len(r.Findings) == 0 {
		t.Fatalf("import output: %v", err)
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("import output is not valid CTIS: %v", err)
	}
	doc := filepath.Join(t.TempDir(), "r.ctis.json")
	if err := os.WriteFile(doc, []byte(out), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"sarif", "cyclonedx", "ocsf"} {
		code, got, stderr := runCmd(t, "", "export", "--format", f, doc)
		if code != 0 || !json.Valid([]byte(got)) {
			t.Fatalf("export %s: %d %s", f, code, stderr)
		}
	}
	// Through stdin, with an explicit format and the whole result.
	data, _ := os.ReadFile(sarifLog)
	if code, got, _ := runCmd(t, string(data), "import", "--format", "sarif", "--result", "--no-passthrough", "-"); code != 0 || !strings.Contains(got, `"stats"`) {
		t.Fatalf("import --result: %d", code)
	}
	for _, f := range []string{"cyclonedx", "spdx", "csaf", "openvex"} {
		if !strings.Contains(formatNames(), f) {
			t.Errorf("adapter %s not linked", f)
		}
	}
}

func TestImportExportErrors(t *testing.T) {
	cases := []struct {
		args  []string
		stdin string
		code  int
	}{
		{[]string{"import"}, "", 2},
		{[]string{"import", "missing-file"}, "", 2},
		{[]string{"import", "-"}, "not a known format", 2},
		{[]string{"import", "--format", "sarif", "-"}, `{"version":"2.1.0","runs":{}}`, 1},
		{[]string{"import", "--max-size", "4", "-"}, `{"version":"2.1.0"}`, 2},
		{[]string{"export", "-"}, "{}", 2},
		{[]string{"export", "--format", "pdf", "-"}, "{}", 2},
		{[]string{"export", "--format", "sarif", "-"}, `{"version":"1.6"}`, 1},
		{[]string{"export", "--format", "sarif", "missing-file"}, "", 2},
		{[]string{"export", "--bogus"}, "", 2},
		{[]string{"import", "--bogus"}, "", 2},
	}
	for _, c := range cases {
		if code, _, stderr := runCmd(t, c.stdin, c.args...); code != c.code {
			t.Errorf("%v: exit %d, want %d (%s)", c.args, code, c.code, stderr)
		}
	}
}
