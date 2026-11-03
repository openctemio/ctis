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

const validDoc = `{"version":"2.0","metadata":{"id":"019a2b3c-4d5e-7000-8000-000000000001","generated_at":"2026-10-02T00:00:00Z"}}`

func exec(t *testing.T, stdin string, args ...string) (code int, out, errOut string) {
	t.Helper()
	var o, e bytes.Buffer
	code = run(args, strings.NewReader(stdin), &o, &e)
	return code, o.String(), e.String()
}

func write(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestValidateExitCodes(t *testing.T) {
	good := write(t, "good.json", validDoc)
	bad := write(t, "bad.json", `{"version":"2.0","bogus":1}`)
	semantic := write(t, "semantic.json", `{"version":"2.0","metadata":{"id":"019a2b3c-4d5e-7000-8000-000000000001","generated_at":"2026-10-02T00:00:00Z"},"assets":[{"id":"a","type":"domain_name","value":"x.example"},{"id":"a","type":"domain_name","value":"y.example"}]}`)

	if code, out, _ := exec(t, "", "validate", good); code != 0 || !strings.Contains(out, "good.json: ok") {
		t.Errorf("valid: %d %q", code, out)
	}
	if code, out, _ := exec(t, "", "validate", bad); code != 1 || !strings.Contains(out, "bad.json: decode:") {
		t.Errorf("unknown field: %d %q", code, out)
	}
	if code, out, _ := exec(t, "", "validate", semantic); code != 1 || !strings.Contains(out, "duplicate id") {
		t.Errorf("semantic: %d %q", code, out)
	}
	if code, _, _ := exec(t, "", "validate", good, bad); code != 1 {
		t.Errorf("one bad file must give 1, got %d", code)
	}
	if code, out, _ := exec(t, validDoc, "validate", "-"); code != 0 || !strings.Contains(out, "-: ok") {
		t.Errorf("stdin: %d %q", code, out)
	}
	if code, _, errOut := exec(t, "", "validate", filepath.Join(t.TempDir(), "missing.json")); code != 2 || errOut == "" {
		t.Errorf("missing file: %d %q", code, errOut)
	}
	// An I/O error outranks an invalid document.
	if code, _, _ := exec(t, "", "validate", bad, filepath.Join(t.TempDir(), "missing.json")); code != 2 {
		t.Errorf("io error with invalid: %d", code)
	}
	if code, _, _ := exec(t, ""); code != 2 {
		t.Errorf("no command: %d", code)
	}
	if code, _, _ := exec(t, "", "validate"); code != 2 {
		t.Errorf("no files: %d", code)
	}
	if code, _, _ := exec(t, "", "validate", "--nope", good); code != 2 {
		t.Errorf("bad flag: %d", code)
	}
	if code, _, _ := exec(t, "", "bogus"); code != 2 {
		t.Errorf("unknown command: %d", code)
	}
}

func TestValidateOversize(t *testing.T) {
	big := write(t, "big.json", validDoc+strings.Repeat(" ", 200))
	code, _, errOut := exec(t, "", "validate", "--max-size", "100", big)
	if code != 2 || !strings.Contains(errOut, "larger than 100 bytes") {
		t.Errorf("oversize: %d %q", code, errOut)
	}
	// Exactly at the limit is accepted; stdin is bounded too.
	if code, _, _ := exec(t, validDoc, "validate", "--max-size", "112", "-"); code != 0 {
		t.Errorf("at limit (%d bytes): %d", len(validDoc), code)
	}
	if code, _, _ := exec(t, validDoc, "validate", "--max-size", "10", "-"); code != 2 {
		t.Errorf("stdin oversize: %d", code)
	}
	if code, _, _ := exec(t, "", "validate", "--max-size", "0", big); code != 2 {
		t.Errorf("max-size 0: %d", code)
	}
}

func TestValidateJSON(t *testing.T) {
	good := write(t, "good.json", validDoc)
	bad := write(t, "bad.json", `{"version":"1.6","metadata":{"timestamp":"2026-10-02T00:00:00Z"}}`)
	code, out, _ := exec(t, "", "validate", "--json", good, bad)
	if code != 1 {
		t.Fatalf("code %d", code)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 2 {
		t.Fatalf("lines: %q", out)
	}
	var a, b fileResult
	if json.Unmarshal([]byte(lines[0]), &a) != nil || json.Unmarshal([]byte(lines[1]), &b) != nil {
		t.Fatalf("not JSON: %q", out)
	}
	if !a.Valid || b.Valid || b.Category != "version" || b.Problem == "" {
		t.Errorf("results: %+v %+v", a, b)
	}
}

func TestVersionAndCanon(t *testing.T) {
	if code, out, _ := exec(t, "", "version"); code != 0 || !strings.HasPrefix(out, "ctis dev (CTIS 2.") {
		t.Errorf("version: %d %q", code, out)
	}
	if code, out, _ := exec(t, "", "canon", "web_origin", "HTTPS://Example.com/Admin/"); code != 0 || out != "https://example.com\t"+ctis.AssetKey(ctis.AssetTypeWebOrigin, "https://example.com")+"\n" {
		t.Errorf("canon: %d %q", code, out)
	}
	if code, _, _ := exec(t, "", "canon", "web_origin", "ftp://x"); code != 1 {
		t.Errorf("canon without a canonical form: %d", code)
	}
	if code, _, _ := exec(t, "", "canon", "subdomain", "x.example"); code != 1 {
		t.Errorf("canon of a removed type: %d", code)
	}
	if code, _, _ := exec(t, "", "canon", "domain"); code != 2 {
		t.Errorf("canon usage: %d", code)
	}
}

func TestConformanceCommand(t *testing.T) {
	code, out, _ := exec(t, "", "conformance", "../../conformance/v2")
	if code != 0 || !strings.Contains(out, "0 failed") {
		t.Errorf("conformance: %d %q", code, out)
	}
	if code, _, _ := exec(t, "", "conformance", filepath.Join(t.TempDir(), "none")); code != 2 {
		t.Errorf("missing dir: %d", code)
	}
	// A directory with a wrong expectation fails with 1.
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "canonical"), 0o700); err != nil {
		t.Fatal(err)
	}
	vec := `{"function":"CanonicalDomain","vectors":[{"input":"A.com","output":"wrong"}]}`
	if err := os.WriteFile(filepath.Join(dir, "canonical", "d.json"), []byte(vec), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := exec(t, "", "conformance", dir); code != 1 || !strings.Contains(out, "FAIL canonical/d.json") {
		t.Errorf("failing vectors: %d %q", code, out)
	}
}
