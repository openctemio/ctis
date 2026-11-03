package conformance

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRunVectors(t *testing.T) {
	rs, err := Run("../../conformance/v1")
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) < 50 {
		t.Errorf("only %d vectors ran", len(rs))
	}
	for _, r := range Failures(rs) {
		t.Errorf("%s: %s: %s", r.Suite, r.Name, r.Err)
	}
}

func TestRunMissingAndBrokenDirs(t *testing.T) {
	if _, err := Run(filepath.Join(t.TempDir(), "none")); err == nil {
		t.Error("missing dir accepted")
	}
	// An empty directory runs nothing and reports every suite as failing,
	// instead of passing silently.
	rs, err := Run(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(Failures(rs)) != len(rs) || len(rs) == 0 {
		t.Errorf("empty dir: %+v", rs)
	}
	// Malformed vector files fail rather than pass.
	dir := t.TempDir()
	for _, f := range []string{"location-key.json", "preferred-id.json", "fingerprint.json"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("{"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if rs, _ := Run(dir); len(Failures(rs)) != len(rs) {
		t.Errorf("malformed files passed: %+v", rs)
	}
}

func TestVectorMismatchesFail(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("location-key.json", `{"cases":[{"name":"x","finding":{"network":{"port":22}},"expected":"wrong"}]}`)
	write("preferred-id.json", `{"cases":[
	 {"name":"none expected","vulnerability":{"cve_id":"CVE-2024-0001"},"expected":null},
	 {"name":"some expected","vulnerability":{},"expected":{"type":"cve","id":"CVE-2024-0001"}},
	 {"name":"wrong id","vulnerability":{"cve_id":"CVE-2024-0001"},"expected":{"type":"cve","id":"CVE-2024-0002"}}]}`)
	write("fingerprint.json", `{"cases":[{"name":"x","type":"sca","input":{"package_name":"a"},"expected":"00"}]}`)
	write("documents/manifest.json", `{"documents":[
	 {"file":"a.json","result":"valid"},{"file":"missing.json","result":"valid"},{"file":"a.json","result":"maybe"},
	 {"file":"a.json","result":"invalid"},{"file":"b.json","result":"valid"},
	 {"file":"b.json","result":"invalid","category":"version"},{"file":"b.json","result":"invalid","error":"nope"}]}`)
	write("documents/a.json", `{"version":"1.3","metadata":{"timestamp":"2026-10-02T00:00:00Z"}}`)
	write("documents/b.json", `{"version":"2.0"}`)
	rs, _ := Run(dir)
	failed := map[string]bool{}
	for _, r := range Failures(rs) {
		failed[r.Suite+"/"+r.Name] = true
	}
	for _, want := range []string{
		"location-key.json/x", "preferred-id.json/none expected", "preferred-id.json/some expected",
		"preferred-id.json/wrong id", "fingerprint.json/x", "documents/missing.json",
	} {
		if !failed[want] {
			t.Errorf("%s did not fail", want)
		}
	}
	if n := len(Failures(rs)); n < 11 {
		t.Errorf("only %d failures: %+v", n, Failures(rs))
	}
}
