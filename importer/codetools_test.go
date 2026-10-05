package importer

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDetect_CodeFormats(t *testing.T) {
	cases := []struct {
		in   string
		want Format
	}{
		{`{"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": []}`, FormatSARIF},
		{`{"version": "2.1.0", "runs": [{"tool": {}}]}`, FormatSARIF},
		{`{"SchemaVersion": 2, "ArtifactName": "/src", "Results": []}`, FormatTrivy},
		{`{"template-id": "x", "info": {"name": "n"}, "host": "a.example.com"}` + "\n" + `{"template-id": "y"}`, FormatNuclei},
		{`[{"template-id": "x", "info": {"name": "n"}}]`, FormatNuclei},
		{`{"jsonVersion": 4, "serverName": "web", "scannedCves": {}}`, FormatVuls},
		{`[{"RuleID": "aws-access-key", "File": "a.env", "Secret": "x"}]`, FormatBetterleaks},
		{`{"version": "1.149.0", "results": [{"check_id": "r", "path": "a.py"}]}`, FormatSemgrep},
		{`{"results": [], "errors": [], "paths": {"scanned": []}}`, FormatSemgrep},
		// osv-scanner also has top-level results.
		{`{"results": [{"source": {"path": "go.mod"}, "packages": []}]}`, FormatOSV},
		{`{"results": []}`, FormatOSV},
		// Not SARIF: a runs member without a SARIF version or schema.
		{`{"runs": [], "version": "1.0"}`, ""},
	}
	for _, c := range cases {
		got, ok := Detect([]byte(c.in))
		if got != c.want || ok != (c.want != "") {
			t.Errorf("Detect(%.70q) = %q, %v; want %q", c.in, got, ok, c.want)
		}
	}
}

// The repository a receiver passes wins over the one a file names: a CI
// upload cannot file its findings on another repository.
func TestCodeFormats_RepositoryOptionWins(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(fixtureRoot, "sarif", "codeql-provenance.sarif.json"))
	if err != nil {
		t.Fatal(err)
	}
	res, err := Parse(context.Background(), bytes.NewReader(data), Options{Repository: "github.com/example/verified", Branch: "main", CommitSHA: "abc"})
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
	// trivy: the image the file names loses to the repository too.
	data, _ = os.ReadFile(filepath.Join(fixtureRoot, "trivy", "image.json"))
	res, err = Parse(context.Background(), bytes.NewReader(data), Options{Repository: "github.com/example/verified"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Report.Assets[0].Value != "github.com/example/verified" {
		t.Fatalf("trivy asset = %+v", res.Report.Assets[0])
	}
}

// No raw secret, credential in a URL, cookie or extracted target data
// reaches any golden output of the code formats.
func TestCodeFormats_NoSecretsInOutput(t *testing.T) {
	secrets := []string{"AKIAEXAMPLEEXAMPLE00", "ghp_0000EXAMPLE", "not-a-token", "user:secret", "session=abc", "root:x:0", "admin:hunter2"}
	for _, dir := range []string{"betterleaks", "trivy", "sarif", "nuclei", "semgrep"} {
		files, _ := filepath.Glob(filepath.Join(fixtureRoot, dir, "*.golden.json"))
		res, _ := filepath.Glob(filepath.Join(fixtureRoot, dir, "*.result.json"))
		for _, f := range append(files, res...) {
			b, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			for _, s := range secrets {
				if bytes.Contains(b, []byte(s)) {
					t.Errorf("%s holds %q", f, s)
				}
			}
		}
	}
}

func TestCodeFormats_Hostile(t *testing.T) {
	deep := strings.Repeat("[", 200) + strings.Repeat("]", 200)
	cases := map[string]struct {
		format Format
		in     string
		kind   error
		line   int
	}{
		"sarif deep":          {FormatSARIF, `{"version":"2.1.0","runs":` + deep + `}`, ErrTooLarge, 0},
		"sarif old version":   {FormatSARIF, `{"version":"2.0.0","runs":[]}`, ErrUnknownFormat, 0},
		"sarif bad utf-8":     {FormatSARIF, "{\"version\":\"2.1.0\",\n\"runs\":[{\"x\":\"\xff\"}]}", ErrMalformed, 2},
		"sarif wrong type":    {FormatSARIF, "{\"version\":\"2.1.0\",\n\"runs\":{\"a\":1}}", ErrMalformed, 2},
		"trivy deep":          {FormatTrivy, `{"SchemaVersion":2,"Results":` + deep + `}`, ErrTooLarge, 0},
		"trivy wrong type":    {FormatTrivy, "{\"SchemaVersion\":2,\n\"Results\":\"x\"}", ErrMalformed, 2},
		"semgrep no results":  {FormatSemgrep, `{"errors":[]}`, ErrMalformed, 0},
		"semgrep bad utf-8":   {FormatSemgrep, "{\"results\":[\n{\"check_id\":\"\xff\"}]}", ErrMalformed, 2},
		"vuls deep":           {FormatVuls, `{"jsonVersion":4,"x":` + deep + `}`, ErrTooLarge, 0},
		"vuls cves wrong":     {FormatVuls, `{"jsonVersion":4,"serverName":"a","scannedCves":"x"}`, ErrMalformed, 0},
		"betterleaks object":  {FormatBetterleaks, `{"RuleID":"a"}`, ErrMalformed, 0},
		"betterleaks deep":    {FormatBetterleaks, deep, ErrTooLarge, 0},
		"nuclei empty":        {FormatNuclei, "\n\n", ErrMalformed, 0},
		"nuclei array deep":   {FormatNuclei, `[` + deep + `]`, ErrTooLarge, 0},
		"nuclei array utf-8":  {FormatNuclei, "[\n{\"template-id\":\"\xff\"}]", ErrMalformed, 2},
		"huge string (limit)": {FormatSemgrep, `{"results":[{"check_id":"` + strings.Repeat("a", 2048) + `"}]}`, ErrTooLarge, 0},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse(context.Background(), strings.NewReader(c.in), Options{Format: c.format, Limits: Limits{MaxTextBytes: 1024}})
			if !errors.Is(err, c.kind) {
				t.Fatalf("want %v, got %v", c.kind, err)
			}
			var pe *ParseError
			if !errors.As(err, &pe) {
				t.Fatalf("not a ParseError: %T", err)
			}
			if c.line > 0 && pe.Line != c.line {
				t.Errorf("line = %d, want %d", pe.Line, c.line)
			}
		})
	}
}

// A JSON-lines file: a broken, giant or wrong-typed line is skipped with an
// issue at its line; the other lines are imported; too many lines stop the
// import.
func TestNuclei_LinesAreIsolated(t *testing.T) {
	good := `{"template-id":"t","info":{"name":"n","severity":"low"},"host":"a.example.com"}`
	in := good + "\n" +
		`{"template-id":` + "\n" +
		`{"template-id":"t2","info":{"name":"` + strings.Repeat("x", 4096) + `"},"host":"b.example.com"}` + "\n" +
		`{"template-id":"t3","info":"not an object","host":"c.example.com"}` + "\n" +
		`{"template-id":"t4","info":{"name":"n"}}` + "\n" +
		`{"template-id":"t5","info":{"name":"n"},"host":"` + strings.Repeat("[", 100) + `"}` + "\n" +
		good + "\n"
	res, err := Parse(context.Background(), strings.NewReader(in), Options{Format: FormatNuclei, Limits: Limits{MaxTextBytes: 1024}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Stats.Findings != 2 || res.Stats.Skipped != 5 {
		t.Fatalf("findings %d skipped %d issues %+v", res.Stats.Findings, res.Stats.Skipped, res.Issues)
	}
	wantLines := []int{2, 3, 4, 5, 6}
	for i, is := range res.Issues {
		if i < len(wantLines) && is.Line != wantLines[i] {
			t.Errorf("issue %d at line %d, want %d: %s", i, is.Line, wantLines[i], is.Message)
		}
	}
	var many strings.Builder
	for i := 0; i < 20; i++ {
		many.WriteString(good + "\n")
	}
	_, err = Parse(context.Background(), strings.NewReader(many.String()), Options{Format: FormatNuclei, Limits: Limits{MaxFindings: 10}})
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("too many lines: %v", err)
	}
}

func TestLeaks_Helpers(t *testing.T) {
	if fingerprintMask("short") != "****" || fingerprintMask("fake_tok_0123456789abcdefghijklmn") != "fake****klmn" {
		t.Fatalf("fingerprintMask = %q", fingerprintMask("fake_tok_0123456789abcdefghijklmn"))
	}
	if got := maskIn("key=SECRETSECRETSECRET1 end", "SECRETSECRETSECRET1"); strings.Contains(got, "SECRETSECRETSECRET1") {
		t.Fatalf("maskIn = %q", got)
	}
	// A source fingerprint that holds the secret is not used.
	f, ok := leakFinding(&leakRecord{RuleID: "generic-api-key", File: "a", Secret: "abcdefghijklmnopqrstuvwxyz", Fingerprint: "x:abcdefghijklmnopqrstuvwxyz"}, "betterleaks")
	if !ok || strings.Contains(f.Fingerprint, "abcdefghijklmnopqrstuvwxyz") {
		t.Fatalf("fingerprint = %q", f.Fingerprint)
	}
	if _, ok := leakFinding(&leakRecord{RuleID: "x"}, "betterleaks"); ok {
		t.Fatal("record without File accepted")
	}
	for rule, want := range map[string]string{"private-key": "private_key", "ssh-rsa": "ssh_key", "jwt-token": "jwt", "aws-x": "aws_key", "gcp-x": "gcp_key", "azure-x": "azure_key", "db-password": "password", "slack-token": "token", "generic-api-key": "api_key", "tls-cert": "certificate", "other": "generic_secret"} {
		if got := leakSecretType(rule); got != want {
			t.Errorf("leakSecretType(%q) = %q, want %q", rule, got, want)
		}
	}
	if leakService("stripe-live-key") != "stripe" || leakService("none") != "" {
		t.Fatal("leakService")
	}
	if got := stripUserinfo("https://u:p@a.example.com/x"); got != "https://a.example.com/x" {
		t.Fatalf("stripUserinfo = %q", got)
	}
	if typ, v := hostAsset("[2001:db8::1]:443"); typ != "ip_address" || v != "2001:db8::1" {
		t.Fatalf("hostAsset = %s %s", typ, v)
	}
	if _, v := hostAsset("bad host@x"); v != "" {
		t.Fatal("hostAsset accepted a bad host")
	}
	if cweID("CWE-89: SQL") != "CWE-89" || cweID("89") != "CWE-89" || cweID("x") != "" {
		t.Fatal("cweID")
	}
	if sanePURL("pkg:npm/a@1") == "" || sanePURL("pkg:npm/a b") != "" || sanePURL("npm/a") != "" {
		t.Fatal("sanePURL")
	}
}
