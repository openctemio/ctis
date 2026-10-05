package importer

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/ctis"
)

func TestDetect_GitleaksGrypeZAP(t *testing.T) {
	cases := []struct {
		in   string
		want Format
		ok   bool
	}{
		{`[{"RuleID": "generic-api-key", "Secret": "x", "File": "a"}]`, FormatGitleaks, true},
		{`[{"RuleID": "r", "Match": "x"}]`, FormatGitleaks, true},
		{`[{"RuleID": "r"}]`, "", false},
		{`[]`, "", false},
		{`[{"document": {"csaf_version": "2.0"}}]`, FormatCSAF, true},
		{`{"matches": [], "source": {"type": "image"}}`, FormatGrype, true},
		{`{"matches": [], "descriptor": {"name": "grype"}}`, FormatGrype, true},
		{`{"matches": []}`, "", false},
		{`{"@programName": "ZAP", "site": []}`, FormatZAP, true},
		{`{"@version": "2.15.0", "site": []}`, FormatZAP, true},
		{`{"site": []}`, "", false},
		{"<?xml version=\"1.0\"?>\n<OWASPZAPReport version=\"2.15.0\">", FormatZAP, true},
		// The earlier formats still win their own shapes.
		{`{"findings": [{"title": "x"}]}`, FormatDefectDojo, true},
		{`{"results": []}`, FormatOSV, true},
	}
	for _, c := range cases {
		got, ok := Detect([]byte(c.in))
		if got != c.want || ok != c.ok {
			t.Errorf("Detect(%.60q) = %q, %v; want %q, %v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestGitleaks_NoRawSecretAnywhere(t *testing.T) {
	long := "fakeLongSampleSecretValue0123456789"
	short := "pw12345"
	in := `[
{"RuleID": "aws-access-token", "Description": "found ` + long + ` here", "Secret": "` + long + `", "Match": "key=` + long + `", "Line": "x = ` + long + `", "File": "a.py", "StartLine": 1, "Fingerprint": "c:a.py:aws-access-token:1:` + long + `", "Author": "Jane Example", "Email": "jane@example.com", "Message": "secret commit"},
{"RuleID": "password", "Description": "pw", "Secret": "` + short + `", "Match": "pw=` + short + `", "File": "b.env"}
]`
	res, err := Parse(context.Background(), strings.NewReader(in), Options{})
	if err != nil {
		t.Fatal(err)
	}
	out, _ := json.Marshal(res)
	for _, s := range []string{long, short, "Jane", "jane@example.com", "secret commit"} {
		if strings.Contains(string(out), s) {
			t.Errorf("output holds %q", s)
		}
	}
	f := res.Report.Findings
	if f[0].Location.Snippet != "fake********" || f[1].Location.Snippet != "REDACTED" {
		t.Fatalf("snippets = %q, %q", f[0].Location.Snippet, f[1].Location.Snippet)
	}
	if f[0].Secret.SecretType != "aws_key" || f[1].Secret.SecretType != "password" {
		t.Fatalf("secret types = %q, %q", f[0].Secret.SecretType, f[1].Secret.SecretType)
	}
	if f[0].Secret.MaskedValue != "" || f[0].Secret.Length != 0 {
		t.Fatal("masked_value or length set: it changes fingerprints or reveals the length")
	}
}

func TestGitleaks_DefaultAssetAndEmpty(t *testing.T) {
	res, err := Parse(context.Background(), strings.NewReader(`[{"RuleID": "jwt", "Secret": "x", "File": "a"}]`),
		Options{DefaultAsset: &ctis.Asset{Type: ctis.AssetTypeRepository, Value: "github.com/example/app"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Report.Findings[0].AssetRef != "repository-github.com/example/app" {
		t.Fatalf("asset_ref = %q", res.Report.Findings[0].AssetRef)
	}
	// gitleaks writes [] when it finds nothing.
	res, err = Parse(context.Background(), strings.NewReader("[]"), Options{Format: FormatGitleaks})
	if err != nil || len(res.Report.Findings) != 0 {
		t.Fatalf("empty report: %v", err)
	}
}

func TestGlSecretType(t *testing.T) {
	for rule, want := range map[string]string{
		"private-key": "private_key", "github-pat": "token", "gcp-api-key": "gcp_key", "azure-ad-client-secret": "azure_key",
		"slack-bot-token": "token", "generic-api-key": "api_key", "postgres-uri": "database_credential", "jwt": "jwt",
		"age-secret-key": "encryption_key", "pkcs12-file": "certificate", "openssh-key": "ssh_key", "something": "generic_secret",
		"oauth-client": "oauth",
	} {
		if got := glSecretType(rule); got != want {
			t.Errorf("glSecretType(%q) = %q, want %q", rule, got, want)
		}
	}
}

func TestMore_HostileInputs(t *testing.T) {
	cases := map[string]struct {
		in     string
		format Format
		kind   error
		line   int
	}{
		"zap xxe":            {`<?xml version="1.0"?><!DOCTYPE OWASPZAPReport [<!ENTITY x SYSTEM "file:///etc/passwd">]><OWASPZAPReport>&x;</OWASPZAPReport>`, FormatZAP, ErrUnsafe, 0},
		"zap billion laughs": {`<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;&a;">]><OWASPZAPReport>&b;</OWASPZAPReport>`, FormatZAP, ErrUnsafe, 0},
		"zap xml deep":       {`<OWASPZAPReport>` + strings.Repeat("<site>", 200) + strings.Repeat("</site>", 200) + `</OWASPZAPReport>`, FormatZAP, ErrTooLarge, 0},
		"zap wrong root":     {`<html/>`, FormatZAP, ErrMalformed, 0},
		"zap json no site":   {`{"@programName": "ZAP"}`, FormatZAP, ErrMalformed, 0},
		"zap json bad site":  {`{"@programName": "ZAP", "site": 5}`, FormatZAP, ErrMalformed, 0},
		"grype deep":         {`{"matches": [` + strings.Repeat("[", 200) + strings.Repeat("]", 200) + `]}`, FormatGrype, ErrTooLarge, 0},
		"grype no matches":   {`{"source": {}}`, FormatGrype, ErrMalformed, 0},
		"gitleaks not array": {`{"RuleID": "x"}`, FormatGitleaks, ErrMalformed, 0},
		"gitleaks utf-8":     {"[\n{\"RuleID\": \"r\",\n\"Secret\": \"\xff\"}]", FormatGitleaks, ErrMalformed, 3},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse(context.Background(), strings.NewReader(c.in), Options{Format: c.format})
			if !errors.Is(err, c.kind) {
				t.Fatalf("want %v, got %v", c.kind, err)
			}
			var pe *ParseError
			if c.line > 0 && (!errors.As(err, &pe) || pe.Line != c.line) {
				t.Fatalf("want line %d, got %v", c.line, err)
			}
		})
	}
}

func TestMore_HugeStringRefused(t *testing.T) {
	in := `[{"RuleID": "r", "Secret": "` + strings.Repeat("A", 4096) + `"}]`
	_, err := Parse(context.Background(), strings.NewReader(in), Options{Limits: Limits{MaxTextBytes: 1024}})
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("want ErrTooLarge, got %v", err)
	}
}

func TestMore_WrongTypesAreIssuesWithLines(t *testing.T) {
	grype := "{\"source\": {\"type\": \"image\", \"target\": {\"userInput\": \"img:1\"}},\n\"matches\": [\n" +
		"{\"vulnerability\": {\"id\": \"CVE-2024-0001\", \"severity\": \"High\"}, \"artifact\": {\"name\": \"a\", \"version\": \"1\"}},\n" +
		"{\"vulnerability\": {\"id\": 5}, \"artifact\": {\"name\": \"b\"}}\n]}"
	res, err := Parse(context.Background(), strings.NewReader(grype), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Report.Findings) != 1 || len(res.Issues) != 1 || res.Issues[0].Line != 4 {
		t.Fatalf("findings %d issues %+v", len(res.Report.Findings), res.Issues)
	}
	leaks := "[\n{\"RuleID\": \"r\", \"Secret\": \"x\"},\n{\"RuleID\": [1], \"Secret\": \"y\"}\n]"
	res, err = Parse(context.Background(), strings.NewReader(leaks), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Report.Findings) != 1 || len(res.Issues) != 1 || res.Issues[0].Line != 3 {
		t.Fatalf("findings %d issues %+v", len(res.Report.Findings), res.Issues)
	}
	zap := "{\"@programName\": \"ZAP\", \"site\": [\n{\"@host\": \"a.example.com\", \"alerts\": [{\"pluginid\": \"1\", \"alert\": \"x\", \"riskcode\": \"1\"}]},\n{\"@host\": {\"bad\": 1}}\n]}"
	res, err = Parse(context.Background(), strings.NewReader(zap), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Report.Findings) != 1 || len(res.Issues) != 1 || res.Issues[0].Line != 3 {
		t.Fatalf("findings %d issues %+v", len(res.Report.Findings), res.Issues)
	}
}

func TestZAP_SingleSiteObjectAndURIUserInfo(t *testing.T) {
	in := `{"@programName": "ZAP", "site": {"@name": "https://a.example.com:8443/path?x=1", "alerts": [{"pluginid": "1", "alert": "x", "riskcode": "2", "instances": [{"uri": "https://u:p@a.example.com:8443/x", "method": "GET"}]}]}}`
	res, err := Parse(context.Background(), strings.NewReader(in), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if v := res.Report.Assets[0].Value; v != "https://a.example.com:8443" {
		t.Fatalf("asset = %q", v)
	}
	if ev := res.Report.Findings[0].Evidence; strings.Contains(ev, "u:p@") {
		t.Fatalf("user info kept: %q", ev)
	}
	if res.Report.Findings[0].Network.Port != 8443 {
		t.Fatalf("port = %d", res.Report.Findings[0].Network.Port)
	}
}

func TestZAP_InstancesAreCapped(t *testing.T) {
	var inst []string
	for i := 0; i < 30; i++ {
		inst = append(inst, `{"uri": "https://a.example.com/p", "method": "GET"}`)
	}
	in := `{"@programName": "ZAP", "site": [{"@host": "a.example.com", "@ssl": "true", "alerts": [{"pluginid": "1", "alert": "x", "riskcode": "2", "instances": [` + strings.Join(inst, ",") + `]}]}]}`
	res, err := Parse(context.Background(), strings.NewReader(in), Options{})
	if err != nil {
		t.Fatal(err)
	}
	f := res.Report.Findings[0]
	if got := strings.Count(f.Evidence, "\n") + 1; got != zapMaxInstances+1 || !strings.Contains(f.Evidence, "10 more instances") || f.OccurrenceCount != 30 {
		t.Fatalf("evidence lines %d, count %d: %q", got, f.OccurrenceCount, f.Evidence)
	}
}

func TestGrype_DefaultAssetAndSources(t *testing.T) {
	in := `{"source": {"type": "directory", "target": "/src"}, "matches": [{"vulnerability": {"id": "CVE-2024-0001", "severity": "Negligible", "cvss": [{"source": "security-advisories@github.com", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "metrics": {"baseScore": 5.3}}]}, "artifact": {"name": "a", "version": "1", "purl": "pkg:npm/a@1"}}]}`
	res, err := Parse(context.Background(), strings.NewReader(in), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if a := res.Report.Assets[0]; a.Type != ctis.AssetTypeRepository || a.Value != "/src" {
		t.Fatalf("asset = %+v", a)
	}
	f := res.Report.Findings[0]
	if f.Severity != ctis.SeverityInfo || f.Scores[0].Source != "ghsa" || f.Vulnerability.CVSSSource != "ghsa" {
		t.Fatalf("finding = %+v %+v", f.Severity, f.Scores)
	}
	res, err = Parse(context.Background(), strings.NewReader(in), Options{DefaultAsset: &ctis.Asset{Type: ctis.AssetTypeRepository, Value: "github.com/example/app"}})
	if err != nil || res.Report.Assets[0].Value != "github.com/example/app" {
		t.Fatalf("default asset not used: %v %+v", err, res.Report.Assets)
	}
	if grypeSource("", "debian:distro:debian:12") != "debian" || grypeSource("", "") != "vendor" {
		t.Fatal("grypeSource")
	}
}
