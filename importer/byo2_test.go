package importer

import (
	"os"
	"strings"
	"testing"

	"github.com/openctemio/ctis/v2"
)

// ffuf, S3Scanner and arjun: detection, secrets never kept, hostile lines,
// scope verdicts.

func TestDetect_FfufS3ScannerArjun(t *testing.T) {
	cases := map[string]struct {
		in   string
		want Format
	}{
		"ffuf":            {`{"commandline":"ffuf -u x","time":"t","results":[]}`, FormatFfuf},
		"s3scanner":       {`{"bucket":{"name":"a"},"level":"info","msg":"","time":"t"}`, FormatS3Scanner},
		"s3scanner log 1": {"{\"level\":\"info\",\"msg\":\"start\",\"time\":\"t\"}\n{\"bucket\":{\"name\":\"a\"},\"level\":\"info\",\"msg\":\"\"}\n", FormatS3Scanner},
		"arjun":           {`{"https://www.example.com/a":{"method":"GET","params":["q"]}}`, FormatArjun},
		// semgrep and osv files also have "results".
		"semgrep": {`{"results":[{"check_id":"x"}],"errors":[]}`, FormatSemgrep},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			got, ok := Detect([]byte(c.in))
			if !ok || got != c.want {
				t.Fatalf("Detect = %q, %v; want %q", got, ok, c.want)
			}
		})
	}
	for _, in := range []string{`{"https://a.example.com":{},"notes":"x"}`, `{"level":"info","msg":"x","time":"t"}`} {
		if f, ok := Detect([]byte(in)); ok {
			t.Fatalf("%s detected as %q", in, f)
		}
	}
}

func TestFfufArjun_SecretsNeverKept(t *testing.T) {
	for _, fx := range []struct {
		path   string
		format Format
	}{{fixtureRoot + "/ffuf/results.json", FormatFfuf}, {fixtureRoot + "/arjun/params.json", FormatArjun}} {
		data, err := os.ReadFile(fx.path)
		if err != nil {
			t.Fatal(err)
		}
		res, err := parseString(t, string(data), Options{Format: fx.format})
		if err != nil {
			t.Fatal(err)
		}
		raw := mustJSON(t, res.Report)
		for _, secret := range []string{"SECRETCOOKIE", "SECRETTOKEN", "FFUFHASH", "Mozilla"} {
			if strings.Contains(raw, secret) {
				t.Fatalf("%s: %q reached the report", fx.format, secret)
			}
		}
		if len(res.Report.Findings) != 0 || len(res.Report.Endpoints) == 0 {
			t.Fatalf("%s: findings %d endpoints %d", fx.format, len(res.Report.Findings), len(res.Report.Endpoints))
		}
	}
}

func TestFfuf_HostileResults(t *testing.T) {
	in := `{"commandline":"x","results":[{"url":"javascript:alert(1)"},{"url":"https://u:p@www.example.com/a?token=abc","status":200},{"url":7}],"config":{}}`
	res, err := parseString(t, in, Options{Format: FormatFfuf, ScopeDomains: []string{"example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	raw := mustJSON(t, res.Report)
	if strings.Contains(raw, "u:p@") || strings.Contains(raw, "abc") {
		t.Fatalf("credentials or a query value reached the report: %s", raw)
	}
	if res.Stats.Skipped != 2 || len(res.Report.Endpoints) != 1 {
		t.Fatalf("skipped %d endpoints %d", res.Stats.Skipped, len(res.Report.Endpoints))
	}
	if got := scopeOf(res.Report, ctis.AssetTypeWebOrigin, "https://www.example.com"); got != scopeInTarget {
		t.Fatalf("origin is %q, want in_target", got)
	}
}

func TestS3Scanner_FindingsAndHostileLines(t *testing.T) {
	in := strings.Join([]string{
		`{"level":"info","msg":"start","time":"t"}`,
		`not json`,
		`{"bucket":{"name":"../etc","exists":1,"provider":"aws","perm_all_users_read":1},"level":"info","msg":""}`,
		`{"bucket":{"name":"pub-bucket","exists":1,"provider":"gcp","perm_all_users_full_control":1,"perm_auth_users_read":2,"objects":[{"key":"secret/key.pem"}],"owner_display_name":"Jane"},"level":"info","msg":""}`,
		`{"bucket":{"name":"gone-bucket","exists":0,"provider":"aws","perm_all_users_read":1},"level":"info","msg":""}`,
		`{"bucket":{"name":"unknown-bucket","exists":2,"provider":"aws"},"level":"info","msg":""}`,
		"{\"bucket\":{\"name\":\"ctl\x1b[31m\",\"exists\":1},\"level\":\"info\",\"msg\":\"\"}",
	}, "\n")
	res, err := parseString(t, in, Options{Format: FormatS3Scanner, ScopeDomains: []string{"example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Report.Assets) != 1 || res.Report.Assets[0].Value != "pub-bucket.storage.googleapis.com" {
		t.Fatalf("assets = %+v", res.Report.Assets)
	}
	if len(res.Report.Findings) != 1 || res.Report.Findings[0].RuleID != "s3scanner:public-write" || res.Report.Findings[0].Severity != ctis.SeverityCritical {
		t.Fatalf("findings = %+v (unknown permissions are not findings)", res.Report.Findings)
	}
	raw := mustJSON(t, res.Report)
	if strings.Contains(raw, "key.pem") || strings.Contains(raw, "Jane") {
		t.Fatalf("object keys or the owner reached the report: %s", raw)
	}
	if got := scopeOf(res.Report, ctis.AssetTypeStorage, "pub-bucket.storage.googleapis.com"); got != scopeOutsideTarget {
		t.Fatalf("a provider bucket is %q, want outside_target", got)
	}
}

func TestArjun_MethodsAndBadKeys(t *testing.T) {
	in := `{"https://www.example.com/a":{"method":"POST","params":["x","x",""]},"ftp://www.example.com/b":{"method":"GET","params":["y"]},"https://www.example.com/c":{"method":"XML","params":"notalist"}}`
	res, err := parseString(t, in, Options{Format: FormatArjun})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Report.Endpoints) != 1 {
		t.Fatalf("endpoints = %+v", res.Report.Endpoints)
	}
	e := res.Report.Endpoints[0]
	if e.Method != "POST" || len(e.Params) != 1 || e.Params[0].Location != ctis.ParamLocationForm {
		t.Fatalf("endpoint = %+v", e)
	}
	if res.Stats.Skipped != 2 {
		t.Fatalf("skipped = %d, want 2", res.Stats.Skipped)
	}
}
