package importer

import (
	"context"
	"strings"
	"testing"
)

func TestRedactURLCredentials(t *testing.T) {
	cases := map[string]string{
		"https://a.example/admin":                                           "https://a.example/admin",
		"https://user:p4ss@a.example/x":                                     "https://a.example/x",
		"https://a.example/x?api_key=sk-live-123&page=2":                    "https://a.example/x?api_key=REDACTED&page=2",
		"https://a.example/x?q=1&access_token=abc&X-Amz-Signature=deadbeef": "https://a.example/x?q=1&access_token=REDACTED&X-Amz-Signature=REDACTED",
		"https://a.example/cb#access_token=abc&state=1":                     "https://a.example/cb#access_token=REDACTED&state=1",
		"https://a.example/x?password=":                                     "https://a.example/x?password=",
		"https://a.example/x?flag":                                          "https://a.example/x?flag",
		"a.example:443":                                                     "a.example:443",
		"https://a.example/x?Session%5Fid=v":                                "https://a.example/x?Session%5Fid=REDACTED",
	}
	for in, want := range cases {
		if got := redactURLCredentials(in); got != want {
			t.Errorf("redactURLCredentials(%q) = %q, want %q", in, got, want)
		}
	}
	if got := redactURLCredentials("https://u:p@a.example/%zz?token=x"); strings.Contains(got, "u:p@") || strings.Contains(got, "token=x") {
		t.Errorf("unparsable URL kept user info: %q", got)
	}
}

// SECURITY: a credential in a matched URL never reaches the report.
func TestNucleiMatchedURLCredentialsRedacted(t *testing.T) {
	line := `{"template-id":"exposed-panel","info":{"name":"Panel","severity":"medium"},"type":"http","host":"https://ops:hunter2@a.example","matched-at":"https://a.example/admin?api_key=sk-live-SECRET123&page=1#token=frag-SECRET"}`
	res, err := Parse(context.Background(), strings.NewReader(line), Options{Format: FormatNuclei})
	if err != nil {
		t.Fatal(err)
	}
	raw := res.Report
	all := strings.Join([]string{raw.Findings[0].Message, raw.Findings[0].Location.Path, raw.Findings[0].Fingerprint}, " ")
	for _, secret := range []string{"sk-live-SECRET123", "frag-SECRET", "hunter2"} {
		if strings.Contains(all, secret) {
			t.Fatalf("%s reached the report: %s", secret, all)
		}
	}
	if !strings.Contains(raw.Findings[0].Location.Path, "api_key=REDACTED") {
		t.Fatalf("location %q", raw.Findings[0].Location.Path)
	}
}
