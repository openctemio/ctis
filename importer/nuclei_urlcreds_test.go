package importer

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// SECURITY: a credential in a matched URL never reaches the report. The
// URL is redacted with weburl (user info, fragment and every query value
// removed; names kept), and the host is fingerprinted without its user
// info.
func TestNucleiMatchedURLCredentialsRedacted(t *testing.T) {
	line := `{"template-id":"exposed-panel","info":{"name":"Panel","severity":"medium"},"type":"http","host":"https://ops:hunter2@a.example","matched-at":"https://a.example/admin?api_key=sk-live-SECRET123&page=1#token=frag-SECRET"}`
	res, err := Parse(context.Background(), strings.NewReader(line), Options{Format: FormatNuclei})
	if err != nil {
		t.Fatal(err)
	}
	f := res.Report.Findings[0]
	out, _ := json.Marshal(res.Report)
	for _, secret := range []string{"sk-live-SECRET123", "frag-SECRET", "hunter2"} {
		if strings.Contains(string(out), secret) {
			t.Fatalf("%s reached the report: %s", secret, out)
		}
	}
	if f.Web == nil || f.Web.URL != "https://a.example/admin?api_key=&page=" {
		t.Fatalf("web %+v", f.Web)
	}
	clean := `{"template-id":"x","info":{"name":"X","severity":"low"},"host":"https://a.example","matched-at":"https://a.example/"}`
	cres, _ := Parse(context.Background(), strings.NewReader(clean), Options{Format: FormatNuclei})
	if fingerprintHost("https://a.example") != "https://a.example" || cres.Report.Findings[0].Fingerprint == "" {
		t.Fatal("a host without credentials keeps its fingerprint input")
	}
	if got := fingerprintHost("https://ops:hunter2@a.example"); strings.Contains(got, "hunter2") {
		t.Fatalf("fingerprint host %q", got)
	}
}
