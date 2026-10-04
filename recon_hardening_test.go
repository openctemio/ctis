package ctis

import (
	"encoding/json"
	"strings"
	"testing"
)

// Recon output describes hosts that the scanned party controls: titles,
// server headers and banners are attacker-chosen, and crawled URLs can carry
// credentials. None of that may reach the report unfiltered.
func TestReconHostileInput(t *testing.T) {
	const token = "s3cr3t-" + "token"
	in := &ReconToCTISInput{
		ScannerName: "httpx",
		ReconType:   "",
		LiveHosts: []LiveHostInput{{
			URL:       "https://admin:" + token + "@app.example.com:8443/login",
			Host:      "app.example.com",
			Scheme:    "https",
			Port:      8443,
			Title:     "Login\x1b[31m\nINFO forged log line\r\x00",
			WebServer: "nginx\x07",
			Redirect:  "https://" + token + "@sso.example.com/",
		}},
		URLs: []DiscoveredURLInput{{
			URL:    "https://user:" + token + "@app.example.com/a?x=1",
			Parent: "http://u:" + token + "@app.example.com/",
		}},
		OpenPorts: []OpenPortInput{{
			IP:      "192.0.2.1",
			Port:    22,
			Service: "ssh\n\x1b]0;pwned\x07",
			Banner:  "SSH-2.0-OpenSSH_9.6\r\nline2\x1b[2J\x00",
		}},
		Subdomains: []SubdomainInput{{
			Host: "a.example.com", Domain: "example.com",
			IPs: []string{"192.0.2.1", "192.0.2.1", "::ffff:192.0.2.1", "2001:db8::1", "not-an-ip"},
		}},
	}
	r, err := ConvertReconToCTIS(in, nil)
	if err != nil {
		t.Fatal(err)
	}
	assertReportValid(t, loadSchemaSet(t), r)
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), token) {
		t.Errorf("URL credentials are in the report:\n%s", out)
	}
	for _, bad := range []string{`\u001b`, `\u0000`, `\u0007`} {
		if strings.Contains(string(out), bad) {
			t.Errorf("control character %s is in the report:\n%s", bad, out)
		}
	}

	byValue := assetsByValue(r)
	http, ok := byValue["https://app.example.com:8443/login"]
	if !ok {
		t.Fatalf("http service not keyed by the URL without userinfo: %v", keys(byValue))
	}
	if got := http.Properties["title"]; got != "Login[31mINFO forged log line" {
		t.Errorf("title = %q", got)
	}
	if got := http.Properties["redirect_url"]; got != "https://sso.example.com/" {
		t.Errorf("redirect_url = %q", got)
	}
	if _, ok := byValue["https://app.example.com/a?x=1"]; !ok {
		t.Errorf("crawled URL not stripped of userinfo: %v", keys(byValue))
	}
	ports := byValue["192.0.2.1"].Technical.IPAddress.Ports
	if len(ports) != 1 || ports[0].Service != "ssh]0;pwned" || ports[0].Banner != "SSH-2.0-OpenSSH_9.6\r\nline2[2J" {
		t.Errorf("port = %+v", ports)
	}
	var recs []string
	for _, rec := range byValue["a.example.com"].Technical.Domain.DNSRecords {
		recs = append(recs, rec.Type+" "+rec.Value)
	}
	if got := strings.Join(recs, ","); got != "A 192.0.2.1,AAAA 2001:db8::1" {
		t.Errorf("DNS records = %s (duplicates and ::ffff: mapped forms collapse)", got)
	}
}

// Criticality is business context; the converter's defaults assert none.
func TestReconDefaultsSetNoCriticality(t *testing.T) {
	for name, in := range reconFixtures() {
		r, err := ConvertReconToCTIS(in, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, a := range r.Assets {
			if a.Criticality != "" {
				t.Errorf("%s: asset %s has criticality %q", name, a.Value, a.Criticality)
			}
		}
	}
}

func TestStripURLUserinfo(t *testing.T) {
	for in, want := range map[string]string{
		"":                              "",
		"https://a.example/":            "https://a.example/",
		"https://u:p@a.example/x?y=1#z": "https://a.example/x?y=1#z",
		"https://tok@a.example":         "https://a.example",
		"mailto:a@b.example":            "mailto:a@b.example", // no host: unchanged
		"not a url @ all":               "not a url @ all",
		"https://a.example/@user/repo":  "https://a.example/@user/repo",
		"http://[::1]:80/%zz@x":         "http://[::1]:80/%zz@x", // unparsable: unchanged
	} {
		if got := stripURLUserinfo(in); got != want {
			t.Errorf("stripURLUserinfo(%q) = %q, want %q", in, got, want)
		}
	}
}

func keys(m map[string]Asset) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
