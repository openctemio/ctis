package ctis

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

const testFP = "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89"

var testFPHex = strings.ToLower(strings.ReplaceAll(testFP, ":", ""))

func probeWithLeaf(hosts ...LiveHostInput) *ReconToCTISInput {
	return &ReconToCTISInput{ScannerName: "httpx", ReconType: "http_probe", Target: "example.com", LiveHosts: hosts}
}

func testLeaf() *TLSLeafInput {
	return &TLSLeafInput{
		SubjectCN:         "example.com",
		SANs:              []string{"example.com", "www.example.com", "WWW.example.com."},
		IssuerCN:          "R11",
		IssuerOrg:         "Let's Encrypt",
		SerialNumber:      "03:a1:b2",
		NotBefore:         time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:          time.Now().Add(60 * 24 * time.Hour).UTC().Truncate(time.Second),
		FingerprintSHA256: testFP,
	}
}

func certAssets(r *Report) []Asset {
	var out []Asset
	for _, a := range r.Assets {
		if a.Type == AssetTypeCertificate {
			out = append(out, a)
		}
	}
	return out
}

// An HTTPS probe keeps its leaf certificate: one certificate asset named by
// its SHA-256 fingerprint, linked from the service, with its dates.
func TestLiveHostLeafCertificate(t *testing.T) {
	in := probeWithLeaf(LiveHostInput{
		URL: "https://example.com", Host: "example.com", Scheme: "https", Port: 443, StatusCode: 200,
		TLS: testLeaf(), FaviconMMH3: "-1840324437", JARM: "27d40d40d29d40d1dc42d43d00041d4689ee210389f4f6b4b5b1b93f92252d",
		ASN: &ASNInput{Number: "AS13335", Org: "CLOUDFLARENET", Country: "us"}, CDN: "cloudflare", CDNType: "waf",
	})
	r, err := ConvertReconToCTIS(in, nil)
	if err != nil {
		t.Fatal(err)
	}
	assertReportValid(t, loadSchemaSet(t), r)
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	certs := certAssets(r)
	if len(certs) != 1 {
		t.Fatalf("want 1 certificate asset, got %d", len(certs))
	}
	c := certs[0]
	ct := c.Technical.Certificate
	if c.Value != testFPHex || ct == nil || ct.SHA256Fingerprint != testFPHex {
		t.Errorf("certificate identity = %q/%+v, want %s", c.Value, ct, testFPHex)
	}
	if ct == nil || ct.NotAfter == nil || ct.NotBefore == nil || ct.SubjectCN != "example.com" || ct.IssuerOrg != "Let's Encrypt" {
		t.Fatalf("certificate technical = %+v", ct)
	}
	if want := []string{"example.com", "www.example.com"}; strings.Join(ct.SubjectAltNames, ",") != strings.Join(want, ",") {
		t.Errorf("SANs = %v, want %v (lower-cased, de-duplicated)", ct.SubjectAltNames, want)
	}

	var origin Asset
	for _, a := range r.Assets {
		if a.Type == AssetTypeWebOrigin {
			origin = a
		}
	}
	if relationshipsOf(r, RelServesCertificate)[testFPHex] != origin.Value {
		t.Errorf("origin not linked to its certificate: %+v", r.Relationships)
	}
	h := origin.Technical.HTTP
	if h.FaviconMMH3 != "-1840324437" || h.WAF != "cloudflare" || h.CDN != "" || len(h.JARM) != 62 {
		t.Errorf("http = %+v", h)
	}
}

// Two services that serve the same certificate share one certificate asset.
func TestLiveHostSharedCertificateOnce(t *testing.T) {
	in := probeWithLeaf(
		LiveHostInput{URL: "https://example.com", Host: "example.com", Scheme: "https", TLS: testLeaf()},
		LiveHostInput{URL: "https://www.example.com", Host: "www.example.com", Scheme: "https", TLS: testLeaf()},
	)
	r, _ := ConvertReconToCTIS(in, nil)
	certs := certAssets(r)
	if len(certs) != 1 {
		t.Fatalf("want 1 certificate asset, got %d", len(certs))
	}
	n := 0
	for _, rel := range r.Relationships {
		if rel.Type == RelServesCertificate && rel.ToRef == certs[0].ID {
			n++
		}
	}
	if n != 2 {
		t.Errorf("%d origins link the certificate, want 2", n)
	}
}

// A leaf without a valid SHA-256 fingerprint has no identity: no
// certificate asset, and the service keeps no link.
func TestLiveHostLeafWithoutFingerprint(t *testing.T) {
	for _, fp := range []string{"", "zz", strings.Repeat("a", 63), strings.Repeat("g", 64), strings.Repeat("a", 40)} {
		leaf := testLeaf()
		leaf.FingerprintSHA256 = fp
		r, _ := ConvertReconToCTIS(probeWithLeaf(LiveHostInput{URL: "https://example.com", Scheme: "https", TLS: leaf}), nil)
		if n := len(certAssets(r)); n != 0 {
			t.Errorf("fingerprint %q: %d certificate assets, want 0", fp, n)
		}
		if len(r.Relationships) != 0 {
			t.Errorf("fingerprint %q: relationships %v", fp, r.Relationships)
		}
	}
}

// The scanned server chooses every certificate value: names are bounded,
// control characters removed, the SAN list capped.
func TestLiveHostLeafHostile(t *testing.T) {
	leaf := testLeaf()
	leaf.SubjectCN = strings.Repeat("x", 100_000) + "\x1b[31m"
	leaf.IssuerCN = "evil\nINFO forged\x00"
	leaf.SerialNumber = strings.Repeat("9", 10_000)
	leaf.SANs = make([]string, 10_000)
	for i := range leaf.SANs {
		leaf.SANs[i] = fmt.Sprintf("h%d.example.com", i)
	}
	leaf.SANs[0] = "bad name/with slash"
	leaf.SANs[1] = strings.Repeat("a", 5000)
	leaf.NotAfter = time.Now().Add(-time.Hour)
	in := probeWithLeaf(LiveHostInput{
		URL: "https://example.com", Scheme: "https", TLS: leaf,
		FaviconMMH3: "99999999999", JARM: strings.Repeat("0", 62),
		ASN: &ASNInput{Number: "AS99999999999", Org: "x"}, CDN: strings.Repeat("c", 1000) + "\x07", CDNType: "evil",
	})
	r, err := ConvertReconToCTIS(in, nil)
	if err != nil {
		t.Fatal(err)
	}
	assertReportValid(t, loadSchemaSet(t), r)
	c := certAssets(r)[0]
	ct := c.Technical.Certificate
	if len(ct.SubjectCN) > maxCertNameLen || len(ct.SerialNumber) > maxSerialLen {
		t.Errorf("unbounded names: cn %d bytes, serial %d bytes", len(ct.SubjectCN), len(ct.SerialNumber))
	}
	if len(ct.SubjectAltNames) != maxCertSANs {
		t.Errorf("SANs = %d, want capped at %d", len(ct.SubjectAltNames), maxCertSANs)
	}
	out, _ := json.Marshal(r)
	for _, bad := range []string{`\u001b`, `\u0000`, `\u0007`, `\n`} {
		if strings.Contains(string(out), bad) {
			t.Errorf("control character %s in the report", bad)
		}
	}
	h := r.Assets[0].Technical.HTTP
	if h.FaviconMMH3 != "" || h.JARM != "" || h.CDN != "" || h.WAF != "" {
		t.Errorf("invalid values kept: %+v", h)
	}
}

// Merging recon reports keeps a service's link to its certificate, even
// when the merged IDs change.
func TestMergeKeepsCertificateLink(t *testing.T) {
	a, _ := ConvertReconToCTIS(probeWithLeaf(LiveHostInput{URL: "https://example.com", Scheme: "https", TLS: testLeaf()}), nil)
	leaf := testLeaf()
	leaf.FingerprintSHA256 = strings.Repeat("1", 64)
	b, _ := ConvertReconToCTIS(probeWithLeaf(LiveHostInput{URL: "https://other.example.com", Scheme: "https", TLS: leaf}), nil)
	m := MergeReconReports([]*Report{a, b})
	assertReportValid(t, loadSchemaSet(t), m)
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
	serves := relationshipsOf(m, RelServesCertificate)
	if serves[testFPHex] != "https://example.com" || serves[strings.Repeat("1", 64)] != "https://other.example.com" {
		t.Errorf("certificate links: %v", serves)
	}
}

// A live host's technologies are typed asset technologies, never tags.
func TestLiveHostTechnologiesAreNotTags(t *testing.T) {
	r, err := ConvertReconToCTIS(probeWithLeaf(LiveHostInput{
		URL: "https://example.com", Host: "example.com", Scheme: "https", Port: 443, StatusCode: 200,
		Technologies: []string{"HSTS", "Vercel", "Next.js:13.4.1"},
	}), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range r.Assets {
		for _, tag := range a.Tags {
			t.Fatalf("tag %q on %s", tag, a.Value)
		}
	}
	got := fmt.Sprint(r.Assets[0].Technologies)
	if got != "[{HSTS   [] 0} {Vercel   [] 0} {Next.js 13.4.1  [] 0}]" {
		t.Fatalf("technologies = %s", got)
	}
}
