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
	if c.Value != testFPHex || c.Name != testFPHex || c.Properties["fingerprint"] != testFPHex {
		t.Errorf("certificate identity = %q/%q/%v, want %s", c.Value, c.Name, c.Properties["fingerprint"], testFPHex)
	}
	ct := c.Technical.Certificate
	if ct == nil || ct.NotAfter == nil || ct.NotBefore == nil || ct.SubjectCN != "example.com" || ct.IssuerOrg != "Let's Encrypt" {
		t.Fatalf("certificate technical = %+v", ct)
	}
	if want := []string{"example.com", "www.example.com"}; strings.Join(ct.SANs, ",") != strings.Join(want, ",") {
		t.Errorf("SANs = %v, want %v (lower-cased, de-duplicated)", ct.SANs, want)
	}
	if ct.Expired {
		t.Error("a certificate valid for 60 more days is not expired")
	}

	var svc Asset
	for _, a := range r.Assets {
		if a.Type == AssetTypeHTTPService {
			svc = a
		}
	}
	if len(svc.RelatedAssets) != 1 || svc.RelatedAssets[0] != c.ID || svc.Properties["tls_fingerprint"] != testFPHex {
		t.Errorf("service not linked to its certificate: related %v, tls_fingerprint %v", svc.RelatedAssets, svc.Properties["tls_fingerprint"])
	}
	for k, want := range map[string]any{
		"favicon_mmh3": "-1840324437", "asn": "AS13335", "asn_org": "CLOUDFLARENET", "asn_country": "US",
		"cdn": "cloudflare", "cdn_type": "waf", "waf": "cloudflare", "hosted_by": "cloudflare",
	} {
		if svc.Properties[k] != want {
			t.Errorf("service %s = %v, want %v", k, svc.Properties[k], want)
		}
	}
	if j, _ := svc.Properties["jarm"].(string); len(j) != 62 {
		t.Errorf("jarm = %v", svc.Properties["jarm"])
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
	for _, a := range r.Assets {
		if a.Type == AssetTypeHTTPService && len(a.RelatedAssets) == 1 && a.RelatedAssets[0] == certs[0].ID {
			n++
		}
	}
	if n != 2 {
		t.Errorf("%d services link the certificate, want 2", n)
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
		if len(r.Assets[0].RelatedAssets) != 0 {
			t.Errorf("fingerprint %q: service links %v", fp, r.Assets[0].RelatedAssets)
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
	if len(ct.SANs) != maxCertSANs {
		t.Errorf("SANs = %d, want capped at %d", len(ct.SANs), maxCertSANs)
	}
	if c.Properties["sans_truncated"] != 10_000-maxCertSANs {
		t.Errorf("sans_truncated = %v, want %d", c.Properties["sans_truncated"], 10_000-maxCertSANs)
	}
	if !ct.Expired {
		t.Error("a certificate past not_after is expired")
	}
	out, _ := json.Marshal(r)
	for _, bad := range []string{`\u001b`, `\u0000`, `\u0007`, `\n`} {
		if strings.Contains(string(out), bad) {
			t.Errorf("control character %s in the report", bad)
		}
	}
	svc := r.Assets[0]
	for _, k := range []string{"favicon_mmh3", "jarm", "asn", "cdn_type", "waf"} {
		if v, ok := svc.Properties[k]; ok {
			t.Errorf("invalid %s kept: %v", k, v)
		}
	}
	if cdn, _ := svc.Properties["cdn"].(string); len(cdn) > maxProviderLen {
		t.Errorf("cdn %d bytes, want at most %d", len(cdn), maxProviderLen)
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
	byID := map[string]Asset{}
	for _, x := range m.Assets {
		byID[x.ID] = x
	}
	for _, x := range m.Assets {
		if x.Type != AssetTypeHTTPService {
			continue
		}
		if len(x.RelatedAssets) != 1 {
			t.Fatalf("%s: related %v", x.Value, x.RelatedAssets)
		}
		cert := byID[x.RelatedAssets[0]]
		if cert.Type != AssetTypeCertificate || cert.Value != x.Properties["tls_fingerprint"] {
			t.Errorf("%s links %q (%s), want its own certificate %v", x.Value, cert.Value, cert.Type, x.Properties["tls_fingerprint"])
		}
	}
}
