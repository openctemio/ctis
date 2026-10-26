package importer

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Hostile bundles. Every case must fail closed, or keep going without the
// bad part, and never open a file the policy forbids.

// memBundle builds ArchiveFiles from named contents and records which were
// opened.
type memBundle struct {
	files  []ArchiveFile
	opened map[string]int
}

func newMemBundle(contents map[string]string) *memBundle {
	m := &memBundle{opened: map[string]int{}}
	names := make([]string, 0, len(contents))
	for n := range contents {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		n, data := n, contents[n]
		m.files = append(m.files, NewArchiveFile(n, int64(len(data)), func() (io.ReadCloser, error) {
			m.opened[n]++
			return io.NopCloser(strings.NewReader(data)), nil
		}))
	}
	return m
}

func (m *memBundle) parse(opts Options) (*Result, error) {
	return ParseBundle(context.Background(), m.files, opts)
}

// minimal is a small valid bundle: the layout markers and a subdomain list.
func minimal(extra map[string]string) map[string]string {
	c := map[string]string{
		"example.com/subdomains/subdomains.txt": "www.example.com\n",
		"example.com/webs/webs.txt":             "https://www.example.com\n",
	}
	for k, v := range extra {
		c["example.com/"+k] = v
	}
	return c
}

func TestBundle_NeverOpensPeopleAndCredentialFiles(t *testing.T) {
	dir := filepath.Join(bundleFixtureRoot, "v4")
	contents := map[string]string{}
	err := filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		b, _ := os.ReadFile(p)
		contents[filepath.ToSlash(rel)] = string(b)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// More people and credential files, under names reconFTW and others use.
	for _, n := range []string{"osint/emails.txt", "osint/passwords.txt", "osint/metadata.txt", "osint/dorks.txt", "osint/users.txt", "osint/trufflehog.json", "osint/secrets/leak.txt"} {
		contents[n] = "NEVER-OPENED-SENTINEL"
	}
	m := newMemBundle(contents)
	res, err := m.parse(bundleOpts())
	if err != nil {
		t.Fatal(err)
	}
	for n := range m.opened {
		if strings.HasPrefix(n, "osint/") || strings.HasPrefix(n, "screenshots/") {
			t.Errorf("%s was opened", n)
		}
	}
	skipped := map[string]bool{}
	for _, s := range res.Skipped {
		skipped[s.Path] = true
	}
	for _, n := range []string{"/osint/emails.txt", "/osint/passwords.txt", "/osint/secrets/leak.txt", "/osint/trufflehog.json", "/screenshots/www.example.com.png"} {
		if !skipped[n] {
			t.Errorf("%s is not listed as skipped", n)
		}
	}
	b, _ := json.Marshal(res.Report)
	if strings.Contains(string(b), "NEVER-OPENED-SENTINEL") {
		t.Error("the report holds data of a forbidden file")
	}
}

func TestBundle_UnreadFilesAreListed(t *testing.T) {
	m := newMemBundle(minimal(map[string]string{
		"fuzzing/ffuf.txt":            "https://www.example.com/admin\n",
		"js/js_secrets.txt":           "token=AKIAXXXXXXXXXXXXXXXX\n",
		"hosts/portscan_active.gnmap": "Host: 192.0.2.1 ()\tPorts: 22/open/tcp//ssh///\n",
		"report/export_all.jsonl":     "{}\n",
		"webs/web_full_info.txt":      `{"url":"https://www.example.com","zzz_new_member":1,"tls":{"zzz_tls":1}}` + "\n",
	}))
	res, err := m.parse(bundleOpts())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/fuzzing/ffuf.txt", "/js/js_secrets.txt", "/hosts/portscan_active.gnmap", "/report/export_all.jsonl",
		"/webs/web_full_info.txt/zzz_new_member", "/webs/web_full_info.txt/tls/zzz_tls"}
	got := map[string]bool{}
	for _, u := range res.Unmapped {
		got[u] = true
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("%s is not in Unmapped %v", w, res.Unmapped)
		}
	}
	for _, n := range []string{"example.com/fuzzing/ffuf.txt", "example.com/js/js_secrets.txt", "example.com/hosts/portscan_active.gnmap"} {
		if m.opened[n] != 0 {
			t.Errorf("%s was opened though nothing reads it", n)
		}
	}
}

func TestBundle_PathTraversalRefused(t *testing.T) {
	for _, name := range []string{"../evil.txt", "example.com/../../evil.txt", "/etc/passwd", "example.com\\subdomains\\subdomains.txt", "C:/x.txt", "example.com/a\x00b.txt", "example.com/a\nb.txt"} {
		t.Run(name, func(t *testing.T) {
			// As a ZIP entry.
			z := zipFiles(t, map[string][]byte{"example.com/subdomains/subdomains.txt": []byte("a.example.com\n"), "example.com/webs/webs.txt": []byte("https://a.example.com\n"), name: []byte("x")})
			_, err := OpenBundleZip(bytes.NewReader(z), int64(len(z)), BundleLimits{})
			wantKind(t, err, ErrUnsafe)
			// As a file of any other source.
			c := minimal(nil)
			c[name] = "x"
			_, err = newMemBundle(c).parse(bundleOpts())
			wantKind(t, err, ErrUnsafe)
		})
	}
}

func TestBundle_RefusedConstructs(t *testing.T) {
	t.Run("duplicate name", func(t *testing.T) {
		m := newMemBundle(minimal(nil))
		m.files = append(m.files, m.files[0])
		_, err := m.parse(bundleOpts())
		wantKind(t, err, ErrUnsafe)
	})
	t.Run("nested archive", func(t *testing.T) {
		z := zipFiles(t, map[string][]byte{"example.com/subdomains/subdomains.txt": []byte("a\n"), "example.com/webs/inner.zip": []byte("PK")})
		_, err := OpenBundleZip(bytes.NewReader(z), int64(len(z)), BundleLimits{})
		wantKind(t, err, ErrUnsafe)
	})
	t.Run("too deep", func(t *testing.T) {
		c := minimal(nil)
		c["example.com/"+strings.Repeat("d/", 40)+"f.txt"] = "x"
		_, err := newMemBundle(c).parse(bundleOpts())
		wantKind(t, err, ErrUnsafe)
	})
	t.Run("two recon directories", func(t *testing.T) {
		c := minimal(nil)
		c["other.org/subdomains/subdomains.txt"] = "a.other.org\n"
		c["other.org/webs/webs.txt"] = "https://a.other.org\n"
		_, err := newMemBundle(c).parse(bundleOpts())
		wantKind(t, err, ErrMalformed)
	})
	t.Run("no layout", func(t *testing.T) {
		_, err := newMemBundle(map[string]string{"notes.txt": "x", "data/a.txt": "y"}).parse(bundleOpts())
		wantKind(t, err, ErrUnknownFormat)
		if _, ok := DetectBundle([]string{"notes.txt"}); ok {
			t.Error("DetectBundle accepted a directory without the layout")
		}
	})
	t.Run("one marker only", func(t *testing.T) {
		_, err := newMemBundle(map[string]string{"subdomains/subdomains.txt": "a.example.com\n"}).parse(bundleOpts())
		wantKind(t, err, ErrUnknownFormat)
	})
	t.Run("wrong format named", func(t *testing.T) {
		o := bundleOpts()
		o.Format = FormatNuclei
		_, err := newMemBundle(minimal(nil)).parse(o)
		wantKind(t, err, ErrUnknownFormat)
	})
	t.Run("Parse does not read a bundle", func(t *testing.T) {
		_, err := Parse(context.Background(), strings.NewReader("a.example.com\n"), Options{Format: FormatReconFTW})
		wantKind(t, err, ErrUnknownFormat)
	})
	t.Run("files listed", func(t *testing.T) {
		o := bundleOpts()
		o.Bundle.MaxFilesListed = 1
		_, err := newMemBundle(minimal(nil)).parse(o)
		wantKind(t, err, ErrTooLarge)
		z := zipFiles(t, map[string][]byte{"a/subdomains/subdomains.txt": []byte("x\n"), "a/webs/webs.txt": []byte("x\n")})
		_, err = OpenBundleZip(bytes.NewReader(z), int64(len(z)), BundleLimits{MaxFilesListed: 1})
		wantKind(t, err, ErrTooLarge)
	})
}

func TestBundle_DecompressionBomb(t *testing.T) {
	// 64 MiB of zeros compress to about 64 KiB: a ratio far over 200.
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	put := func(name string, data []byte) {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	put("example.com/webs/webs.txt", []byte("https://www.example.com\n"))
	put("example.com/subdomains/subdomains.txt", bytes.Repeat([]byte("a"), 64<<20))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if buf.Len() > 1<<20 {
		t.Fatalf("the test bomb is not compressible: %d bytes", buf.Len())
	}
	_, _, err := parseZipBundle(t, buf.Bytes(), bundleOpts())
	wantKind(t, err, ErrTooLarge)
}

func TestBundle_SizeLimits(t *testing.T) {
	c := minimal(map[string]string{"hosts/ips.txt": strings.Repeat("192.0.2.1\n", 1000)})
	o := bundleOpts()
	o.Bundle.MaxTotalBytes = 500
	_, err := newMemBundle(c).parse(o)
	wantKind(t, err, ErrTooLarge)

	o = bundleOpts()
	o.Bundle.MaxFileBytes = 100
	_, err = newMemBundle(c).parse(o)
	wantKind(t, err, ErrTooLarge)

	// Files over the read limit are listed, not read.
	o = bundleOpts()
	o.Bundle.MaxFilesRead = 1
	res, err := newMemBundle(c).parse(o)
	if err != nil {
		t.Fatal(err)
	}
	over := 0
	for _, s := range res.Skipped {
		if strings.Contains(s.Reason, "not read") {
			over++
		}
	}
	if over == 0 {
		t.Errorf("no file was reported as over the read limit: %+v", res.Skipped)
	}
}

func TestBundle_HostileLines(t *testing.T) {
	huge := strings.Repeat("a", 1<<20)
	subs := "ok1.example.com\r\n" + // CRLF is fine
		huge + ".example.com\n" + // 1 MiB line
		"nul\x00.example.com\n" +
		"bare\rcr.example.com\n" +
		"bad\xff\xfe.example.com\n" +
		"esc\x1b[31m.example.com\n" +
		"javascript:alert(1)\n" +
		"user@example.com\n" +
		"*.wild.example.com\n" +
		"ok2.example.com"
	urls := "https://www.example.com/a?x=1\r\n" +
		"javascript:alert(1)\n" +
		"data:text/html,<script>alert(1)</script>\n" +
		"https://user:pw@www.example.com/secret\n" +
		"https://www.example.com/a\r\nSet-Cookie: x=1\n" +
		"https://www.example.com/a\x00b\n" +
		"https://www.example.com/" + huge + "\n" +
		"ftp://www.example.com/f\n" +
		"https://www.example.com/ok%0d%0aInjected: 1\n" +
		"https://www.example.com/last"
	res, err := newMemBundle(minimal(map[string]string{"subdomains/subdomains.txt": subs, "webs/url_extract.txt": urls})).parse(bundleOpts())
	if err != nil {
		t.Fatal(err)
	}
	hosts := map[string]bool{}
	for _, a := range res.Report.Assets {
		if a.Type != "http_service" {
			hosts[a.Value] = true
		}
	}
	for _, h := range []string{"ok1.example.com", "ok2.example.com"} {
		if !hosts[h] {
			t.Errorf("%s was lost with the hostile lines around it", h)
		}
	}
	for h := range hosts {
		if strings.ContainsAny(h, "\x00\r\n\x1b@*:") || strings.Contains(h, "javascript") {
			t.Errorf("hostile host kept: %q", h)
		}
	}
	for _, e := range res.Report.Endpoints {
		if strings.ContainsAny(e.Path+e.Origin, "\x00\r\n") || strings.Contains(e.Path, "javascript") || strings.Contains(e.Origin, "user") {
			t.Errorf("hostile endpoint kept: %+v", e)
		}
		for _, p := range e.Params {
			if strings.Contains(p.Name, "=") {
				t.Errorf("a parameter value was kept: %+v", p)
			}
		}
	}
	if len(res.Report.Endpoints) < 2 {
		t.Errorf("valid URLs around hostile ones were lost: %+v", res.Report.Endpoints)
	}
	if !hasPathIssue(res, "/subdomains/subdomains.txt", "longer than") || !hasPathIssue(res, "/webs/url_extract.txt", "longer than") {
		t.Errorf("long lines are not reported: %+v", res.Issues)
	}
}

func hasPathIssue(res *Result, path, text string) bool {
	for _, is := range res.Issues {
		if is.Path == path && strings.Contains(is.Message, text) {
			return true
		}
	}
	return false
}

func TestBundle_HTTPXHostile(t *testing.T) {
	lines := []string{
		`{"url":"javascript:alert(1)","status_code":200}`,
		`{"url":"https://user:pw@www.example.com/","status_code":200}`,
		"{\"url\":\"https://www.example.com/\\r\\nX: y\",\"status_code\":200}",
		`{"url":"https://www.example.com","title":"` + strings.Repeat("t", 5000) + `","tech":["a","b"],"status_code":99999}`,
		`{"url":"https://deep.example.com","x":` + strings.Repeat("[", 200) + strings.Repeat("]", 200) + `}`,
		`not json`,
		`[1,2]`,
		`{"url":"https://ok.example.com","tls":{"fingerprint_hash":{"sha256":"zz"}},"asn":{"as_number":"AS0"}}`,
	}
	res, err := newMemBundle(minimal(map[string]string{"webs/web_full_info.txt": strings.Join(lines, "\n") + "\n"})).parse(bundleOpts())
	if err != nil {
		t.Fatal(err)
	}
	var svc []string
	for _, a := range res.Report.Assets {
		if a.Type == "http_service" {
			svc = append(svc, a.Value)
			if title, _ := a.Properties["title"].(string); len(title) > 600 {
				t.Errorf("a title of %d bytes was kept", len(title))
			}
			if c, ok := a.Properties["status_code"]; ok && c != 0 {
				if n, _ := c.(int); n > 599 {
					t.Errorf("status %v kept", c)
				}
			}
		}
	}
	sort.Strings(svc)
	want := []string{"https://ok.example.com", "https://www.example.com"}
	if strings.Join(svc, ",") != strings.Join(want, ",") {
		t.Errorf("http services %v, want %v", svc, want)
	}
}

func TestBundle_OutOfScopeHostsAreCandidates(t *testing.T) {
	c := minimal(map[string]string{
		"subdomains/subdomains.txt": "www.example.com\nexample.com.evil.net\nevilexample.com\nother.org\n",
		"report/report.json":        `{"domain":"example.com"}`,
	})
	res, err := newMemBundle(c).parse(bundleOpts())
	if err != nil {
		t.Fatal(err)
	}
	scope := map[string]string{}
	for _, a := range res.Report.Assets {
		scope[a.Value], _ = a.Properties["import_scope"].(string)
	}
	want := map[string]string{"www.example.com": "in_target", "example.com.evil.net": "outside_target", "evilexample.com": "outside_target", "other.org": "outside_target"}
	for h, w := range want {
		if scope[h] != w {
			t.Errorf("%s: import_scope %q, want %q", h, scope[h], w)
		}
	}

	// The importing organization's own domains decide when it gives them.
	o := bundleOpts()
	o.ScopeDomains = []string{"other.org"}
	res, err = newMemBundle(c).parse(o)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range res.Report.Assets {
		got, _ := a.Properties["import_scope"].(string)
		if a.Value == "other.org" && got != "in_target" || a.Value == "www.example.com" && got != "outside_target" {
			t.Errorf("%s: import_scope %q with ScopeDomains", a.Value, got)
		}
	}
}

func TestBundle_VersionAndLayout(t *testing.T) {
	cases := []struct {
		name    string
		extra   map[string]string
		layout  string
		version string
	}{
		{"no log, no report", nil, "v3", "unknown-v3"},
		{"no log, report", map[string]string{"report/report.json": `{"domain":"example.com"}`}, "v4", "unknown-v4"},
		{"log v3", map[string]string{".log/a.txt": "reconFTW version: v3.6.1\n"}, "v3", "3.6.1"},
		{"log v4 without report", map[string]string{".log/a.txt": "x\n\x1b[1m reconFTW version: 4.2 \x1b[0m"}, "v4", "4.2"},
		{"log v3 with report", map[string]string{".log/a.txt": "reconFTW version: 3.0", "report/report.json": `{}`}, "v4", "3.0"},
		{"log with junk", map[string]string{".log/a.txt": "reconFTW version: vX\n"}, "v3", "unknown-v3"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := newMemBundle(minimal(tc.extra)).parse(bundleOpts())
			if err != nil {
				t.Fatal(err)
			}
			if res.Layout != tc.layout || res.Report.Tool.Version != tc.version {
				t.Errorf("layout %q version %q, want %q %q", res.Layout, res.Report.Tool.Version, tc.layout, tc.version)
			}
		})
	}
	t.Run("log beyond 64 KiB is not read", func(t *testing.T) {
		log := strings.Repeat("x", 70<<10) + "\nreconFTW version: 4.0\n"
		res, err := newMemBundle(minimal(map[string]string{".log/a.txt": log})).parse(bundleOpts())
		if err != nil {
			t.Fatal(err)
		}
		if res.Report.Tool.Version != "unknown-v3" {
			t.Errorf("version %q", res.Report.Tool.Version)
		}
	})
}

func TestBundle_ReportJSON(t *testing.T) {
	t.Run("future time is clamped", func(t *testing.T) {
		res, err := newMemBundle(minimal(map[string]string{"report/report.json": `{"domain":"example.com","generated_at":"2099-01-01T00:00:00Z"}`})).parse(bundleOpts())
		if err != nil {
			t.Fatal(err)
		}
		if !res.Report.Metadata.Timestamp.Equal(fixedNow) {
			t.Errorf("timestamp %v", res.Report.Metadata.Timestamp)
		}
	})
	t.Run("hostile domain is dropped", func(t *testing.T) {
		res, err := newMemBundle(minimal(map[string]string{"report/report.json": `{"domain":"a.com/../x\r\n"}`})).parse(bundleOpts())
		if err != nil {
			t.Fatal(err)
		}
		if s := res.Report.Metadata.Scope; s != nil && strings.ContainsAny(s.Name, "/\r\n") {
			t.Errorf("scope %q", s.Name)
		}
	})
	t.Run("malformed report is an issue", func(t *testing.T) {
		res, err := newMemBundle(minimal(map[string]string{"report/report.json": `{"domain":`})).parse(bundleOpts())
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Issues) == 0 {
			t.Error("a malformed report.json is not reported")
		}
	})
}

func TestBundle_NucleiFiles(t *testing.T) {
	good := `{"template-id":"t1","info":{"name":"N","severity":"medium"},"host":"https://www.example.com","matched-at":"https://www.example.com/x"}` + "\n"
	res, err := newMemBundle(minimal(map[string]string{
		"nuclei_output/medium_json.txt": good + "not json\n",
		"nuclei_output/low_json.txt":    "garbage only\n",
		"nuclei_output/info.txt":        "[t1] [http] [info] https://www.example.com\n",
	})).parse(bundleOpts())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Report.Findings) != 1 {
		t.Fatalf("findings %d", len(res.Report.Findings))
	}
	f := res.Report.Findings[0]
	var asset string
	for _, a := range res.Report.Assets {
		if a.ID == f.AssetRef {
			asset = a.Value
		}
	}
	if asset != "www.example.com" {
		t.Errorf("the finding is on %q, not on the bundle's host asset", asset)
	}
	if len(res.Issues) == 0 {
		t.Error("the broken nuclei lines are not reported")
	}
	found := false
	for _, u := range res.Unmapped {
		found = found || u == "/nuclei_output/info.txt"
	}
	if !found {
		t.Errorf("a plain nuclei text file is unread but not listed: %v", res.Unmapped)
	}

	// MinSeverity applies to the findings of a bundle.
	o := bundleOpts()
	o.MinSeverity = "high"
	res, err = newMemBundle(minimal(map[string]string{"nuclei_output/medium_json.txt": good})).parse(o)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Report.Findings) != 0 {
		t.Error("MinSeverity did not apply")
	}
}

func TestBundle_EmailInURLIsTemplatedAway(t *testing.T) {
	res, err := newMemBundle(minimal(map[string]string{"webs/url_extract.txt": "https://www.example.com/u/jane.doe@example.com/inbox?mail=jane.doe@example.com\n"})).parse(bundleOpts())
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(res.Report)
	if strings.Contains(string(b), "jane.doe") {
		t.Errorf("an address in a URL reached the report: %s", b)
	}
	if len(res.Report.Endpoints) != 1 {
		t.Errorf("endpoints %+v", res.Report.Endpoints)
	}
}

func TestBundle_RecordCaps(t *testing.T) {
	o := bundleOpts()
	o.Limits = Limits{MaxAssets: 3, MaxEndpoints: 2}
	var urls strings.Builder
	for i := 0; i < 50; i++ {
		urls.WriteString("https://www.example.com/p" + strings.Repeat("x", i+1) + "\n")
	}
	var subs strings.Builder
	for i := 0; i < 50; i++ {
		subs.WriteString(strings.Repeat("a", i+1) + ".example.com\n")
	}
	res, err := newMemBundle(minimal(map[string]string{"webs/url_extract.txt": urls.String(), "subdomains/subdomains.txt": subs.String()})).parse(o)
	if err != nil && !errors.Is(err, ErrTooLarge) {
		t.Fatal(err)
	}
	if err == nil && (len(res.Report.Endpoints) > 2 || len(res.Report.Assets) > 3) {
		t.Errorf("caps not applied: %d assets, %d endpoints", len(res.Report.Assets), len(res.Report.Endpoints))
	}
}

func TestBundle_ContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var subs strings.Builder
	for i := 0; i < 20000; i++ {
		subs.WriteString("h" + strings.Repeat("a", i%50) + ".example.com\n")
	}
	_, err := ParseBundle(ctx, newMemBundle(minimal(map[string]string{"subdomains/subdomains.txt": subs.String()})).files, bundleOpts())
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Errorf("err %v, want context.Canceled", err)
	}
}

// FuzzParseBundle drives the bundle reader with arbitrary content for one
// mapped file at a time (and, for the last selector, with an arbitrary ZIP),
// beside the layout markers.
func FuzzParseBundle(f *testing.F) {
	paths := []string{
		"report/report.json", ".log/run.txt", "subdomains/subdomains.txt", "hosts/ips.txt", "hosts/cdn_providers.txt",
		"hosts/naabu.txt", "webs/web_full_info.txt", "webs/webs.txt", "webs/webs_wafs.txt", "webs/url_extract.txt",
		"js/js_endpoints.txt", "webs/takeover.txt", "subdomains/s3buckets.txt", "nuclei_output/high_json.txt", "osint/emails.txt",
	}
	dir := filepath.Join(bundleFixtureRoot, "v4")
	for i, p := range paths {
		if b, err := os.ReadFile(filepath.Join(dir, p)); err == nil {
			f.Add(b, uint8(i))
		}
	}
	f.Add([]byte("PK\x03\x04"), uint8(len(paths)))
	f.Fuzz(func(t *testing.T, data []byte, sel uint8) {
		opts := Options{Now: fixedNow, Limits: Limits{MaxInputBytes: 1 << 20}, Bundle: BundleLimits{MaxFileBytes: 1 << 20, MaxTotalBytes: 4 << 20, MaxLineBytes: 4096, MaxLines: 5000}}
		var files []ArchiveFile
		if int(sel)%(len(paths)+1) == len(paths) {
			var err error
			files, err = OpenBundleZip(bytes.NewReader(data), int64(len(data)), opts.Bundle)
			if err != nil {
				checkFuzzErr(t, err)
				return
			}
		} else {
			c := minimal(nil)
			c["example.com/"+paths[int(sel)%len(paths)]] = string(data)
			files = newMemBundle(c).files
		}
		res, err := ParseBundle(context.Background(), files, opts)
		if err != nil {
			checkFuzzErr(t, err)
			return
		}
		if err := res.Report.Validate(); err != nil {
			t.Fatalf("ParseBundle returned an invalid report: %v", err)
		}
	})
}

func checkFuzzErr(t *testing.T, err error) {
	t.Helper()
	var pe *ParseError
	if !errors.As(err, &pe) && !errors.Is(err, context.Canceled) {
		t.Fatalf("error is not a *ParseError: %v", err)
	}
}
