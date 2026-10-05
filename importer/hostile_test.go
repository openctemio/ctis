package importer

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// Hostile input. Every case must fail closed, fast, with the right error
// kind, and without touching the network or the filesystem.

func parseString(t *testing.T, in string, opts Options) (*Result, error) {
	t.Helper()
	return Parse(context.Background(), strings.NewReader(in), opts)
}

// pos is where a ParseError points.
type pos struct{ Line, Column int }

func wantKind(t *testing.T, err, kind error) pos {
	t.Helper()
	if err == nil {
		t.Fatalf("want an error wrapping %v, got none", kind)
	}
	if !errors.Is(err, kind) {
		t.Fatalf("want an error wrapping %v, got %v", kind, err)
	}
	var pe *ParseError
	if !errors.As(err, &pe) {
		t.Fatalf("want a *ParseError, got %T", err)
	}
	return pos{pe.Line, pe.Column}
}

const nessusHead = `<?xml version="1.0"?>` + "\n"

func TestXML_RefusesInternalSubsetAndEntities(t *testing.T) {
	cases := map[string]string{
		"xxe file": nessusHead + `<!DOCTYPE NessusClientData_v2 [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<NessusClientData_v2><Report><ReportHost name="a"><ReportItem pluginID="1" severity="1" pluginName="&xxe;"/></ReportHost></Report></NessusClientData_v2>`,
		"billion laughs": nessusHead + `<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">]>
<NessusClientData_v2>&lol3;</NessusClientData_v2>`,
		"parameter entity":                   nessusHead + `<!DOCTYPE x [<!ENTITY % p SYSTEM "http://127.0.0.1:1/evil.dtd"> %p;]><NessusClientData_v2/>`,
		"entity declaration outside doctype": nessusHead + `<NessusClientData_v2><!ENTITY x "y"></NessusClientData_v2>`,
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := parseString(t, in, Options{Format: FormatNessus})
			if err == nil {
				t.Fatal("parsed a document with entity declarations")
			}
			if !errors.Is(err, ErrUnsafe) && !errors.Is(err, ErrMalformed) {
				t.Fatalf("want ErrUnsafe or ErrMalformed, got %v", err)
			}
		})
	}
}

func TestXML_UndefinedEntityRefused(t *testing.T) {
	in := nessusHead + `<NessusClientData_v2><Report><ReportHost name="a"><ReportItem pluginID="1" severity="1" pluginName="&nbsp;"/></ReportHost></Report></NessusClientData_v2>`
	pe := wantKind(t, func() error { _, err := parseString(t, in, Options{Format: FormatNessus}); return err }(), ErrMalformed)
	if pe.Line != 2 {
		t.Errorf("line = %d, want 2", pe.Line)
	}
}

// An external DTD is allowed (Qualys names one) and never fetched: a
// listener that must not be called proves it.
func TestXML_ExternalDTDNeverFetched(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("no loopback listener:", err)
	}
	defer func() { _ = ln.Close() }()
	hit := make(chan struct{}, 1)
	go func() {
		if c, err := ln.Accept(); err == nil {
			hit <- struct{}{}
			_ = c.Close()
		}
	}()
	in := nessusHead + `<!DOCTYPE NessusClientData_v2 SYSTEM "http://` + ln.Addr().String() + `/x.dtd">
<NessusClientData_v2><Report><ReportHost name="192.0.2.1"><ReportItem pluginID="1" severity="2" pluginName="t"/></ReportHost></Report></NessusClientData_v2>`
	res, err := parseString(t, in, Options{Format: FormatNessus})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Report.Findings) != 1 {
		t.Fatalf("findings = %d", len(res.Report.Findings))
	}
	select {
	case <-hit:
		t.Fatal("the parser fetched the external DTD")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestXML_DeepNesting(t *testing.T) {
	in := nessusHead + "<NessusClientData_v2>" + strings.Repeat("<a>", 100_000) + strings.Repeat("</a>", 100_000) + "</NessusClientData_v2>"
	start := time.Now()
	_, err := parseString(t, in, Options{Format: FormatNessus})
	wantKind(t, err, ErrTooLarge)
	if time.Since(start) > 5*time.Second {
		t.Fatal("deep nesting took too long to refuse")
	}
}

func TestXML_Limits(t *testing.T) {
	t.Run("input size", func(t *testing.T) {
		in := nessusHead + "<NessusClientData_v2>" + strings.Repeat(" ", 4096) + "</NessusClientData_v2>"
		_, err := parseString(t, in, Options{Format: FormatNessus, Limits: Limits{MaxInputBytes: 1024}})
		wantKind(t, err, ErrTooLarge)
	})
	t.Run("input exactly at the limit", func(t *testing.T) {
		in := nessusHead + "<NessusClientData_v2></NessusClientData_v2>"
		if _, err := parseString(t, in, Options{Format: FormatNessus, Limits: Limits{MaxInputBytes: int64(len(in))}}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("attributes", func(t *testing.T) {
		var b strings.Builder
		for i := 0; i < 100; i++ {
			b.WriteString(` a` + strings.Repeat("x", i) + `="1"`)
		}
		in := nessusHead + "<NessusClientData_v2" + b.String() + "/>"
		_, err := parseString(t, in, Options{Format: FormatNessus})
		wantKind(t, err, ErrTooLarge)
	})
	t.Run("text", func(t *testing.T) {
		in := nessusHead + "<NessusClientData_v2><Report><ReportHost name=\"a\"><ReportItem pluginID=\"1\" severity=\"1\"><plugin_output>" + strings.Repeat("A", 4096) + "</plugin_output></ReportItem></ReportHost></Report></NessusClientData_v2>"
		_, err := parseString(t, in, Options{Format: FormatNessus, Limits: Limits{MaxTextBytes: 1024}})
		wantKind(t, err, ErrTooLarge)
	})
	t.Run("elements", func(t *testing.T) {
		in := nessusHead + "<NessusClientData_v2>" + strings.Repeat("<x/>", 1000) + "</NessusClientData_v2>"
		_, err := parseString(t, in, Options{Format: FormatNessus, Limits: Limits{MaxElements: 100}})
		wantKind(t, err, ErrTooLarge)
	})
	t.Run("findings", func(t *testing.T) {
		in := nessusHead + "<NessusClientData_v2><Report><ReportHost name=\"192.0.2.1\">" + strings.Repeat(`<ReportItem pluginID="1" severity="2" pluginName="t"/>`, 10) + "</ReportHost></Report></NessusClientData_v2>"
		_, err := parseString(t, in, Options{Format: FormatNessus, Limits: Limits{MaxFindings: 5}})
		wantKind(t, err, ErrTooLarge)
	})
	t.Run("assets", func(t *testing.T) {
		var b strings.Builder
		for i := 0; i < 10; i++ {
			b.WriteString(`<ReportHost name="h` + strings.Repeat("x", i) + `"/>`)
		}
		in := nessusHead + "<NessusClientData_v2><Report>" + b.String() + "</Report></NessusClientData_v2>"
		_, err := parseString(t, in, Options{Format: FormatNessus, Limits: Limits{MaxAssets: 3}})
		wantKind(t, err, ErrTooLarge)
	})
}

func TestXML_Encodings(t *testing.T) {
	t.Run("invalid UTF-8", func(t *testing.T) {
		in := nessusHead + "<NessusClientData_v2><Report><ReportHost name=\"a\">\n<ReportItem pluginID=\"1\" severity=\"1\" pluginName=\"bad \xff\xfe\"/></ReportHost></Report></NessusClientData_v2>"
		pe := wantKind(t, func() error { _, err := parseString(t, in, Options{Format: FormatNessus}); return err }(), ErrMalformed)
		if pe.Line != 3 {
			t.Errorf("line = %d, want 3", pe.Line)
		}
	})
	t.Run("UTF-16 declared", func(t *testing.T) {
		in := `<?xml version="1.0" encoding="UTF-16"?><NessusClientData_v2/>`
		_, err := parseString(t, in, Options{Format: FormatNessus})
		wantKind(t, err, ErrUnsafe)
	})
	t.Run("US-ASCII declared", func(t *testing.T) {
		in := `<?xml version="1.0" encoding="US-ASCII"?><NessusClientData_v2><Report><ReportHost name="192.0.2.1"><ReportItem pluginID="1" severity="2" pluginName="t"/></ReportHost></Report></NessusClientData_v2>`
		if _, err := parseString(t, in, Options{Format: FormatNessus}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("control characters are removed from values", func(t *testing.T) {
		in := nessusHead + "<NessusClientData_v2><Report><ReportHost name=\"192.0.2.1\"><ReportItem pluginID=\"1\" severity=\"2\" pluginName=\"t\"><plugin_output>a&#x9b;31mred</plugin_output></ReportItem></ReportHost></Report></NessusClientData_v2>"
		res, err := parseString(t, in, Options{Format: FormatNessus})
		if err != nil {
			t.Fatal(err)
		}
		if got := res.Report.Findings[0].Evidence; strings.ContainsRune(got, 0x9b) {
			t.Fatalf("evidence kept an escape character: %q", got)
		}
	})
}

func TestXML_MalformedHasLineNumber(t *testing.T) {
	in := nessusHead + "<NessusClientData_v2>\n<Report>\n<ReportHost name=\"a\">\n<ReportItem pluginID=\"1\"\n</Report></NessusClientData_v2>"
	_, err := parseString(t, in, Options{Format: FormatNessus})
	pe := wantKind(t, err, ErrMalformed)
	if pe.Line < 4 {
		t.Fatalf("line = %d, want the broken element's line (>= 4)", pe.Line)
	}
	if !strings.Contains(err.Error(), "line") {
		t.Fatalf("message has no line: %v", err)
	}
}

func TestXML_WrongRoot(t *testing.T) {
	_, err := parseString(t, nessusHead+"<html><body/></html>", Options{Format: FormatNessus})
	wantKind(t, err, ErrMalformed)
	_, err = parseString(t, nessusHead, Options{Format: FormatNessus})
	wantKind(t, err, ErrMalformed)
}

func TestNessus_CredentialsNeverInOutput(t *testing.T) {
	res, _ := runFixture(t, fixture{format: FormatNessus, path: fixtureRoot + "/nessus/scan.nessus"})
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(res); err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"svc-scan", "hunter2", "EXAMPLE\\\\svc-scan", "SSH password"} {
		if bytes.Contains(buf.Bytes(), []byte(secret)) {
			t.Errorf("output holds %q", secret)
		}
	}
}

func TestRedactCredentials(t *testing.T) {
	cases := map[string]string{
		"Credentialed checks : yes, as 'root' via ssh": "Credentialed checks : yes, as '[redacted]' via ssh",
		"User: admin\nOther: keep":                     "User: [redacted]\nOther: keep",
		"  Login = jdoe":                               "  Login = [redacted]",
		"password=s3cret rest":                         "password=[redacted] rest",
		"SNMP community: public":                       "SNMP community: [redacted]",
		"api_key: abc123":                              "api_key: [redacted]",
		"nothing here":                                 "nothing here",
	}
	for in, want := range cases {
		if got := redactCredentials(in); got != want {
			t.Errorf("redactCredentials(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestJSON_Scan(t *testing.T) {
	lim := DefaultLimits()
	t.Run("deep nesting", func(t *testing.T) {
		in := strings.Repeat("[", 100_000) + strings.Repeat("]", 100_000)
		_, err := scanJSON([]byte(in), FormatDefectDojo, lim, newObserver(10))
		wantKind(t, err, ErrTooLarge)
	})
	t.Run("invalid UTF-8 with line", func(t *testing.T) {
		in := "{\n\"a\": \"ok\",\n\"b\": \"\xff\"\n}"
		_, err := scanJSON([]byte(in), FormatDefectDojo, lim, newObserver(10))
		pe := wantKind(t, err, ErrMalformed)
		if pe.Line != 3 {
			t.Errorf("line = %d, want 3", pe.Line)
		}
	})
	t.Run("syntax error with line", func(t *testing.T) {
		in := "{\n\"a\": 1,\n\"b\": ,\n}"
		_, err := scanJSON([]byte(in), FormatDefectDojo, lim, newObserver(10))
		pe := wantKind(t, err, ErrMalformed)
		if pe.Line != 3 {
			t.Errorf("line = %d, want 3", pe.Line)
		}
	})
	t.Run("trailing value", func(t *testing.T) {
		_, err := scanJSON([]byte(`{"a":1} {"b":2}`), FormatDefectDojo, lim, newObserver(10))
		wantKind(t, err, ErrMalformed)
	})
	t.Run("empty", func(t *testing.T) {
		_, err := scanJSON([]byte("  "), FormatDefectDojo, lim, newObserver(10))
		wantKind(t, err, ErrMalformed)
	})
	t.Run("long string", func(t *testing.T) {
		l := lim
		l.MaxTextBytes = 10
		_, err := scanJSON([]byte(`{"a":"`+strings.Repeat("x", 100)+`"}`), FormatDefectDojo, l, newObserver(10))
		wantKind(t, err, ErrTooLarge)
	})
	t.Run("paths and element lines", func(t *testing.T) {
		in := "{\n \"findings\": [\n  {\"title\": \"a\"},\n  {\"title\": \"b\", \"tags\": [\"x\"]}\n ]\n}"
		obs := newObserver(100)
		doc, err := scanJSON([]byte(in), FormatDefectDojo, lim, obs, "/findings[]")
		if err != nil {
			t.Fatal(err)
		}
		got := strings.Join(obs.paths(), ",")
		want := "/findings,/findings[],/findings[]/tags,/findings[]/tags[],/findings[]/title"
		if got != want {
			t.Errorf("paths = %s, want %s", got, want)
		}
		is := doc.issueAt("/findings[]", 1, "/findings/1", "x")
		if is.Line != 4 || is.Column != 3 {
			t.Errorf("element 1 at %d:%d, want 4:3", is.Line, is.Column)
		}
	})
	t.Run("type error with line", func(t *testing.T) {
		in := "{\n\"findings\": \"not a list\"\n}"
		doc, err := scanJSON([]byte(in), FormatDefectDojo, lim, newObserver(10))
		if err != nil {
			t.Fatal(err)
		}
		var v struct {
			Findings []string `json:"findings"`
		}
		pe := wantKind(t, doc.decode(&v), ErrMalformed)
		if pe.Line != 2 {
			t.Errorf("line = %d, want 2", pe.Line)
		}
	})
}

func TestReadAll(t *testing.T) {
	data, err := readAll(strings.NewReader("\xEF\xBB\xBF{}"), FormatDefectDojo, Limits{MaxInputBytes: 10})
	if err != nil || string(data) != "{}" {
		t.Fatalf("readAll = %q, %v", data, err)
	}
	_, err = readAll(strings.NewReader(strings.Repeat("x", 20)), FormatDefectDojo, Limits{MaxInputBytes: 10})
	wantKind(t, err, ErrTooLarge)
}

func makeZip(t *testing.T, files map[string][]byte, mod func(*zip.FileHeader)) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, data := range files {
		h := &zip.FileHeader{Name: name, Method: zip.Deflate}
		if mod != nil {
			mod(h)
		}
		w, err := zw.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestOpenZip(t *testing.T) {
	scan, err := os.ReadFile(fixtureRoot + "/nessus/scan.nessus")
	if err != nil {
		t.Fatal(err)
	}
	t.Run("reads regular files", func(t *testing.T) {
		z := makeZip(t, map[string][]byte{"exports/scan.nessus": scan}, nil)
		if !IsZip(z) {
			t.Fatal("IsZip = false")
		}
		files, err := OpenZip(bytes.NewReader(z), int64(len(z)), ArchiveLimits{})
		if err != nil {
			t.Fatal(err)
		}
		if len(files) != 1 || files[0].Name != "exports/scan.nessus" {
			t.Fatalf("files = %+v", files)
		}
		rc, err := files[0].Open()
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = rc.Close() }()
		res, err := Parse(context.Background(), rc, Options{})
		if err != nil {
			t.Fatal(err)
		}
		if res.Format != FormatNessus || len(res.Report.Findings) == 0 {
			t.Fatalf("parsed %s with %d findings", res.Format, len(res.Report.Findings))
		}
	})
	for name, entry := range map[string]string{
		"traversal":      "../../etc/cron.d/x",
		"inner dotdot":   "a/../../b",
		"absolute":       "/etc/passwd",
		"backslash":      "..\\..\\win.ini",
		"drive letter":   "C:/Windows/x",
		"control char":   "a\x00b",
		"nested archive": "inner.zip",
	} {
		t.Run(name, func(t *testing.T) {
			z := makeZip(t, map[string][]byte{entry: []byte("x")}, nil)
			_, err := OpenZip(bytes.NewReader(z), int64(len(z)), ArchiveLimits{})
			wantKind(t, err, ErrUnsafe)
		})
	}
	t.Run("symlink", func(t *testing.T) {
		z := makeZip(t, map[string][]byte{"link": []byte("/etc/passwd")}, func(h *zip.FileHeader) { h.SetMode(os.ModeSymlink | 0o777) })
		_, err := OpenZip(bytes.NewReader(z), int64(len(z)), ArchiveLimits{})
		wantKind(t, err, ErrUnsafe)
	})
	t.Run("too many files", func(t *testing.T) {
		files := map[string][]byte{}
		for i := 0; i < 5; i++ {
			files[string(rune('a'+i))+".json"] = []byte("{}")
		}
		z := makeZip(t, files, nil)
		_, err := OpenZip(bytes.NewReader(z), int64(len(z)), ArchiveLimits{MaxEntries: 3})
		wantKind(t, err, ErrTooLarge)
	})
	t.Run("decompression bomb", func(t *testing.T) {
		z := makeZip(t, map[string][]byte{"bomb.json": bytes.Repeat([]byte{'0'}, 64<<20)}, nil)
		files, err := OpenZip(bytes.NewReader(z), int64(len(z)), ArchiveLimits{})
		if err != nil {
			t.Fatal(err)
		}
		rc, err := files[0].Open()
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = rc.Close() }()
		_, err = io.Copy(io.Discard, rc)
		wantKind(t, err, ErrTooLarge)
	})
	t.Run("entry over the size limit", func(t *testing.T) {
		z := makeZip(t, map[string][]byte{"big.json": bytes.Repeat([]byte("ab"), 4096)}, nil)
		_, err := OpenZip(bytes.NewReader(z), int64(len(z)), ArchiveLimits{MaxEntryBytes: 1024})
		wantKind(t, err, ErrTooLarge)
	})
	t.Run("total over the limit", func(t *testing.T) {
		z := makeZip(t, map[string][]byte{"a.json": bytes.Repeat([]byte("ab"), 2048), "b.json": bytes.Repeat([]byte("cd"), 2048)}, nil)
		files, err := OpenZip(bytes.NewReader(z), int64(len(z)), ArchiveLimits{MaxTotalBytes: 6000})
		if err != nil {
			t.Fatal(err)
		}
		var last error
		for _, f := range files {
			rc, _ := f.Open()
			_, last = io.Copy(io.Discard, rc)
			_ = rc.Close()
		}
		wantKind(t, last, ErrTooLarge)
	})
	t.Run("not a zip", func(t *testing.T) {
		_, err := OpenZip(bytes.NewReader([]byte("PK\x03\x04junk")), 8, ArchiveLimits{})
		wantKind(t, err, ErrMalformed)
	})
}

func TestParse_UnknownAndCanceled(t *testing.T) {
	_, err := parseString(t, "hello", Options{})
	wantKind(t, err, ErrUnknownFormat)
	_, err = parseString(t, "<x/>", Options{Format: "nope"})
	wantKind(t, err, ErrUnknownFormat)
	_, err = parseString(t, "<x/>", Options{Format: FormatQualysKB})
	wantKind(t, err, ErrUnknownFormat)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	in := nessusHead + "<NessusClientData_v2><Report><ReportHost name=\"192.0.2.1\">" + strings.Repeat(`<ReportItem pluginID="1" severity="2" pluginName="t"/>`, 10_000) + "</ReportHost></Report></NessusClientData_v2>"
	_, err = Parse(ctx, strings.NewReader(in), Options{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
}

func TestParse_MinSeverity(t *testing.T) {
	res, err := Parse(context.Background(), mustOpen(t, fixtureRoot+"/nessus/scan.nessus"), Options{MinSeverity: "high"})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range res.Report.Findings {
		if f.Severity.Score() < 7.5 {
			t.Errorf("kept a %s finding", f.Severity)
		}
	}
	if res.Stats.Skipped == 0 {
		t.Error("nothing skipped")
	}
}

func mustOpen(t *testing.T, p string) io.Reader {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.NewReader(b)
}

func FuzzParse(f *testing.F) {
	for _, fx := range []string{"nessus/scan.nessus", "nessus/all-fields.nessus"} {
		if b, err := os.ReadFile(fixtureRoot + "/" + fx); err == nil {
			f.Add(b)
		}
	}
	f.Add([]byte(`{"findings":[{"title":"t","severity":"High"}]}`))
	f.Add([]byte(nessusHead + `<NessusClientData_v2><Report><ReportHost name="a"/></Report></NessusClientData_v2>`))
	f.Fuzz(func(t *testing.T, data []byte) {
		res, err := Parse(context.Background(), bytes.NewReader(data), Options{Limits: Limits{MaxInputBytes: 1 << 20}})
		if err != nil {
			var pe *ParseError
			if !errors.As(err, &pe) {
				t.Fatalf("error is not a *ParseError: %v", err)
			}
			return
		}
		if err := res.Report.Validate(); err != nil {
			t.Fatalf("Parse returned an invalid report: %v", err)
		}
	})
}

func FuzzDetect(f *testing.F) {
	f.Add([]byte(`{"bomFormat":"CycloneDX"}`))
	f.Add([]byte(`[{"document":{"csaf_version":"2.0"}}]`))
	f.Add([]byte(nessusHead + `<NessusClientData_v2/>`))
	f.Fuzz(func(t *testing.T, data []byte) {
		Detect(data)
	})
}
