package weburl

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite testdata goldens")

func TestPunycode(t *testing.T) {
	cases := map[string]string{
		"bücher":       "xn--bcher-kva",
		"münchen":      "xn--mnchen-3ya",
		"ドメイン名例":       "xn--eckwd4c7cu47r2wf",
		"example":      "example",
		"пример":       "xn--e1afmkfd",
		"faß":          "xn--fa-hia",
		"日本語":          "xn--wgv71a119e",
		"bücher-store": "xn--bcher-store-thb",
	}
	for in, want := range cases {
		got, err := punycodeLabel(in)
		if err != nil || got != want {
			t.Errorf("punycodeLabel(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := punycodeLabel(strings.Repeat("ü", 70)); err == nil {
		t.Error("a label over 63 bytes once encoded must fail")
	}
	if _, err := punycodeLabel("\xff\xfe"); err == nil {
		t.Error("invalid UTF-8 must fail")
	}
}

func TestParse(t *testing.T) {
	u, err := Parse("HTTPS://Shop.Example.COM.:443/a//b/./c/../D/?b=2&a=1&a=3&=x&c#frag")
	if err != nil {
		t.Fatal(err)
	}
	if u.Origin() != "https://shop.example.com" || u.Path != "/a/b/D" || strings.Join(u.Params, ",") != "a,b,c" {
		t.Fatalf("parsed %+v origin %s", u, u.Origin())
	}
	if u.String() != "https://shop.example.com/a/b/D" {
		t.Fatal(u.String())
	}
	u, _ = Parse("http://[2001:DB8::1]:8080/x/")
	if u.Origin() != "http://[2001:db8::1]:8080" || u.Path != "/x" {
		t.Fatalf("ipv6: %s%s", u.Origin(), u.Path)
	}
	u, _ = Parse("http://bücher.example/")
	if u.Host != "xn--bcher-kva.example" || u.Path != "/" {
		t.Fatalf("idna: %+v", u)
	}
	for in, want := range map[string]string{
		"http://a.example/%7Euser/%2fx/%41b%c3%a9":         "/~user/%2Fx/Ab%C3%A9",
		"http://a.example/app;JSESSIONID=ABC123/x":         "/app/x",
		"http://a.example/app;jsessionid=1;v=2":            "/app;v=2",
		"http://a.example/x;jsessionid=a;JSESSIONID=b;v=1": "/x;v=1",
		"http://a.example/../../etc":                       "/etc",
		"http://a.example":                                 "/",
		"http://a.example/%2E%2E/x":                        "/x",
	} {
		u, err := Parse(in)
		if err != nil || u.Path != want {
			t.Errorf("Parse(%q).Path = %v %v, want %q", in, u, err, want)
		}
	}
}

func TestParseRefusals(t *testing.T) {
	for _, in := range []string{
		"", "example.com/x", "ftp://a.example/", "javascript:alert(1)", "http:///x",
		"http://user:pass@a.example/", "http://a.example/x\n", "http://a.example/a b",
		"http://a.example/\u202e", "http://a.example:0/", "http://a.example:99999/", "http://a.example:080/",
		"http://a.example/%zz", "http://a.example/%4", "http://-bad.example/", "http://a..example/",
		"http://" + strings.Repeat("a", 64) + ".example/", "http://a.example/" + strings.Repeat("x", MaxURLBytes),
		"http://a.example/\xff", "http://a!b.example/", "mailto:a@b.example",
		"http://0x7f.0.0.1/", "http://2130706433/", "http://a.example/%00", "http://a.example/x%7F",
	} {
		if u, err := Parse(in); err == nil || !errors.Is(err, ErrInvalid) {
			t.Errorf("Parse(%q) = %+v, %v; want ErrInvalid", in, u, err)
		}
	}
	if _, err := Normalize("nope"); err == nil {
		t.Fatal("Normalize must refuse")
	}
	if _, _, _, err := Template("nope"); err == nil {
		t.Fatal("Template must refuse")
	}
	if _, err := NormalizePath(strings.Repeat("a", MaxURLBytes+1)); err == nil {
		t.Fatal("a long path must be refused")
	}
}

func TestTemplateSegment(t *testing.T) {
	cases := map[string]string{
		"42":                                   VarInt,
		"8f14e45f-ceea-467a-9575-0d1a2b3c4d5e": VarUUID,
		"2026-10-07":                           VarDate,
		"alice@example.com":                    VarEmail,
		"alice%40example.com":                  VarEmail,
		"d41d8cd98f00b204e9800998ecf8427e":     VarHex,
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln": VarToken,
		"Zx9QkLm3PqR7sT2vWy8aBc":                    VarToken,
		"a1b2c3d4e5f6":                              VarID,
		"orders":                                    "orders",
		"this-is-a-long-article-slug-2024":          "this-is-a-long-article-slug-2024",
		"v1":                                        "v1",
		"index.html":                                "index.html",
		"":                                          "",
		"releasenotes":                              "releasenotes",
	}
	for in, want := range cases {
		if got := TemplateSegment(in); got != want {
			t.Errorf("TemplateSegment(%q) = %q, want %q", in, got, want)
		}
	}
	o, tpl, params, err := Template("https://api.example.com/v1/orders/42/items/8f14e45f-ceea-467a-9575-0d1a2b3c4d5e?token=x")
	if err != nil || o != "https://api.example.com" || tpl != "/v1/orders/{int}/items/{uuid}" || strings.Join(params, ",") != "token" {
		t.Fatalf("Template = %q %q %v %v", o, tpl, params, err)
	}
}

func TestQueryNames(t *testing.T) {
	if QueryNames("") != nil {
		t.Fatal("empty")
	}
	got := QueryNames("b=1&a=2&a=3&%61b=x&=v&%zz=1&ctl%0A=1&" + strings.Repeat("n", MaxParamNameBytes+1) + "=1")
	if strings.Join(got, ",") != "%zz,a,ab,b,ctl" {
		t.Fatalf("names %v", got)
	}
	var many []string
	for i := 0; i < MaxParams+20; i++ {
		many = append(many, strings.Repeat("p", 1+i%50)+string(rune('a'+i%26))+"=1")
	}
	if n := len(QueryNames(strings.Join(many, "&"))); n > MaxParams {
		t.Fatalf("%d names", n)
	}
}

func TestRedactURL(t *testing.T) {
	cases := map[string]string{
		"https://u:p@a.example/x?api_key=sk-1&page=2#access_token=t": "https://a.example/x?api_key=&page=",
		"https://a.example/x":                      "https://a.example/x",
		"https://a.example/x?":                     "https://a.example/x",
		"https://u:p@a.example/%zz?token=secret#f": "https://a.example/%zz",
		"not a url ?secret=1":                      "not%20a%20url%20?secret=",
		"https://a.example/x?flag":                 "https://a.example/x?flag=",
	}
	for in, want := range cases {
		if got := RedactURL(in); got != want {
			t.Errorf("RedactURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMethodsAndPathHash(t *testing.T) {
	if m, ok := NormalizeMethod(" post "); m != "POST" || !ok {
		t.Fatal("POST")
	}
	if m, ok := NormalizeMethod(""); m != MethodAny || !ok {
		t.Fatal("ANY")
	}
	if _, ok := NormalizeMethod("BREW"); ok {
		t.Fatal("BREW is not a method")
	}
	a, b := PathHash("get", "/v1/orders/{int}"), PathHash("GET", "/v1/orders/{int}")
	if a != b || len(a) != 64 || a == PathHash("POST", "/v1/orders/{int}") || a == PathHash("GET", "/v1/order/{int}") {
		t.Fatal("PathHash")
	}
}

// goldenCase is one line of testdata/urls.golden.json.
type goldenCase struct {
	In       string   `json:"in"`
	Origin   string   `json:"origin,omitempty"`
	Path     string   `json:"path,omitempty"`
	Template string   `json:"template,omitempty"`
	Params   []string `json:"params,omitempty"`
	Redacted string   `json:"redacted"`
	Error    bool     `json:"error,omitempty"`
}

// The corpus (testdata/urls.txt, one URL per line, Go-quoted) and its
// golden results. Run with -update after a deliberate change and review the
// diff.
func TestGoldenCorpus(t *testing.T) {
	f, err := os.Open(filepath.Join("testdata", "urls.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var got []goldenCase
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var in string
		if err := json.Unmarshal([]byte(line), &in); err != nil {
			t.Fatalf("corpus line %q: %v", line, err)
		}
		c := goldenCase{In: in, Redacted: RedactURL(in)}
		if u, err := Parse(in); err != nil {
			c.Error = true
		} else {
			c.Origin, c.Path, c.Template, c.Params = u.Origin(), u.Path, u.Template(), u.Params
		}
		got = append(got, c)
	}
	if len(got) < 200 {
		t.Fatalf("corpus has %d URLs, want at least 200", len(got))
	}
	b, _ := json.MarshalIndent(got, "", "  ")
	b = append(b, '\n')
	golden := filepath.Join("testdata", "urls.golden.json")
	if *update {
		if err := os.WriteFile(golden, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if string(want) != string(b) {
		t.Fatal("weburl output differs from testdata/urls.golden.json; run go test ./weburl -run TestGoldenCorpus -update and review")
	}
	// Invariants over the whole corpus.
	for _, c := range got {
		if strings.Contains(c.Redacted, "secret") || strings.Contains(c.Redacted, "hunter2") {
			t.Errorf("RedactURL kept a credential: %q -> %q", c.In, c.Redacted)
		}
		if !c.Error {
			again, err := Parse(c.Origin + c.Path)
			if err != nil || again.Path != c.Path || again.Origin() != c.Origin {
				t.Errorf("not idempotent: %q -> %q%q", c.In, c.Origin, c.Path)
			}
		}
	}
}
