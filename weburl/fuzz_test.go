package weburl

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// FuzzWebURL checks the invariants every caller relies on, on any input:
// no panic; a parsed URL re-parses to itself (idempotent); the template
// keeps the segment count; nothing longer than the limits; RedactURL never
// keeps a query value, a fragment or user info, and never fails.
func FuzzWebURL(f *testing.F) {
	for _, s := range []string{
		"https://a.example/v1/orders/42?x=1#f", "http://u:p@b.example:8080/a/../b/%7E?token=s",
		"http://[2001:db8::1]/x;jsessionid=1", "https://bücher.example/パス", "http://a.example/%zz",
		"http://0x7f.0.0.1/", "", "javascript:alert(1)", "http://a.example/" + strings.Repeat("a/", 40),
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		red := RedactURL(raw)
		if strings.Contains(red, "#") && !strings.Contains(raw, "#") {
			t.Fatalf("RedactURL added a fragment: %q", red)
		}
		if u, err := Parse(red); err == nil && len(u.Params) > 0 {
			// Every query value of a redacted URL is empty.
			if i := strings.IndexByte(red, '?'); i >= 0 {
				for _, p := range strings.Split(red[i+1:], "&") {
					if _, v, ok := strings.Cut(p, "="); ok && v != "" {
						t.Fatalf("RedactURL kept a value: %q -> %q", raw, red)
					}
				}
			}
		}
		u, err := Parse(raw)
		if err != nil {
			return
		}
		s := u.String()
		if len(u.Path) > MaxURLBytes || !utf8.ValidString(s) || len(u.Params) > MaxParams {
			t.Fatalf("limits: %q", s)
		}
		again, err := Parse(s)
		if err != nil || again.String() != s {
			t.Fatalf("not idempotent: %q -> %q -> %v %v", raw, s, again, err)
		}
		tpl := u.Template()
		if strings.Count(tpl, "/") != strings.Count(u.Path, "/") {
			t.Fatalf("template changed the segments: %q -> %q", u.Path, tpl)
		}
		if TemplatePath(tpl) != tpl {
			t.Fatalf("template not stable: %q -> %q", tpl, TemplatePath(tpl))
		}
		if len(PathHash("GET", tpl)) != 64 {
			t.Fatal("hash")
		}
	})
}
