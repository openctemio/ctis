package ctis

import (
	"testing"
)

// Canonical forms are idempotent: canonicalizing a canonical value returns it.
func TestCanonicalIdempotent(t *testing.T) {
	for _, in := range []string{"Example.COM.", "bücher.example", "пример.рф"} {
		a, err := CanonicalDomain(in)
		if err != nil {
			t.Fatal(err)
		}
		if b, _ := CanonicalDomain(a); b != a {
			t.Errorf("domain %q: %q then %q", in, a, b)
		}
	}
	for _, in := range []string{"https://u@Example.com/a/../B?z&a=1", "http://[2001:DB8::1]:8080/%7e"} {
		a, err := CanonicalURL(in)
		if err != nil {
			t.Fatal(err)
		}
		if b, _ := CanonicalURL(a); b != a {
			t.Errorf("url %q: %q then %q", in, a, b)
		}
	}
	a, _ := CanonicalImage("nginx:1.25")
	if b, _ := CanonicalImage(a); b != a {
		t.Errorf("image: %q then %q", a, b)
	}
}

func FuzzCanonical(f *testing.F) {
	for _, s := range []string{"Example.com", "bücher.example", "https://a/b/../c?x=1", "pkg:npm/%40a/b@1", "nginx@sha256:00", "cpe:/a:b:c"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if d, err := CanonicalDomain(s); err == nil {
			if d2, err := CanonicalDomain(d); err != nil || d2 != d {
				t.Fatalf("domain not idempotent: %q -> %q -> %q (%v)", s, d, d2, err)
			}
		}
		_, _ = CanonicalURL(s)
		_, _, _ = CanonicalPurl(s)
		_, _ = CanonicalImage(s)
		_, _ = CanonicalCPE(s)
	})
}
