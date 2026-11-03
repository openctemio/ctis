package ctis

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type canonicalVectorFile struct {
	Function string            `json:"function"`
	Vectors  []canonicalVector `json:"vectors"`
}

type canonicalVector struct {
	Function string          `json:"function"`
	Input    json.RawMessage `json:"input"`
	Output   json.RawMessage `json:"output"`
	Error    bool            `json:"error"`
	Note     string          `json:"note"`
}

// runCanonical applies the named function to a vector input and returns
// the result as JSON.
func runCanonical(t *testing.T, fn string, in json.RawMessage) (any, error) {
	t.Helper()
	var s string
	str := func() string {
		if err := json.Unmarshal(in, &s); err != nil {
			t.Fatalf("%s: input is not a string: %s", fn, in)
		}
		return s
	}
	switch fn {
	case "CanonicalDomain":
		return CanonicalDomain(str())
	case "CanonicalIP":
		return CanonicalIP(str())
	case "CanonicalCIDR":
		return CanonicalCIDR(str())
	case "CanonicalOrigin":
		return CanonicalOrigin(str())
	case "CanonicalURL":
		return CanonicalURL(str())
	case "CanonicalCPE":
		return CanonicalCPE(str())
	case "CanonicalARN":
		return CanonicalARN(str())
	case "CanonicalAzureResourceID":
		return CanonicalAzureResourceID(str())
	case "CanonicalGCPResourceName":
		return CanonicalGCPResourceName(str())
	case "CanonicalImage":
		return CanonicalImage(str())
	case "CanonicalCertificateFingerprint":
		return CanonicalCertificateFingerprint(str())
	case "CanonicalPurl":
		id, ver, err := CanonicalPurl(str())
		return map[string]string{"identity": id, "version": ver}, err
	case "CanonicalService":
		var v struct {
			Host      string `json:"host"`
			Port      int    `json:"port"`
			Transport string `json:"transport"`
		}
		if err := json.Unmarshal(in, &v); err != nil {
			t.Fatal(err)
		}
		return CanonicalService(v.Host, v.Port, v.Transport)
	case "AssetKey":
		var v struct {
			Type  AssetType `json:"type"`
			Value string    `json:"value"`
		}
		if err := json.Unmarshal(in, &v); err != nil {
			t.Fatal(err)
		}
		return AssetKey(v.Type, v.Value), nil
	}
	t.Fatalf("unknown function %q", fn)
	return nil, nil
}

// TestCanonicalConformance runs conformance/canonical/*.json, the vectors
// every implementation of the canonical forms must pass.
func TestCanonicalConformance(t *testing.T) {
	files, err := filepath.Glob("conformance/canonical/*.json")
	if err != nil || len(files) < 10 {
		t.Fatalf("canonical vectors missing: %v", err)
	}
	for _, name := range files {
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		var f canonicalVectorFile
		if err := json.Unmarshal(raw, &f); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for i, v := range f.Vectors {
			fn := v.Function
			if fn == "" {
				fn = f.Function
			}
			got, err := runCanonical(t, fn, v.Input)
			if v.Error {
				if err == nil {
					t.Errorf("%s[%d] %s(%s) = %v, want an error", name, i, fn, v.Input, got)
				} else if fn != "AssetKey" && !errors.Is(err, ErrNotCanonicalizable) {
					t.Errorf("%s[%d]: error does not wrap ErrNotCanonicalizable: %v", name, i, err)
				}
				continue
			}
			if err != nil {
				t.Errorf("%s[%d] %s(%s): %v", name, i, fn, v.Input, err)
				continue
			}
			gotJSON, _ := json.Marshal(got)
			var a, b any
			_ = json.Unmarshal(gotJSON, &a)
			_ = json.Unmarshal(v.Output, &b)
			if ga, gb := canonJSON(a), canonJSON(b); ga != gb {
				t.Errorf("%s[%d] %s(%s) = %s, want %s", name, i, fn, v.Input, ga, gb)
			}
		}
	}
}

func canonJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

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
