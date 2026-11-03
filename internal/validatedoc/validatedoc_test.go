package validatedoc

import (
	"strings"
	"testing"
)

func TestCheck(t *testing.T) {
	const ok = `{"version":"1.3","metadata":{"timestamp":"2026-10-02T00:00:00Z"}}`
	cases := []struct {
		name, in, cat, sub string
	}{
		{"valid", ok, "", ""},
		{"not json", `nope`, CategoryDecode, "invalid character"},
		{"unknown member", `{"version":"1.3","bogus":1}`, CategoryDecode, "bogus"},
		{"trailing data", ok + ` {}`, CategoryDecode, "after the report"},
		{"future major", `{"version":"2.0","metadata":{"timestamp":"2026-10-02T00:00:00Z"}}`, CategoryVersion, `"2.0"`},
		{"future minor", `{"version":"1.99","metadata":{"timestamp":"2026-10-02T00:00:00Z"}}`, CategoryVersion, `"1.99"`},
		{"missing version", `{"metadata":{"timestamp":"2026-10-02T00:00:00Z"}}`, CategoryVersion, `""`},
		{"semantic", `{"version":"1.3","metadata":{"timestamp":"2026-10-02T00:00:00Z"},"findings":[{"type":"vulnerability","title":"t","severity":"high","asset_ref":"x"}]}`, CategoryValidate, "asset_ref"},
	}
	for _, c := range cases {
		p := Check([]byte(c.in))
		switch {
		case c.cat == "" && p != nil:
			t.Errorf("%s: unexpected %v", c.name, p)
		case c.cat != "" && (p == nil || p.Category != c.cat || !strings.Contains(p.Message, c.sub)):
			t.Errorf("%s: got %v, want %s containing %q", c.name, p, c.cat, c.sub)
		}
	}
}
