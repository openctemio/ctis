package validatedoc

import (
	"strings"
	"testing"
)

func TestCheck(t *testing.T) {
	const meta = `"metadata":{"id":"019a2b3c-4d5e-7000-8000-000000000001","generated_at":"2026-10-02T00:00:00Z"}`
	const ok = `{"version":"2.0",` + meta + `}`
	cases := []struct {
		name, in, cat, sub string
	}{
		{"valid", ok, "", ""},
		{"not json", `nope`, CategoryDecode, "invalid character"},
		{"unknown member", `{"version":"2.0","bogus":1}`, CategoryDecode, "bogus"},
		{"trailing data", ok + ` {}`, CategoryDecode, "invalid character"},
		{"old major", `{"version":"1.6","metadata":{"timestamp":"2026-10-02T00:00:00Z"}}`, CategoryVersion, "upgrade the producer"},
		{"future major", `{"version":"3.0",` + meta + `}`, CategoryVersion, `"3.0"`},
		{"future minor", `{"version":"2.99",` + meta + `}`, CategoryVersion, `"2.99"`},
		{"missing version", `{` + meta + `}`, CategoryVersion, "required"},
		{"semantic", `{"version":"2.0",` + meta + `,"findings":[{"type":"vulnerability","title":"t","severity":"high","asset_ref":"x"}]}`, CategoryValidate, "asset_ref"},
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
