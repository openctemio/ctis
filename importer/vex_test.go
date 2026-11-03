package importer

import "testing"

func TestPathMatch_MiddleDoubleStar(t *testing.T) {
	cases := []struct {
		pattern, path string
		want          bool
	}{
		{"/t/**/branches[]/name", "/t/branches[]/name", true},
		{"/t/**/branches[]/name", "/t/branches[]/branches[]/branches[]/name", true},
		{"/t/**/branches[]/name", "/t/branches[]/product/name", false},
		{"/t/notes*/**", "/t/notes[]/text", true},
		{"/t/notes*/**", "/t/notes", true},
	}
	for _, c := range cases {
		if got := pathMatch(c.pattern, c.path); got != c.want {
			t.Errorf("pathMatch(%q, %q) = %v, want %v", c.pattern, c.path, got, c.want)
		}
	}
}
