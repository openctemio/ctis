package fingerprint

import "testing"

// The vectors pin the algorithm: the receiver (the OpenCTEM platform)
// computes the same values from a snippet, so a change here re-keys every
// SAST finding keyed by a hash.
func TestSnippetHash_Vectors(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"one line", "os.system(cmd)", "3983deb711f566537fe2c1c9aa678e6a"},
		{"indent and trailing space ignored", "\t  os.system(cmd)   ", "3983deb711f566537fe2c1c9aa678e6a"},
		{"CRLF and empty lines ignored", "\r\nos.system(cmd)\r\n\r\n", "3983deb711f566537fe2c1c9aa678e6a"},
		{"inner runs collapse", "os.system(  cmd)", SnippetHash("os.system( cmd)")},
		{"empty", "  \n\t\n", ""},
		{"two lines", "a\nb", "7e18f737311b2dc3b2f269dd78396b03"},
		{"no-break space is not ASCII whitespace", "x\u00a0 y", "f2c75c3a61c508182c14848e59b49fff"},
		{"vertical tab is", " a\vb ", "98992d7f2eec732149414be555d6c3ae"},
	}
	for _, c := range cases {
		if got := SnippetHash(c.in); got != c.want {
			t.Errorf("%s: SnippetHash(%q) = %q, want %q", c.name, c.in, got, c.want)
		}
	}
}

func TestSnippetHash_LinesStayDistinct(t *testing.T) {
	if SnippetHash("a\nb") == SnippetHash("a b") {
		t.Fatal("a line break must not be folded into a space")
	}
	if SnippetHash("os.system(cmd)") == SnippetHash("os.system(safe)") {
		t.Fatal("edited code must change the hash")
	}
	if len(SnippetHash("x")) != 32 {
		t.Fatal("the hash is 32 hex characters")
	}
}
