package ctis

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestRedactCodeSecrets(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"plain code is kept", `db.query("SELECT * FROM t WHERE id = " + req.query.id)`, `db.query("SELECT * FROM t WHERE id = " + req.query.id)`},
		{"long identifiers are kept", `String userInput = request.getParameterValues("name")[0];`, `String userInput = request.getParameterValues("name")[0];`},
		{"password assignment", `password = "hunter2hunter2"`, `password = "REDACTED"`},
		{"api key json", `{"apiKey": "abcd1234efgh5678ijkl"}`, `{"apiKey": "abcd********"}`},
		{"go short assignment", `clientSecret := "s3cr3t-value-abcdefg"`, `clientSecret := "s3cr********"`},
		{"placeholder kept", `password = "${DB_PASSWORD}"`, `password = "${DB_PASSWORD}"`},
		{"masked kept", `token = "****"`, `token = "****"`},
		{"url user info", `connect("mysql://app:pa55word@db:3306/x")`, `connect("mysql://app:REDACTED@db:3306/x")`},
		{"aws key bare", `key := AKIAIOSFODNN7EXAMPLE`, `key := AKIA********`},
		{"github token", `auth(ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789)`, `auth(ghp_********)`},
		{"private key", "k = `-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----`", "k = `-----BEGIN PRIVATE KEY-----REDACTED-----END PRIVATE KEY-----`"},
		{"getter call is no assignment", `token := r.Header.Get("X-Token-Value")`, `token := r.Header.Get("X-Token-Value")`},
		{"empty", ``, ``},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := RedactCodeSecrets(c.in); got != c.want {
				t.Errorf("got  %q\nwant %q", got, c.want)
			}
			if again := RedactCodeSecrets(RedactCodeSecrets(c.in)); again != c.want {
				t.Errorf("not idempotent: %q", again)
			}
		})
	}
}

func TestNormalizeDataFlow_Paths(t *testing.T) {
	cases := []struct {
		name  string
		path  string
		roots []string
		other string // a relative path elsewhere in the flow
		want  string
	}{
		{"relative kept", "src/a.go", nil, "", "src/a.go"},
		{"dot segments cleaned", "./src/../src/a.go", nil, "", "src/a.go"},
		{"leaving the repository dropped", "../etc/passwd", nil, "", ""},
		{"backslashes", `src\win\a.cs`, nil, "", "src/win/a.cs"},
		{"percent-encoded", "src/my%20file.js", nil, "", "src/my file.js"},
		{"file uri under root", "file:///home/runner/work/r/r/src/a.go", []string{"file:///home/runner/work/r/r/"}, "", "src/a.go"},
		{"absolute under root without slash", "/build/src/a.go", []string{"/build"}, "", "src/a.go"},
		{"absolute, no root, dropped", "/home/runner/work/r/r/src/a.go", nil, "", ""},
		{"absolute inferred from a relative step", "/tmp/ci-1234/src/a.go", nil, "src/a.go", "src/a.go"},
		{"root is not a prefix of a sibling", "/buildx/src/a.go", []string{"/build"}, "", ""},
		{"windows file uri", "file:///C:/agent/_work/1/s/src/a.cs", []string{"file:///C:/agent/_work/1/s/"}, "", "src/a.cs"},
		{"http uri dropped", "https://example.test/a.js", nil, "", ""},
		{"control character dropped", "src/a\x00.go", nil, "", ""},
		{"over-long dropped", strings.Repeat("a/", MaxDataFlowPathLen) + "x.go", nil, "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			df := &DataFlow{Sources: []DataFlowLocation{{Path: c.path, Line: 3}}}
			if c.other != "" {
				df.Sinks = []DataFlowLocation{{Path: c.other, Line: 9, Index: 1}}
			}
			got := NormalizeDataFlow(df, c.roots...)
			if got == nil || len(got.Sources) != 1 {
				t.Fatalf("flow lost: %+v", got)
			}
			if got.Sources[0].Path != c.want {
				t.Errorf("path %q, want %q", got.Sources[0].Path, c.want)
			}
			if got.Sources[0].Line != 3 {
				t.Errorf("the step is kept when its path is dropped: %+v", got.Sources[0])
			}
		})
	}
}

func TestNormalizeDataFlow_Bounds(t *testing.T) {
	if NormalizeDataFlow(nil) != nil || NormalizeDataFlow(&DataFlow{}) != nil {
		t.Fatal("an empty flow is nil")
	}
	df := &DataFlow{Confidence: 900}
	for i := 0; i < 3*MaxDataFlowSteps; i++ {
		df.Intermediates = append(df.Intermediates, DataFlowLocation{
			Path: "a.go", Line: -i, Column: 1 << 40, Index: 3*MaxDataFlowSteps - i,
			Content: strings.Repeat("x", 10*MaxDataFlowContentLen),
			Label:   strings.Repeat("l\x01", MaxDataFlowLabelLen),
		})
	}
	df.Sinks = []DataFlowLocation{{Path: "b.go", Line: 1, Index: -1}}
	got := NormalizeDataFlow(df)
	steps := got.GetFullPath()
	if n := len(got.Sources) + len(got.Intermediates) + len(got.Sanitizers) + len(got.Sinks); n != MaxDataFlowSteps {
		t.Fatalf("steps %d, want %d", n, MaxDataFlowSteps)
	}
	if len(got.Sinks) != 1 || got.Sinks[0].Index != 0 {
		t.Errorf("the lowest index comes first: %+v", got.Sinks)
	}
	for _, s := range steps {
		if utf8.RuneCountInString(s.Content) > MaxDataFlowContentLen || utf8.RuneCountInString(s.Label) > MaxDataFlowLabelLen {
			t.Fatalf("text not cut: %d %d", len(s.Content), len(s.Label))
		}
		if strings.ContainsRune(s.Label, '\x01') || s.Line < 0 || s.Column != 0 {
			t.Fatalf("not cleaned: %+v", s)
		}
	}
	if got.Confidence != 0 || got.IsTainted || !got.IsCrossFile {
		t.Errorf("flags: confidence %d tainted %v cross_file %v", got.Confidence, got.IsTainted, got.IsCrossFile)
	}
}
