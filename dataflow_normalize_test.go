package ctis

import (
	"encoding/json"
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
	if got.Confidence != 0 || got.Tainted || !got.CrossFile {
		t.Errorf("flags: confidence %d tainted %v cross_file %v", got.Confidence, got.Tainted, got.CrossFile)
	}
}

func TestFromSARIF_CodeFlows(t *testing.T) {
	type step struct {
		Kinds   []string `json:"kinds,omitempty"`
		Message string   `json:"-"`
		Path    string   `json:"-"`
		Line    int      `json:"-"`
	}
	build := func(steps ...step) string {
		var locs []map[string]any
		for _, s := range steps {
			loc := map[string]any{"physicalLocation": map[string]any{
				"artifactLocation": map[string]any{"uri": s.Path},
				"region":           map[string]any{"startLine": s.Line},
			}}
			if s.Message != "" {
				loc["message"] = map[string]any{"text": s.Message}
			}
			tfl := map[string]any{"location": loc}
			if s.Kinds != nil {
				tfl["kinds"] = s.Kinds
			}
			locs = append(locs, tfl)
		}
		b, _ := json.Marshal([]any{map[string]any{"threadFlows": []any{map[string]any{"locations": locs}}}})
		return string(b)
	}
	roles := func(df *DataFlow) string {
		if df == nil {
			return "<nil>"
		}
		out := make([]string, len(df.GetFullPath())+len(df.Sanitizers))
		for _, l := range append(df.GetFullPath(), df.Sanitizers...) {
			out[l.Index] = string(l.Type)
		}
		return strings.Join(out, ",")
	}
	cases := []struct {
		name, flows, want string
	}{
		{"position", build(step{Path: "a", Line: 1}, step{Path: "a", Line: 2}, step{Path: "a", Line: 3}), "source,propagator,sink"},
		{"one step is the sink", build(step{Path: "a", Line: 1}), "sink"},
		{"kinds win over position", build(step{Path: "a", Line: 1, Kinds: []string{"sink"}}, step{Path: "a", Line: 2, Kinds: []string{"source"}}), "sink,source"},
		{"kinds sanitizer", build(step{Path: "a", Line: 1}, step{Path: "a", Line: 2, Kinds: []string{"taint", "sanitizer"}}, step{Path: "a", Line: 3}), "source,sanitizer,sink"},
		{"message sanitized", build(step{Path: "a", Line: 1}, step{Path: "a", Line: 2, Message: "value is sanitized here"}, step{Path: "a", Line: 3}), "source,sanitizer,sink"},
		{"semgrep messages", build(step{Path: "a", Line: 1, Message: "Source: 'x' @ 'a:1'"}, step{Path: "a", Line: 2, Message: "Propagator : 'y' @ 'a:2'"}, step{Path: "a", Line: 3, Message: "Sink: 'z' @ 'a:3'"}), "source,propagator,sink"},
		{"word prefix only", build(step{Path: "a", Line: 1, Message: "sourceFile"}, step{Path: "a", Line: 2, Message: "sinkhole"}), "source,sink"},
		{"empty locations skipped", `[{"threadFlows":[{"locations":[{"location":{}},{"location":{"physicalLocation":{"artifactLocation":{"uri":"a"},"region":{"startLine":4}}}}]}]}]`, "sink"},
		{"first non-empty thread flow", `[{"threadFlows":[{"locations":[]}]},{"threadFlows":[{"locations":[{"location":{"message":{"text":"m"}}}]}]}]`, "sink"},
		{"malformed trace", `[{"threadFlows":"nope"}]`, "<nil>"},
		{"malformed kinds", `[{"threadFlows":[{"locations":[{"kinds":"source","location":{"message":{"text":"m"}}}]}]}]`, "<nil>"},
		{"not an array", `{"a":1}`, "<nil>"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"codeql"}},"results":[{"ruleId":"r","message":{"text":"t"},"codeFlows":` + c.flows + `}]}]}`
			rep, err := FromSARIF([]byte(doc), nil)
			if err != nil {
				t.Fatalf("a trace never fails the log: %v", err)
			}
			if len(rep.Findings) != 1 {
				t.Fatalf("findings %d", len(rep.Findings))
			}
			if got := roles(rep.Findings[0].DataFlow); got != c.want {
				t.Errorf("roles %s, want %s", got, c.want)
			}
		})
	}
}

// The data flow is context: the finding's fingerprint is the same with and
// without it, and a changed trace does not change the identity.
func TestFromSARIF_CodeFlowsNotInFingerprint(t *testing.T) {
	base := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"semgrep"}},"results":[{"ruleId":"r","message":{"text":"t"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.py"},"region":{"startLine":3}}}]%s}]}]}`
	flow := `,"codeFlows":[{"threadFlows":[{"locations":[{"location":{"physicalLocation":{"artifactLocation":{"uri":"%s"},"region":{"startLine":1}}}}]}]}]`
	var fps []string
	for _, extra := range []string{"", strings.Replace(flow, "%s", "a.py", 1), strings.Replace(flow, "%s", "b.py", 1)} {
		rep, err := FromSARIF([]byte(strings.Replace(base, "%s", extra, 1)), nil)
		if err != nil || len(rep.Findings) != 1 {
			t.Fatalf("%v %+v", err, rep)
		}
		f := rep.Findings[0]
		if (extra == "") != (f.DataFlow == nil) {
			t.Fatalf("data flow presence: %+v", f.DataFlow)
		}
		fps = append(fps, f.Fingerprint+"|"+LocationKey(&f))
	}
	if fps[0] != fps[1] || fps[1] != fps[2] {
		t.Errorf("fingerprints differ with the trace: %q", fps)
	}
}

// A secret finding's raw match is masked in its data flow too.
func TestFromSARIF_CodeFlowsSecretMasked(t *testing.T) {
	const raw = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"
	doc := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"gitleaks"}},"results":[{"ruleId":"github-pat","message":{"text":"secret"},
	"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.env"},"region":{"startLine":1,"snippet":{"text":"` + raw + `"}}}}],
	"codeFlows":[{"threadFlows":[{"locations":[{"location":{"physicalLocation":{"artifactLocation":{"uri":"a.env"},"region":{"startLine":1,"snippet":{"text":"T=` + raw + `"}}},"message":{"text":"` + raw + `"}}}]}]}]}]}]}`
	rep, err := FromSARIF([]byte(doc), nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(rep.Findings[0].DataFlow)
	if ContainsSecret(string(b), raw) || rep.Findings[0].DataFlow == nil {
		t.Errorf("raw secret in data flow: %s", b)
	}
}
