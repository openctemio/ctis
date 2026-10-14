package importer

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// The semgrep and opengrep trace goes through the same bounds, path and
// redaction rules as a SARIF codeFlow.
func TestSemgrepTrace_Normalized(t *testing.T) {
	const doc = `{"version":"1.90.0","results":[{"check_id":"js.sqli","path":"src/a.js","start":{"line":9,"col":1},"end":{"line":9,"col":20},
	"extra":{"message":"m","severity":"ERROR","lines":"x","dataflow_trace":{
	  "taint_source":["CliLoc",[{"path":"/home/runner/work/r/r/src/a.js","start":{"line":3,"col":5}},"password = \"hunter2hunter2\""]],
	  "intermediate_vars":[{"location":{"path":"../../etc/passwd","start":{"line":5,"col":1}},"content":"q"}],
	  "taint_sink":["CliLoc",[{"path":"src/a.js","start":{"line":9,"col":1}},"db.query(q)"]]}}}],"errors":[]}`
	for _, format := range []Format{FormatSemgrep, FormatOpengrep} {
		res, err := Parse(context.Background(), strings.NewReader(doc), Options{Format: format})
		if err != nil {
			t.Fatal(err)
		}
		df := res.Report.Findings[0].DataFlow
		if df == nil || len(df.Sources) != 1 || len(df.Intermediates) != 1 || len(df.Sinks) != 1 {
			t.Fatalf("%s: %+v", format, df)
		}
		if df.Sources[0].Path != "src/a.js" || df.Intermediates[0].Path != "" || df.Intermediates[0].Line != 5 {
			t.Errorf("%s paths: %q %q", format, df.Sources[0].Path, df.Intermediates[0].Path)
		}
		b, _ := json.Marshal(df)
		if strings.Contains(string(b), "hunter2") {
			t.Errorf("%s: credential kept: %s", format, b)
		}
	}
}
