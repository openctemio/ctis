package importer

import (
	"context"
	"strings"
	"testing"
)

// A result of the same rule at the same place keeps one fingerprint whether
// semgrep (without a login) or opengrep reported it: the engine change does
// not turn the existing findings into new ones. opengrep's match-based id
// is kept as the partial fingerprint matchBasedId/v1.
func TestOpengrep_FingerprintContinuity(t *testing.T) {
	const result = `{"version":"1","results":[{"check_id":"py.cmd","path":"app.py",
		"start":{"line":8,"col":5},"end":{"line":8,"col":23},
		"extra":{"message":"m","severity":"ERROR","fingerprint":%q,"lines":%q,"metadata":{}}}],"errors":[]}`
	parse := func(f Format, fp, lines string) *Result {
		t.Helper()
		in := strings.Replace(result, "%q", `"`+fp+`"`, 1)
		in = strings.Replace(in, "%q", `"`+lines+`"`, 1)
		res, err := Parse(context.Background(), strings.NewReader(in), Options{Format: f, Repository: "github.com/example/shop"})
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Report.Findings) != 1 {
			t.Fatalf("%s: %d findings", f, len(res.Report.Findings))
		}
		return res
	}
	const id = "5bfdfce6cfd746168c865992e02b6876333bc4bec33c3db607bd7c61783aebb72a224102a0eed50d58bd5d22f59ddcb9d75b2976340b6a7cd8e8793ea2d397b6_0"
	sg := parse(FormatSemgrep, "requires login", "requires login")
	og := parse(FormatOpengrep, id, "    os.system(wrapped)")

	if sg.Report.Tool.Name != "semgrep" || og.Report.Tool.Name != "opengrep" {
		t.Fatalf("tools = %q, %q", sg.Report.Tool.Name, og.Report.Tool.Name)
	}
	sf, of := sg.Report.Findings[0], og.Report.Findings[0]
	if sf.Fingerprint == "" || sf.Fingerprint != of.Fingerprint {
		t.Errorf("fingerprint changed with the engine: semgrep %q, opengrep %q", sf.Fingerprint, of.Fingerprint)
	}
	if got := of.PartialFingerprints[sgMatchBasedID]; got != id {
		t.Errorf("opengrep match-based id = %q, want the engine's id", got)
	}
	if len(sf.PartialFingerprints) != 0 {
		t.Errorf("semgrep without a login has no match-based id: %v", sf.PartialFingerprints)
	}
	if of.Location == nil || of.Location.Snippet == "" {
		t.Errorf("opengrep snippet dropped: %+v", of.Location)
	}
	for _, tag := range of.Tags {
		if tag == "semgrep" {
			t.Errorf("opengrep finding tagged semgrep: %v", of.Tags)
		}
	}

	// The placeholder is never taken for an id.
	ph := parse(FormatOpengrep, "requires login", "requires login")
	if len(ph.Report.Findings[0].PartialFingerprints) != 0 {
		t.Errorf("placeholder kept as a match-based id: %v", ph.Report.Findings[0].PartialFingerprints)
	}
}

// opengrep's output has the semgrep shape: Detect cannot tell them apart and
// names it semgrep; the caller chooses opengrep with Options.Format.
func TestOpengrep_DetectNamesTheShapeSemgrep(t *testing.T) {
	in := `{"version":"1.30.2","results":[{"check_id":"a","path":"b","start":{"line":1},"end":{"line":1},"extra":{}}],"errors":[],"paths":{"scanned":[]}}`
	res, err := Parse(context.Background(), strings.NewReader(in), Options{Repository: "github.com/example/shop"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Format != FormatSemgrep {
		t.Errorf("detected %s", res.Format)
	}
}
