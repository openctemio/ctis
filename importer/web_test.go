package importer

import (
	"context"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/openctemio/ctis"
)

// A web finding names its place in finding.web: one ZAP finding per
// method, URL template and parameter, and no query value, user info or
// fragment anywhere in the output.
func TestWebFindings(t *testing.T) {
	raw, err := os.ReadFile("../testdata/importers/zap/sqli-params.json")
	if err != nil {
		t.Fatal(err)
	}
	res, err := Parse(context.Background(), strings.NewReader(string(raw)), Options{Format: FormatZAP})
	if err != nil {
		t.Fatal(err)
	}
	if n := len(res.Report.Findings); n != 3 {
		t.Fatalf("3 SQL injection parameters became %d findings", n)
	}
	want := []struct {
		method, url string
		loc         ctis.ParamLocation
		name        string
		count       int
	}{
		{"GET", "https://shop.example.com/products/42?id=&sid=", ctis.ParamLocationQuery, "id", 2},
		{"GET", "https://shop.example.com/products/42?sort=", ctis.ParamLocationQuery, "sort", 1},
		{"POST", "https://shop.example.com/cart", ctis.ParamLocationForm, "qty", 2},
	}
	for i, w := range want {
		f := res.Report.Findings[i]
		if f.Web == nil || f.Web.Method != w.method || f.Web.URL != w.url || f.Web.Parameter == nil ||
			f.Web.Parameter.Location != w.loc || f.Web.Parameter.Name != w.name || f.OccurrenceCount != w.count {
			t.Errorf("finding %d: web %+v count %d", i, f.Web, f.OccurrenceCount)
		}
	}
	if err := res.Report.Validate(); err != nil {
		t.Fatal(err)
	}

	nuclei := `{"template-id":"sqli-error","info":{"name":"SQLi","severity":"high"},"host":"https://app.example.com","matched-at":"https://u:pw@app.example.com/q?id=1%27&token=s3cr3t#frag","request":"POST /q HTTP/1.1\r\nCookie: sid=s3cr3t\r\n","fuzzing_method":"","fuzzing_parameter":"id","fuzzing_position":"query"}
{"template-id":"ssh-banner","info":{"name":"SSH","severity":"info"},"host":"10.0.0.1:22","matched-at":"10.0.0.1:22"}
{"template-id":"hdr","info":{"name":"Header","severity":"low"},"host":"https://app.example.com","matched-at":"https://app.example.com/","fuzzing_method":"GET","fuzzing_parameter":"X-\u0007Bad","fuzzing_position":"header"}`
	nres, err := Parse(context.Background(), strings.NewReader(nuclei), Options{Format: FormatNuclei})
	if err != nil {
		t.Fatal(err)
	}
	fs := nres.Report.Findings
	if len(fs) != 3 {
		t.Fatalf("findings %d", len(fs))
	}
	if w := fs[0].Web; w == nil || w.URL != "https://app.example.com/q?id=&token=" || w.Method != "POST" ||
		w.Parameter == nil || w.Parameter.Name != "id" || w.Parameter.Location != ctis.ParamLocationQuery || fs[0].Location != nil {
		t.Errorf("nuclei DAST web %+v location %+v", fs[0].Web, fs[0].Location)
	}
	if fs[1].Web != nil || fs[1].Location != nil {
		t.Errorf("a network result has no web location: %+v", fs[1].Web)
	}
	if w := fs[2].Web; w == nil || w.Method != "GET" || w.Parameter != nil {
		t.Errorf("a control character in a parameter name is dropped: %+v", w)
	}
	if err := nres.Report.Validate(); err != nil {
		t.Fatal(err)
	}

	for name, r := range map[string]*ctis.Report{"zap": res.Report, "nuclei": nres.Report} {
		out, _ := json.Marshal(r)
		for _, bad := range []string{"s3cr3t", "pw@", "frag", "%27", "42'&", "1'"} {
			if strings.Contains(string(out), bad) {
				t.Errorf("%s: %q is in the output", name, bad)
			}
		}
	}
	for _, loc := range []string{"query", "path", "header", "cookie", "body", "json", "multipart", "nope"} {
		if l, ok := nucleiParamLocation(loc); ok != (loc != "nope") || (ok && l == "") {
			t.Errorf("position %s", loc)
		}
	}
}

// An alert with more locations than kept is cut with an issue.
func TestZAPLocationCap(t *testing.T) {
	var inst []string
	for i := 0; i < zapMaxLocations+5; i++ {
		inst = append(inst, `{"uri":"https://a.example/p`+strings.Repeat("x", i%7)+`/`+string(rune('a'+i%26))+`","method":"GET","param":"p`+strconv.Itoa(i)+`"}`)
	}
	doc := `{"@programName":"ZAP","site":[{"@name":"https://a.example","@host":"a.example","@port":"443","@ssl":"true","alerts":[{"pluginid":"1","alert":"A","riskcode":"1","instances":[` + strings.Join(inst, ",") + `]}]}]}`
	res, err := Parse(context.Background(), strings.NewReader(doc), Options{Format: FormatZAP})
	if err != nil {
		t.Fatal(err)
	}
	if n := len(res.Report.Findings); n != zapMaxLocations {
		t.Fatalf("findings %d", n)
	}
	found := false
	for _, is := range res.Issues {
		found = found || strings.Contains(is.Message, "5 instances past")
	}
	if !found {
		t.Errorf("issues %+v", res.Issues)
	}
}
