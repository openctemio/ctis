package importer

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

const qualysDet = `<?xml version="1.0"?><HOST_LIST_VM_DETECTION_OUTPUT><RESPONSE><HOST_LIST><HOST><ID>1</ID><IP>192.0.2.1</IP><DETECTION_LIST><DETECTION><QID>38909</QID><TYPE>Confirmed</TYPE><SEVERITY>4</SEVERITY><STATUS>Active</STATUS></DETECTION></DETECTION_LIST></HOST></HOST_LIST></RESPONSE></HOST_LIST_VM_DETECTION_OUTPUT>`

func TestQualys_KnowledgeBaseIsHostileToo(t *testing.T) {
	cases := map[string]struct {
		kb   string
		kind error
	}{
		"xxe":        {`<?xml version="1.0"?><!DOCTYPE k [<!ENTITY x SYSTEM "file:///etc/passwd">]><KNOWLEDGE_BASE_VULN_LIST_OUTPUT/>`, ErrUnsafe},
		"wrong root": {`<?xml version="1.0"?><NessusClientData_v2/>`, ErrMalformed},
		"empty":      {``, ErrMalformed},
		"deep":       {`<KNOWLEDGE_BASE_VULN_LIST_OUTPUT>` + strings.Repeat("<a>", 1000) + strings.Repeat("</a>", 1000) + `</KNOWLEDGE_BASE_VULN_LIST_OUTPUT>`, ErrTooLarge},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse(context.Background(), strings.NewReader(qualysDet), Options{QualysKnowledgeBase: strings.NewReader(c.kb)})
			if !errors.Is(err, c.kind) {
				t.Fatalf("want %v, got %v", c.kind, err)
			}
		})
	}
}

func TestQualys_KnowledgeBaseSizeLimit(t *testing.T) {
	kb := `<KNOWLEDGE_BASE_VULN_LIST_OUTPUT>` + strings.Repeat(" ", 4096) + `</KNOWLEDGE_BASE_VULN_LIST_OUTPUT>`
	_, err := Parse(context.Background(), strings.NewReader(qualysDet), Options{Limits: Limits{MaxInputBytes: 2048}, QualysKnowledgeBase: strings.NewReader(kb)})
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("want ErrTooLarge, got %v", err)
	}
}

func TestQualys_CredentialsNeverInOutput(t *testing.T) {
	res, _ := runFixture(t, fixture{format: FormatQualys, path: fixtureRoot + "/qualys/detections.xml", kb: fixtureRoot + "/qualys/detections.kb.xml"})
	b, err := os.ReadFile(fixtureRoot + "/qualys/detections.golden.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"qscan", "Pa55w0rd", "Jane", "call Jane", "exmpl_ab1", "javascript:"} {
		if bytes.Contains(b, []byte(s)) {
			t.Errorf("golden output holds %q", s)
		}
	}
	if len(res.Report.Findings) == 0 {
		t.Fatal("no findings")
	}
}

func TestQualysHTML(t *testing.T) {
	cases := map[string]string{
		"plain":                           "plain",
		"a<br/>b":                         "a\nb",
		"<P>x</P>":                        "\nx\n",
		`<A HREF="javascript:x">link</A>`: "link",
		"broken <tag":                     "broken <tag",
		"<script>alert(1)</script>":       "alert(1)",
		"<LI>one<LI>two":                  "\none\ntwo",
	}
	for in, want := range cases {
		if got := qualysHTML(in); got != want {
			t.Errorf("qualysHTML(%q) = %q, want %q", in, got, want)
		}
	}
	if got := cvss2Base("AV:N/AC:M/Au:N/C:N/I:P/A:N/E:POC/RL:OF/RC:C"); got != "AV:N/AC:M/Au:N/C:N/I:P/A:N" {
		t.Errorf("cvss2Base = %q", got)
	}
}
