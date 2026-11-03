package csaf

import (
	"fmt"
	"strings"
	"testing"

	"github.com/openctemio/ctis/v2/importer"
	"github.com/openctemio/ctis/v2/internal/interoptest"
)

type Options = importer.Options
type Limits = importer.Limits

func parseString(t *testing.T, in string, opts Options) (*importer.Result, error) {
	t.Helper()
	return interoptest.ParseString(t, in, opts)
}

func wantKind(t *testing.T, err, kind error) (p struct{ Line, Column int }) {
	t.Helper()
	p.Line, p.Column = interoptest.WantKind(t, err, kind)
	return p
}

const csafHead = `{"document":{"category":"csaf_vex","csaf_version":"2.0","title":"t","publisher":{"name":"p","namespace":"https://p.example"},"tracking":{"id":"T-1","current_release_date":"2025-01-01T00:00:00Z"}},`

func TestCSAF_DeepBranches(t *testing.T) {
	in := csafHead + `"product_tree":{"branches":` + strings.Repeat(`[{"category":"vendor","name":"x","branches":`, 200) + "[]" + strings.Repeat("}]", 200) + "}}"
	_, err := parseString(t, in, Options{})
	wantKind(t, err, importer.ErrTooLarge)
}

func TestCSAF_RelationshipCycle(t *testing.T) {
	in := csafHead + `"product_tree":{
"full_product_names":[{"name":"base","product_id":"B","product_identification_helper":{"purl":"pkg:npm/b@1"}}],
"relationships":[
 {"category":"default_component_of","full_product_name":{"name":"x","product_id":"X"},"product_reference":"Y","relates_to_product_reference":"B"},
 {"category":"default_component_of","full_product_name":{"name":"y","product_id":"Y"},"product_reference":"X","relates_to_product_reference":"B"}]},
"vulnerabilities":[{"cve":"CVE-2025-0001","product_status":{"fixed":["B","X"]}}]}`
	res, err := parseString(t, in, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.VEX) != 1 || len(res.VEX[0].Products) != 1 || res.VEX[0].Products[0].PURL != "pkg:npm/b@1" {
		t.Fatalf("statements = %+v", res.VEX)
	}
	var cycle, undefined bool
	for _, is := range res.Issues {
		cycle = cycle || strings.Contains(is.Message, "circular")
		undefined = undefined || strings.Contains(is.Message, `"X"`)
	}
	if !cycle || !undefined {
		t.Fatalf("issues = %+v", res.Issues)
	}
}

func TestCSAF_TooManyProducts(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 20; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"name":"p%d","product_id":"P%d"}`, i, i)
	}
	in := csafHead + `"product_tree":{"full_product_names":[` + b.String() + `]},"vulnerabilities":[]}`
	_, err := parseString(t, in, Options{Limits: Limits{MaxComponents: 10}})
	wantKind(t, err, importer.ErrTooLarge)
}

func TestCSAF_TooManyStatements(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 5; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"cve":"CVE-2025-000%d","product_status":{"fixed":["A"]}}`, i+1)
	}
	in := csafHead + `"product_tree":{"full_product_names":[{"name":"a","product_id":"A"}]},"vulnerabilities":[` + b.String() + `]}`
	_, err := parseString(t, in, Options{Limits: Limits{MaxStatements: 3}})
	wantKind(t, err, importer.ErrTooLarge)
}

func TestCSAF_MalformedInput(t *testing.T) {
	t.Run("invalid UTF-8", func(t *testing.T) {
		in := csafHead + "\n\"vulnerabilities\":[\n{\"cve\":\"\xff\"}]}"
		p := wantKind(t, func() error { _, err := parseString(t, in, Options{}); return err }(), importer.ErrMalformed)
		if p.Line != 3 {
			t.Errorf("line = %d, want 3", p.Line)
		}
	})
	t.Run("wrong type", func(t *testing.T) {
		in := csafHead + "\n\"vulnerabilities\":\n\"all of them\"}"
		p := wantKind(t, func() error { _, err := parseString(t, in, Options{}); return err }(), importer.ErrMalformed)
		if p.Line != 3 {
			t.Errorf("line = %d, want 3", p.Line)
		}
	})
	t.Run("not CSAF", func(t *testing.T) {
		_, err := parseString(t, `{"document":{"title":"x"}}`, Options{Format: importer.FormatCSAF})
		wantKind(t, err, importer.ErrMalformed)
	})
	t.Run("flag that is not a justification", func(t *testing.T) {
		in := csafHead + `"product_tree":{"full_product_names":[{"name":"a","product_id":"A"}]},
"vulnerabilities":[{"cve":"CVE-2025-0001","product_status":{"known_not_affected":["A"]},
"flags":[{"label":"trust_me","product_ids":["A"]}],
"threats":[{"category":"impact","details":"Not reachable.","product_ids":["A"]}]}]}`
		res, err := parseString(t, in, Options{})
		if err != nil {
			t.Fatal(err)
		}
		if len(res.VEX) != 1 || res.VEX[0].VEX.Justification != "" || res.VEX[0].VEX.NativeJustification != "trust_me" {
			t.Fatalf("statements = %+v", res.VEX)
		}
		if len(res.Issues) != 1 || !strings.Contains(res.Issues[0].Message, "trust_me") {
			t.Fatalf("issues = %+v", res.Issues)
		}
	})
}
