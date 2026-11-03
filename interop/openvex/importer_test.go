package openvex

import (
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

const ovHead = `{"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://vex.example/d","author":"a","timestamp":"2025-01-01T00:00:00Z","version":1,"statements":`

func TestOpenVEX_Hostile(t *testing.T) {
	t.Run("wrong context", func(t *testing.T) {
		_, err := parseString(t, `{"@context":"https://example.com/ns","statements":[]}`, Options{Format: importer.FormatOpenVEX})
		wantKind(t, err, importer.ErrMalformed)
	})
	t.Run("too many products in a statement", func(t *testing.T) {
		in := ovHead + `[{"vulnerability":{"name":"CVE-2025-0001"},"status":"fixed","products":[` + strings.TrimSuffix(strings.Repeat(`{"@id":"pkg:npm/a@1"},`, 20), ",") + `]}]}`
		_, err := parseString(t, in, Options{Limits: Limits{MaxComponents: 10}})
		wantKind(t, err, importer.ErrTooLarge)
	})
	t.Run("unknown status is an issue", func(t *testing.T) {
		in := ovHead + "[\n{\"vulnerability\":{\"name\":\"CVE-2025-0001\"},\"status\":\"maybe\",\"products\":[{\"@id\":\"pkg:npm/a@1\"}]}]}"
		res, err := parseString(t, in, Options{})
		if err != nil {
			t.Fatal(err)
		}
		if len(res.VEX) != 0 || len(res.Issues) != 1 || res.Issues[0].Line != 2 {
			t.Fatalf("vex = %+v issues = %+v", res.VEX, res.Issues)
		}
	})
	t.Run("unknown justification keeps the statement text", func(t *testing.T) {
		in := ovHead + `[{"vulnerability":{"name":"CVE-2025-0001"},"status":"not_affected","justification":"because","impact_statement":"Never loaded.","products":[{"@id":"pkg:npm/a@1"}]}]}`
		res, err := parseString(t, in, Options{})
		if err != nil {
			t.Fatal(err)
		}
		if len(res.VEX) != 1 || res.VEX[0].VEX.Justification != "" || len(res.Issues) != 1 {
			t.Fatalf("vex = %+v issues = %+v", res.VEX, res.Issues)
		}
	})
	t.Run("bad product shapes", func(t *testing.T) {
		in := ovHead + `[{"vulnerability":{"name":"CVE-2025-0001"},"status":"fixed","products":[42,{"hashes":{"sha256":"00"}},{"@id":"pkg:npm/a@1"}]}]}`
		res, err := parseString(t, in, Options{})
		if err != nil {
			t.Fatal(err)
		}
		if len(res.VEX) != 1 || len(res.VEX[0].Products) != 1 || len(res.Issues) != 2 {
			t.Fatalf("vex = %+v issues = %+v", res.VEX, res.Issues)
		}
	})
	t.Run("deep nesting", func(t *testing.T) {
		in := ovHead + strings.Repeat("[", 500) + strings.Repeat("]", 500) + "}"
		_, err := parseString(t, in, Options{})
		wantKind(t, err, importer.ErrTooLarge)
	})
}
