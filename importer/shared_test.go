package importer

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/ctis"
)

func TestVEXOf(t *testing.T) {
	v, err := vexOf("known_not_affected", "vulnerable_code_not_in_execute_path", "", "doc-1", nil)
	if err != nil || v.Status != ctis.VEXStatusNotAffected || v.Justification != ctis.VEXJustificationVulnerableCodeNotInExecutePath {
		t.Fatalf("vexOf = %+v, %v", v, err)
	}
	// CycloneDX words keep the source word next to the mapped one.
	v, err = vexOf("not_affected", "code_not_reachable", "", "", nil)
	if err != nil || v.Justification != ctis.VEXJustificationVulnerableCodeNotInExecutePath || v.NativeJustification != "code_not_reachable" {
		t.Fatalf("vexOf = %+v, %v", v, err)
	}
	// A justification only belongs to not_affected.
	v, err = vexOf("affected", "code_not_reachable", "upgrade", "", nil)
	if err != nil || v.Justification != "" {
		t.Fatalf("vexOf = %+v, %v", v, err)
	}
	// A bare not_affected claim is refused.
	if _, err := vexOf("not_affected", "", "", "", nil); err == nil {
		t.Fatal("bare not_affected accepted")
	}
	if _, err := vexOf("not_affected", "no idea", "", "", nil); err == nil {
		t.Fatal("unknown justification without a statement accepted")
	}
	if v, err := vexOf("not_affected", "", "The function is never called.", "", nil); err != nil || v.Statement == "" {
		t.Fatalf("statement-only not_affected refused: %v", err)
	}
	if _, err := vexOf("false_positive", "", "", "", nil); err == nil {
		t.Fatal("unknown status accepted")
	}
}

func TestBuilderHelpers(t *testing.T) {
	b := newBuilder(context.Background(), FormatNessus, Options{Limits: Limits{MaxComponents: 1, MaxStatements: 1}.withDefaults()})
	if _, err := b.asset(ctis.Asset{ID: "a", Type: ctis.AssetTypeHost, Value: "a"}); err != nil {
		t.Fatal(err)
	}
	if b.assetByID("a") == nil || b.assetByID("b") != nil {
		t.Fatal("assetByID")
	}
	if err := b.dependency(ctis.Dependency{Name: "x"}); err != nil {
		t.Fatal(err)
	}
	if err := b.dependency(ctis.Dependency{Name: "y"}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("second dependency: %v", err)
	}
	if err := b.statement(VEXStatement{}); err != nil {
		t.Fatal(err)
	}
	if err := b.statement(VEXStatement{}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("second statement: %v", err)
	}
	tags := addTags(nil, "a", "a", " ", strings.Repeat("x", 200))
	if len(tags) != 2 || len(tags[1]) > 120 {
		t.Fatalf("tags = %q", tags)
	}
	if parseTime("2024-01-02T03:04:05.123Z") == nil || parseTime("2024-01-02") == nil || parseTime("nope") != nil || parseTime("") != nil {
		t.Fatal("parseTime")
	}
	if got := text(strings.Repeat("é", 20), 15); !strings.HasSuffix(got, truncMarker) || len([]rune(got)) != 15 {
		t.Fatalf("text cut = %q", got)
	}
	if (Issue{Line: 3, Path: "/a", Message: "m"}).String() != "line 3: /a: m" || (Issue{Message: "m"}).String() != "m" {
		t.Fatal("Issue.String")
	}
	pe := &ParseError{Format: FormatNessus, Line: 2, Column: 5, Msg: "bad"}
	if pe.Error() != "nessus at line 2, column 5: bad" || (&ParseError{Msg: "x"}).Error() != "input: x" {
		t.Fatalf("ParseError = %q", pe.Error())
	}
}
