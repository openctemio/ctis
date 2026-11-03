package importer

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/ctis/v2"
)

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
	if (Issue{Line: 3, Path: "/a", Message: "m"}).String() != "line 3: /a: m" || (Issue{Message: "m"}).String() != "m" {
		t.Fatal("Issue.String")
	}
	pe := &ParseError{Format: FormatNessus, Line: 2, Column: 5, Msg: "bad"}
	if pe.Error() != "nessus at line 2, column 5: bad" || (&ParseError{Msg: "x"}).Error() != "input: x" {
		t.Fatalf("ParseError = %q", pe.Error())
	}
}
