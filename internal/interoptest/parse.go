package interoptest

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/ctis/v2/importer"
)

// ParseString parses in through importer.Parse.
func ParseString(t *testing.T, in string, opts importer.Options) (*importer.Result, error) {
	t.Helper()
	return importer.Parse(context.Background(), strings.NewReader(in), opts)
}

// WantKind fails unless err wraps kind and is a *importer.ParseError; it
// returns where the error points.
func WantKind(t *testing.T, err, kind error) (line, column int) {
	t.Helper()
	if err == nil {
		t.Fatalf("want an error wrapping %v, got none", kind)
	}
	if !errors.Is(err, kind) {
		t.Fatalf("want an error wrapping %v, got %v", kind, err)
	}
	var pe *importer.ParseError
	if !errors.As(err, &pe) {
		t.Fatalf("want a *ParseError, got %T", err)
	}
	return pe.Line, pe.Column
}
