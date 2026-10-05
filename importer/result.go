package importer

import (
	"errors"
	"fmt"

	"github.com/openctemio/ctis"
)

// Result is what Parse returns for one file.
type Result struct {
	// Format of the file.
	Format Format `json:"format"`

	// The CTIS report: assets, findings and dependencies. Never nil; a VEX
	// document gives a report without findings.
	Report *ctis.Report `json:"report"`

	// The statements of a VEX document (CSAF VEX, OpenVEX, the analysis
	// members of a CycloneDX VEX). A receiver applies them to its own
	// findings that match a statement's vulnerability and product.
	VEX []VEXStatement `json:"vex,omitempty"`

	// Counts of what the file held and what was kept.
	Stats Stats `json:"stats"`

	// Problems that did not stop the import (an item without a required
	// field, a value out of range), at most Limits.MaxIssues.
	Issues []Issue `json:"issues,omitempty"`

	// Source field paths the file held that the format's mapping spec does
	// not list, sorted. Their values are not in the report; a receiver can
	// show them so the spec is extended.
	Unmapped []string `json:"unmapped,omitempty"`
}

// Stats counts what an import read and produced.
type Stats struct {
	// Records of the source: Nessus ReportItems, Qualys detections, CycloneDX
	// vulnerabilities, OSV affected packages, DefectDojo findings.
	Records int `json:"records"`

	Assets     int `json:"assets"`
	Findings   int `json:"findings"`
	Components int `json:"components"`
	Statements int `json:"statements"`

	// Records skipped (below the minimum severity, or unusable; the reason
	// of an unusable record is in Issues).
	Skipped int `json:"skipped"`

	// Findings per CTIS severity.
	BySeverity map[ctis.Severity]int `json:"by_severity,omitempty"`
}

// Issue is a problem at a place in the input.
type Issue struct {
	// 1-based line and column of the place in the input, when known.
	Line   int `json:"line,omitempty"`
	Column int `json:"column,omitempty"`

	// The record the problem is in: an XML element path or a JSON pointer.
	Path string `json:"path,omitempty"`

	Message string `json:"message"`
}

func (i Issue) String() string {
	loc := ""
	if i.Line > 0 {
		loc = fmt.Sprintf("line %d: ", i.Line)
	}
	if i.Path != "" {
		return fmt.Sprintf("%s%s: %s", loc, i.Path, i.Message)
	}
	return loc + i.Message
}

// VEXStatement is one exploitability statement of a VEX document: the
// status of the products below for the vulnerability below.
type VEXStatement struct {
	// The vulnerability, under every id the document gives it.
	VulnerabilityIDs []ctis.VulnerabilityID `json:"vulnerability_ids"`

	// The products the statement is about. A receiver matches a finding
	// on a shared PURL (version-less when the statement's PURL has no
	// version) or CPE.
	Products []Product `json:"products"`

	// The statement.
	VEX ctis.VEX `json:"vex"`
}

// Product is a product of a VEX statement.
type Product struct {
	// Package URL.
	PURL string `json:"purl,omitempty"`

	// CPE 2.3 name.
	CPE string `json:"cpe,omitempty"`

	// Name and version as the document states them, when it gives no
	// identifier.
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
}

// ParseError is the error of an input that could not be read. Line and
// Column point into the input when known.
type ParseError struct {
	Format Format
	Line   int
	Column int
	Msg    string
	Err    error
}

func (e *ParseError) Error() string {
	where := ""
	if e.Line > 0 {
		where = fmt.Sprintf(" at line %d", e.Line)
		if e.Column > 0 {
			where += fmt.Sprintf(", column %d", e.Column)
		}
	}
	if e.Format != "" {
		return fmt.Sprintf("%s%s: %s", e.Format, where, e.Msg)
	}
	return fmt.Sprintf("input%s: %s", where, e.Msg)
}

func (e *ParseError) Unwrap() error { return e.Err }

// Errors a caller can test with errors.Is.
var (
	// ErrUnknownFormat: Detect does not recognize the input, or the format
	// named is not one this package reads.
	ErrUnknownFormat = errors.New("unknown import format")

	// ErrTooLarge: the input or one of its parts is over a limit.
	ErrTooLarge = errors.New("import input over a limit")

	// ErrUnsafe: the input uses a construct this package never reads (an
	// XML internal subset or entity declaration, an unsupported charset,
	// a link or traversal in an archive).
	ErrUnsafe = errors.New("import input uses a refused construct")

	// ErrMalformed: the input is not well-formed for its format.
	ErrMalformed = errors.New("malformed import input")
)
