// Package validatedoc checks one CTIS document the way a strict receiver
// does: it decodes with unknown members refused, requires a version this
// module implements, and runs Report.Validate. It does no I/O and fetches
// nothing.
package validatedoc

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/openctemio/ctis/v2"
)

// Problem categories.
const (
	CategoryDecode   = "decode"   // not JSON, or members the Go types do not know
	CategoryVersion  = "version"  // version missing or not implemented here
	CategoryValidate = "validate" // Report.Validate refused it
)

// Problem says why a document is invalid.
type Problem struct {
	Category string `json:"category"`
	Message  string `json:"message"`
}

func (p *Problem) Error() string { return p.Category + ": " + p.Message }

// Check returns nil when raw is a valid CTIS report, else the first problem
// found, in the order decode, version, validate.
func Check(raw []byte) *Problem {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var r ctis.Report
	if err := dec.Decode(&r); err != nil {
		return &Problem{CategoryDecode, err.Error()}
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return &Problem{CategoryDecode, "unexpected data after the report"}
	}
	if !ctis.IsSupportedVersion(r.Version) {
		return &Problem{CategoryVersion, fmt.Sprintf("unsupported version %q: this tool implements %v", r.Version, ctis.SupportedSchemaVersions())}
	}
	if err := r.Validate(); err != nil {
		return &Problem{CategoryValidate, err.Error()}
	}
	return nil
}
