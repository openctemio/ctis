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
// found, in the order version, decode, validate. The version comes first so a
// document of another major (a 1.x document) is reported as such, with the
// upgrade it needs, rather than as a list of unknown members.
func Check(raw []byte) *Problem {
	var head struct {
		Version *string `json:"version"`
	}
	if err := json.Unmarshal(raw, &head); err != nil {
		return &Problem{CategoryDecode, err.Error()}
	}
	switch {
	case head.Version == nil:
		return &Problem{CategoryVersion, "version is required"}
	case !ctis.IsSupportedVersion(*head.Version):
		msg := fmt.Sprintf("unsupported version %q: this tool implements %v", *head.Version, ctis.SupportedSchemaVersions())
		if major, _, ok := ctis.ParseVersion(*head.Version); ok && major != ctis.SchemaMajor {
			msg += fmt.Sprintf("; upgrade the producer to CTIS %d", ctis.SchemaMajor)
		}
		return &Problem{CategoryVersion, msg}
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var r ctis.Report
	if err := dec.Decode(&r); err != nil {
		return &Problem{CategoryDecode, err.Error()}
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return &Problem{CategoryDecode, "unexpected data after the report"}
	}
	if err := r.Validate(); err != nil {
		return &Problem{CategoryValidate, err.Error()}
	}
	return nil
}
