package ctis

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Exporters: CTIS to SARIF 2.1.0 (export_sarif.go), CycloneDX 1.6
// (export_cyclonedx.go) and OCSF 1.3.0 (export_ocsf.go).
//
// Every exporter follows the same rules:
//   - Deterministic: the same report gives the same bytes. Findings keep the
//     order of the report; catalogs built from them (SARIF rules, CycloneDX
//     components) are in first-seen order or sorted; maps are written with
//     sorted keys. No exporter reads the clock: a time the output needs and
//     the report lacks comes from the options, else from
//     report.metadata.timestamp.
//   - No network: URL members are written as given, never fetched.
//   - Secrets stay masked: every finding is copied and a secret finding is
//     passed through RedactSecretFinding before any of it is written, so a
//     raw match in a snippet, masked_value, title or property never leaves
//     in an export. Values marked sensitive in HTTP evidence are masked too.
//   - Bounded: the encoded output is refused above MaxExportBytes.
//   - No receiver context: the exporters write what the report holds about
//     the scan, never a tenant or receiver identifier.
//
// What each format cannot carry is listed in docs/exporters.md.

// MaxExportBytes is the largest encoded output an exporter returns. It is
// the importer's default input limit, so an export can be read back.
const MaxExportBytes = 256 << 20

// ErrExportTooLarge is returned when the encoded output would exceed
// MaxExportBytes.
var ErrExportTooLarge = errors.New("ctis: export exceeds MaxExportBytes")

// errNilReport is returned for a nil report.
var errNilReport = errors.New("ctis: nil report")

// exportFinding returns a deep copy of f that is safe to write out: a secret
// finding is redacted (RedactSecretFinding), and the caller's report is
// never modified.
func exportFinding(f *Finding) (Finding, error) {
	b, err := json.Marshal(f)
	if err != nil {
		return Finding{}, fmt.Errorf("ctis: copy finding: %w", err)
	}
	var c Finding
	if err := json.Unmarshal(b, &c); err != nil {
		return Finding{}, fmt.Errorf("ctis: copy finding: %w", err)
	}
	if c.Type == FindingTypeSecret {
		RedactSecretFinding(&c)
	}
	return c, nil
}

// marshalExport encodes v with indentation and enforces MaxExportBytes.
func marshalExport(v any) ([]byte, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("ctis: encode export: %w", err)
	}
	if len(b) > MaxExportBytes {
		return nil, ErrExportTooLarge
	}
	return b, nil
}

// findAsset returns the asset of the report with the given id, or nil.
func findAsset(r *Report, id string) *Asset {
	if id == "" {
		return nil
	}
	for i := range r.Assets {
		if r.Assets[i].ID == id {
			return &r.Assets[i]
		}
	}
	return nil
}

// propString returns the string value of a property, or "".
func propString(p Properties, key string) string {
	if s, ok := p[key].(string); ok {
		return s
	}
	return ""
}

// formatTime writes a time as RFC 3339 in UTC, or "" for nil/zero.
func formatTime(t *time.Time) string {
	if t == nil || t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// formatScore writes a score with the fewest digits that read back equal.
func formatScore(v float64) string {
	return strconv.FormatFloat(v, 'f', -1, 64)
}

// maskSensitiveSpans masks, in value, the ranges the evidence item marks
// sensitive at pointer: a span without offsets masks the whole value.
func maskSensitiveSpans(value, pointer string, spans []SensitiveSpan) string {
	if value == "" {
		return value
	}
	type rng struct{ start, end int }
	var ranges []rng
	for _, s := range spans {
		if s.Pointer != pointer {
			continue
		}
		if s.Start == nil || s.End == nil {
			return redactedSecret
		}
		st, en := *s.Start, *s.End
		if st < 0 || en > len(value) || st >= en {
			return redactedSecret
		}
		ranges = append(ranges, rng{st, en})
	}
	if len(ranges) == 0 {
		return value
	}
	mask := make([]bool, len(value))
	for _, r := range ranges {
		for i := r.start; i < r.end; i++ {
			mask[i] = true
		}
	}
	var b strings.Builder
	in := false
	for i := 0; i < len(value); i++ {
		if mask[i] {
			if !in {
				b.WriteString("********")
				in = true
			}
			continue
		}
		in = false
		b.WriteByte(value[i])
	}
	return b.String()
}
