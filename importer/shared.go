package importer

import (
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/ctis"
)

// Helpers shared by the importers of SBOM, VEX, OSV and generic findings
// files.

// assetByID returns the asset with the id, for in-place additions.
func (b *builder) assetByID(id string) *ctis.Asset {
	if i, ok := b.assets[id]; ok {
		return &b.res.Report.Assets[i]
	}
	return nil
}

// dependency adds a component of the scanned asset.
func (b *builder) dependency(d ctis.Dependency) error {
	if len(b.res.Report.Dependencies) >= b.lim.MaxComponents {
		return b.tooMany("components", b.lim.MaxComponents)
	}
	b.res.Report.Dependencies = append(b.res.Report.Dependencies, d)
	return nil
}

// statement adds a VEX statement.
func (b *builder) statement(s VEXStatement) error {
	if len(b.res.VEX) >= b.lim.MaxStatements {
		return b.tooMany("VEX statements", b.lim.MaxStatements)
	}
	b.res.VEX = append(b.res.VEX, s)
	return nil
}

// addTags appends bounded, distinct tags.
func addTags(dst []string, tags ...string) []string {
	for _, t := range tags {
		t = line(t, capTag)
		if t == "" || len(dst) >= maxTags {
			continue
		}
		dup := false
		for _, d := range dst {
			if d == t {
				dup = true
				break
			}
		}
		if !dup {
			dst = append(dst, t)
		}
	}
	return dst
}

// vexOf builds a CTIS VEX statement from a document's native status and
// justification. It returns an error for a status no table knows, and for a
// not_affected statement with neither a known justification nor an impact
// statement (CTIS requires one of them, and a receiver must not suppress a
// finding on a bare claim).
func vexOf(nativeStatus, nativeJustification, statement, source string, asOf *time.Time) (ctis.VEX, error) {
	st, ok := ctis.NormalizeVEXStatus(nativeStatus)
	if !ok {
		return ctis.VEX{}, fmt.Errorf("unknown VEX status %q", line(nativeStatus, 64))
	}
	v := ctis.VEX{
		Status:    st,
		Statement: text(statement, ctis.MaxVEXStatementLen),
		Source:    line(source, ctis.MaxVEXSourceLen),
		AsOf:      asOf,
	}
	if nj := strings.TrimSpace(nativeJustification); nj != "" {
		if st == ctis.VEXStatusNotAffected {
			if j, ok := ctis.NormalizeVEXJustification(nj); ok {
				v.Justification = j
			}
		}
		v.NativeJustification = line(nj, ctis.MaxNativeValueLen)
	}
	if st == ctis.VEXStatusNotAffected && v.Justification == "" && v.Statement == "" {
		return ctis.VEX{}, fmt.Errorf("status not_affected without a justification or an impact statement")
	}
	return v, nil
}

// parseTime reads an RFC 3339 time (with or without fractional seconds), or
// a date.
func parseTime(s string) *time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			t = t.UTC()
			return &t
		}
	}
	return nil
}
