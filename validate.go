package ctis

import (
	"fmt"
	"math"
	"strings"
)

// maxValidateProblems caps the problems Validate lists, so a report with a
// million bad findings does not build a million-line error.
const maxValidateProblems = 100

// Validate checks a report's semantic invariants using only the standard
// library (CTIS is intentionally zero-external-dependency). Producers should
// call it before sending, and receivers at their ingest boundary, so a
// malformed or drifted report is refused rather than persisted.
//
// It checks, beyond what decoding into the Go types already enforces:
//   - version is MAJOR.MINOR with this module's major (IsCompatibleVersion);
//   - metadata.timestamp is set;
//   - tool.name is set when tool is present;
//   - assets: value set, type and criticality in their enums, confidence
//     0-100, unique non-empty IDs;
//   - findings: title set, type, severity and status in their enums,
//     confidence 0-100, rank 0-100, unique non-empty IDs, and asset_ref
//     naming an asset of this report;
//   - vulnerability scores: cvss_score 0-10, epss_score 0-1,
//     epss_percentile 0-1 (FIRST's fraction scale, not 0-100), vpr_score
//     0-10, none of them NaN or infinite;
//   - the interoperability members (CTIS 1.4): enums, score ranges per
//     system, VEX consistency, typed vulnerability ids, and the size limits
//     of interop.go (scores, ids, advisories, source_extra, identity hints);
//   - dependencies: name set, unique non-empty IDs;
//   - the contract members (CTIS 1.5): metadata.capability is id@major,
//     technologies and finding.attack within their limits and formats,
//     relationships of a known type between two different assets of this
//     report.
//
// Validate reports all problems it finds (up to 100) in one error, joined
// with "; ". It does not modify the report and does no I/O.
func (r *Report) Validate() error {
	if r == nil {
		return fmt.Errorf("invalid CTIS report: report is nil")
	}

	var problems []string
	add := func(format string, args ...any) {
		if len(problems) < maxValidateProblems {
			problems = append(problems, fmt.Sprintf(format, args...))
		}
	}

	switch v := strings.TrimSpace(r.Version); {
	case v == "":
		add("version is required")
	case !IsCompatibleVersion(v):
		add("unsupported version %q: want %d.<minor>", r.Version, SchemaMajor)
	}
	if r.Metadata.Timestamp.IsZero() {
		add("metadata.timestamp is required")
	}
	if r.Tool != nil && strings.TrimSpace(r.Tool.Name) == "" {
		add("tool.name is required when tool is present")
	}

	assetIDs := make(map[string]bool, len(r.Assets))
	for i, a := range r.Assets {
		if strings.TrimSpace(a.Value) == "" {
			add("assets[%d]: value is required", i)
		}
		if !a.Type.IsValid() {
			add("assets[%d]: invalid type %q", i, a.Type)
		}
		// Criticality is optional; validate only when set.
		if a.Criticality != "" && !a.Criticality.IsValid() {
			add("assets[%d]: invalid criticality %q", i, a.Criticality)
		}
		if a.Confidence < 0 || a.Confidence > 100 {
			add("assets[%d]: confidence %d is outside 0-100", i, a.Confidence)
		}
		validateIdentityHints(i, a.IdentityHints, add)
		validateTechnologies(i, a.Technologies, add)
		if a.ID != "" {
			if assetIDs[a.ID] {
				add("assets[%d]: duplicate id %q", i, a.ID)
			}
			assetIDs[a.ID] = true
		}
	}

	findingIDs := make(map[string]bool, len(r.Findings))
	for i := range r.Findings {
		f := &r.Findings[i]
		if strings.TrimSpace(f.Title) == "" {
			add("findings[%d]: title is required", i)
		}
		if !f.Type.IsValid() {
			add("findings[%d]: invalid type %q", i, f.Type)
		}
		if !f.Severity.IsValid() {
			add("findings[%d]: invalid severity %q", i, f.Severity)
		}
		// Status is optional; validate only when set.
		if f.Status != "" && !f.Status.IsValid() {
			add("findings[%d]: invalid status %q", i, f.Status)
		}
		if f.Confidence < 0 || f.Confidence > 100 {
			add("findings[%d]: confidence %d is outside 0-100", i, f.Confidence)
		}
		if !inRange(f.Rank, 0, 100) {
			add("findings[%d]: rank %v is outside 0-100", i, f.Rank)
		}
		if f.ID != "" {
			if findingIDs[f.ID] {
				add("findings[%d]: duplicate id %q", i, f.ID)
			}
			findingIDs[f.ID] = true
		}
		if f.AssetRef != "" && !assetIDs[f.AssetRef] {
			add("findings[%d]: asset_ref %q names no asset in this report", i, f.AssetRef)
		}
		if v := f.Vulnerability; v != nil {
			if !inRange(v.CVSSScore, 0, 10) {
				add("findings[%d]: vulnerability.cvss_score %v is outside 0-10", i, v.CVSSScore)
			}
			if !inRange(v.EPSSScore, 0, 1) {
				add("findings[%d]: vulnerability.epss_score %v is outside 0-1", i, v.EPSSScore)
			}
			if !inRange(v.EPSSPercentile, 0, 1) {
				add("findings[%d]: vulnerability.epss_percentile %v is outside 0-1 (send FIRST's fraction, not 0-100)", i, v.EPSSPercentile)
			}
			if !inRange(v.VPRScore, 0, 10) {
				add("findings[%d]: vulnerability.vpr_score %v is outside 0-10", i, v.VPRScore)
			}
		}
		validateInteropFinding(i, f, add)
		validateFindingTechniques(i, f.Attack, add)
	}

	depIDs := make(map[string]bool, len(r.Dependencies))
	for i, d := range r.Dependencies {
		if strings.TrimSpace(d.Name) == "" {
			add("dependencies[%d]: name is required", i)
		}
		if d.ID != "" {
			if depIDs[d.ID] {
				add("dependencies[%d]: duplicate id %q", i, d.ID)
			}
			depIDs[d.ID] = true
		}
	}

	validateContractReport(r, assetIDs, add)

	if len(problems) > 0 {
		return fmt.Errorf("invalid CTIS report: %s", strings.Join(problems, "; "))
	}
	return nil
}

func inRange(v, lo, hi float64) bool {
	return !math.IsNaN(v) && !math.IsInf(v, 0) && v >= lo && v <= hi
}
