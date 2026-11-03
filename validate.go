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
// library. Producers call it before sending and receivers at their ingest
// boundary, so a malformed report is refused rather than stored.
//
// Beyond what decoding into the Go types enforces, it checks:
//   - version is MAJOR.MINOR of this module's major;
//   - metadata: id is a UUIDv7, generated_at is set, channel, coverage_type,
//     profiles, source_refs, targets and segment are valid;
//   - tool: name set, techniques known, info_url http(s);
//   - assets: id a document reference (never UUID-shaped) and unique, type
//     known, value in the canonical form of its type, criticality,
//     confidence, technical details, compliance, context and extensions;
//   - findings: title, type, severity, status, confidence, rank, an
//     asset_ref naming an asset of the report, document references, URL
//     members http(s), and the type-specific blocks;
//   - dependencies, endpoints and relationships: references resolve within
//     the report, enums and limits.
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
		add("unsupported version %q: want %d.<minor>; upgrade the producer", truncateForError(r.Version), SchemaMajor)
	}
	validateMetadata(&r.Metadata, add)
	if r.Tool != nil {
		validateTool("tool", r.Tool, add)
	}

	assetIDs := make(map[string]bool, len(r.Assets))
	for i := range r.Assets {
		a := &r.Assets[i]
		validateAsset(i, a, add)
		if a.ID != "" {
			if assetIDs[a.ID] {
				add("assets[%d]: duplicate id %q", i, truncateForError(a.ID))
			}
			assetIDs[a.ID] = true
		}
	}

	endpointIDs := validateEndpoints(r, assetIDs, add)

	depIDs := make(map[string]bool, len(r.Dependencies))
	for i := range r.Dependencies {
		if id := r.Dependencies[i].ID; id != "" {
			if depIDs[id] {
				add("dependencies[%d]: duplicate id %q", i, truncateForError(id))
			}
			depIDs[id] = true
		}
	}
	for i := range r.Dependencies {
		validateDependency(i, &r.Dependencies[i], assetIDs, depIDs, add)
	}

	ruleIDs := validateRules(r.Rules, add)

	findingIDs := make(map[string]bool, len(r.Findings))
	for i := range r.Findings {
		f := &r.Findings[i]
		validateFindingCore(i, f, assetIDs, add)
		validateRuleRef(i, f, ruleIDs, add)
		if f.ID != "" {
			if findingIDs[f.ID] {
				add("findings[%d]: duplicate id %q", i, truncateForError(f.ID))
			}
			findingIDs[f.ID] = true
		}
		validateInteropFinding(i, f, add)
		validateFindingTechniques(i, f.AttackTechniqueIDs, add)
		validateWebLocation(i, f.Web, endpointIDs, add)
		validateEvidenceItems(i, f.EvidenceItems, add)
		validateCoverageFinding(i, f, depIDs, add)
		validateFindingDetails(i, f, add)
	}

	validateRelationships(r, assetIDs, add)
	validateExtensions("extensions", r.Extensions, add)
	for i := range r.Endpoints {
		validateExtensions(fmt.Sprintf("endpoints[%d].extensions", i), r.Endpoints[i].Extensions, add)
	}

	if len(problems) > 0 {
		return fmt.Errorf("invalid CTIS report: %s", strings.Join(problems, "; "))
	}
	return nil
}

func validateMetadata(m *ReportMetadata, add func(string, ...any)) {
	switch {
	case m.ID == "":
		add("metadata.id is required (a producer-generated UUIDv7)")
	case !IsReportID(m.ID):
		add("metadata.id %q is not a lowercase UUIDv7", truncateForError(m.ID))
	}
	if m.GeneratedAt.IsZero() {
		add("metadata.generated_at is required")
	}
	if m.DurationMs < 0 {
		add("metadata.duration_ms is negative")
	}
	if m.Channel != "" && !m.Channel.IsValid() {
		add("metadata.channel %q is invalid", truncateForError(string(m.Channel)))
	}
	if m.CoverageType != "" && !m.CoverageType.IsValid() {
		add("metadata.coverage_type %q is invalid", truncateForError(string(m.CoverageType)))
	}
	if len(m.Profiles) > len(AllProfiles()) {
		add("metadata.profiles has %d entries, at most %d", len(m.Profiles), len(AllProfiles()))
	}
	for i, p := range m.Profiles {
		if !p.IsValid() {
			add("metadata.profiles[%d] %q is invalid", i, truncateForError(string(p)))
		}
	}
	validateSourceRefs("metadata.source_refs", m.SourceRefs, add)
	if b := m.Branch; b != nil {
		if strings.TrimSpace(b.Name) == "" {
			add("metadata.branch.name is required")
		}
		checkWebURL("metadata.branch.pull_request_url", b.PullRequestURL, add)
		checkWebURL("metadata.branch.repository_url", b.RepositoryURL, add)
	}
	validateCoverageMetadata(m, add)
}

func validateTool(where string, t *Tool, add func(string, ...any)) {
	if strings.TrimSpace(t.Name) == "" {
		add("%s.name is required", where)
	}
	checkWebURL(where+".info_url", t.InfoURL, add)
	if len(t.Techniques) > len(AllTechniques()) {
		add("%s.techniques has %d entries, at most %d", where, len(t.Techniques), len(AllTechniques()))
	}
	for i, tq := range t.Techniques {
		if !tq.IsValid() {
			add("%s.techniques[%d] %q is invalid", where, i, truncateForError(string(tq)))
		}
	}
}

func validateAsset(i int, a *Asset, add func(string, ...any)) {
	if a.ID == "" {
		add("assets[%d]: id is required", i)
	}
	validateDocumentRef(fmt.Sprintf("assets[%d].id", i), a.ID, add)
	if !a.Type.IsValid() {
		add("assets[%d]: invalid type %q", i, truncateForError(string(a.Type)))
	}
	switch {
	case strings.TrimSpace(a.Value) == "":
		add("assets[%d]: value is required", i)
	case len(a.Value) > MaxAssetValueLen:
		add("assets[%d]: value longer than %d", i, MaxAssetValueLen)
	case a.Type.IsValid():
		if c, err := CanonicalAssetValue(a.Type, a.Value); err != nil {
			add("assets[%d]: value %q has no canonical form for type %s: %v", i, truncateForError(a.Value), a.Type, err)
		} else if c != a.Value {
			add("assets[%d]: value %q is not canonical for type %s (want %q)", i, truncateForError(a.Value), a.Type, truncateForError(c))
		}
	}
	if !a.Criticality.IsValid() {
		add("assets[%d]: invalid criticality %q", i, truncateForError(string(a.Criticality)))
	}
	if a.Confidence < 0 || a.Confidence > 100 {
		add("assets[%d]: confidence %d is outside 0-100", i, a.Confidence)
	}
	validateIdentityHints(i, a.IdentityHints, add)
	validateTechnologies(i, a.Technologies, add)
	validateCoverageAsset(i, a, add)
	validateSourceRefs(fmt.Sprintf("assets[%d].source_refs", i), a.SourceRefs, add)
	validateAssetTechnical(i, a, add)
	if c := a.Compliance; c != nil {
		for j, f := range c.Frameworks {
			if !IsOpenToken(string(f)) {
				add("assets[%d]: compliance.frameworks[%d] %q is not a framework token", i, j, truncateForError(string(f)))
			}
		}
		if c.DataClassification != "" && !c.DataClassification.IsValid() {
			add("assets[%d]: compliance.data_classification %q is invalid", i, truncateForError(string(c.DataClassification)))
		}
	}
}

func validateFindingCore(i int, f *Finding, assetIDs map[string]bool, add func(string, ...any)) {
	if strings.TrimSpace(f.Title) == "" {
		add("findings[%d]: title is required", i)
	}
	if !f.Type.IsValid() {
		add("findings[%d]: invalid type %q", i, truncateForError(string(f.Type)))
	}
	if !f.Severity.IsValid() {
		add("findings[%d]: invalid severity %q", i, truncateForError(string(f.Severity)))
	}
	if f.Status != "" && !f.Status.IsValid() {
		add("findings[%d]: invalid status %q", i, truncateForError(string(f.Status)))
	}
	if f.Confidence < 0 || f.Confidence > 100 {
		add("findings[%d]: confidence %d is outside 0-100", i, f.Confidence)
	}
	if !inRange(f.Rank, 0, 100) {
		add("findings[%d]: rank %v is outside 0-100", i, f.Rank)
	}
	validateDocumentRef(fmt.Sprintf("findings[%d].id", i), f.ID, add)
	switch {
	case f.AssetRef == "":
		add("findings[%d]: asset_ref is required", i)
	case !assetIDs[f.AssetRef]:
		validateDocumentRef(fmt.Sprintf("findings[%d].asset_ref", i), f.AssetRef, add)
		add("findings[%d]: asset_ref %q names no asset in this report", i, truncateForError(f.AssetRef))
	}
	validateDocumentRef(fmt.Sprintf("findings[%d].dependency_ref", i), f.DependencyRef, add)
	validateSourceRefs(fmt.Sprintf("findings[%d].source_refs", i), f.SourceRefs, add)
	if len(f.References) > MaxReferences {
		add("findings[%d]: references has %d entries, at most %d", i, len(f.References), MaxReferences)
	}
	for j, u := range f.References {
		if j < MaxReferences {
			checkWebURL(fmt.Sprintf("findings[%d].references[%d]", i, j), u, add)
		}
	}
	for j, u := range f.WorkItemURIs {
		checkWebURL(fmt.Sprintf("findings[%d].work_item_uris[%d]", i, j), u, add)
	}
	checkWebURL(fmt.Sprintf("findings[%d].hosted_viewer_uri", i), f.HostedViewerURI, add)
}

func inRange(v, lo, hi float64) bool {
	return !math.IsNaN(v) && !math.IsInf(v, 0) && v >= lo && v <= hi
}
