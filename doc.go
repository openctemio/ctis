// Package ctis defines CTIS, the CTEM Ingest Schema: the JSON format security
// tools use to send assets, findings and dependencies to a CTEM platform such
// as OpenCTEM.
//
// The Go types in this package, the JSON Schema in schemas/v1 and the field
// reference in docs/spec.md describe the same format; tests keep them equal.
// Receivers decode strictly into these types, so a member they do not know is
// an error.
//
// Producing a report:
//
//	r := ctis.NewReport() // stamps SchemaVersion, SchemaURL and the time
//	r.Tool = &ctis.Tool{Name: "my-scanner"}
//	r.Findings = append(r.Findings, ctis.Finding{
//		Type: ctis.FindingTypeVulnerability, Title: "...", Severity: ctis.SeverityHigh,
//	})
//	if err := r.Validate(); err != nil { ... }
//
// Converting tool output: FromSARIF for SARIF 2.1.0 logs, ConvertReconToCTIS
// and MergeReconReports for reconnaissance results.
//
// Versioning: a report's Version is the specification version MAJOR.MINOR.
// Receivers accept every minor of their major (IsCompatibleVersion); because
// they decode strictly, producers must not send members newer than the
// receiver's minor. See docs/spec.md.
package ctis
