// Package ctis defines CTIS 2.0, the CTEM Interchange Schema: the JSON
// document format security tools and platforms use to exchange assets,
// findings, software components, relationships and web endpoints for
// continuous threat exposure management. A document carries natural keys
// (canonical forms) and the producer's own references, never a receiver's
// database keys.
//
// The Go types in this package, the JSON Schema in schemas/v2 and the field
// reference in docs/spec.md describe the same format; tests keep them equal.
// Decode reads a document under the compatibility rule: strictly for this
// module's minor or an older one (a member it does not know is an error),
// ignoring unknown members and mapping unknown enum values to their
// fallback for a newer minor, and refusing another major. The Canonical*
// functions and AssetKey give the canonical value and key receivers
// deduplicate assets on.
//
// Producing a report:
//
//	r := ctis.NewReport() // stamps SchemaVersion, SchemaURL, a UUIDv7 id and the time
//	r.Tool = &ctis.Tool{Name: "my-scanner"}
//	r.Assets = append(r.Assets, ctis.Asset{ID: "h1", Type: ctis.AssetTypeHost, Value: "web01.example.com"})
//	r.Findings = append(r.Findings, ctis.Finding{
//		Type: ctis.FindingTypeExposure, Title: "...", Severity: ctis.SeverityHigh, AssetRef: "h1",
//	})
//	if err := r.Validate(); err != nil { ... }
//
// Converting tool output: FromSARIF for SARIF 2.1.0 logs, ConvertReconToCTIS
// and MergeReconReports for reconnaissance results.
//
// Versioning: a report's Version is the specification version MAJOR.MINOR.
// Receivers read every minor of their major (newer minors with unknown
// members ignored, see Decode) and refuse every other major: a 1.x document
// is rejected and its producer must be upgraded. See docs/spec.md.
package ctis
