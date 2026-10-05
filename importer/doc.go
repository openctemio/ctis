// Package importer converts the files other security tools export into CTIS
// 1.4 reports: Nessus v2 XML, Qualys host detection XML (joined with the
// Qualys KnowledgeBase), CycloneDX and SPDX SBOMs, OSV records, CSAF 2.0 and
// OpenVEX documents, DefectDojo Generic Findings JSON, SARIF 2.1.0, and the
// native JSON of trivy, nuclei, semgrep, betterleaks and vuls. It is the one
// conversion entry point: a receiver's upload and CI endpoints and a
// sensor's parser tool all call Parse.
//
// A code report (SARIF, semgrep, betterleaks, a trivy file-system scan) is
// filed on Options.Repository when it is set; a receiver that knows the
// repository from a verified identity sets it, so a file can never move
// its findings onto another asset.
//
// Detect names the format of a file from its first bytes; Parse converts it.
// A Result carries the CTIS report, the VEX statements of a VEX document
// (which describe products, not findings, and so are not findings of the
// report), counts, problems with their line numbers, and the source fields
// the file held that the format's mapping spec does not know.
//
// # Mapping discipline
//
// Every format has a mapping spec (Specs): one row per source field, saying
// which CTIS member holds it, or why it is deliberately not kept. The
// package tests walk every fixture and fail when a fixture holds a field the
// spec does not list, so an importer can never drop a field silently. The
// spec tables are rendered to docs/importers/, with the coverage of each
// format, and a test keeps the documents in step with the code.
//
// The native value always travels next to the normalized one: the source's
// severity, status, ids and scores go to finding.native and finding.scores,
// and fields without a CTIS member go to finding.source_extra (bounded).
//
// # Hostile input
//
// Every file is treated as hostile. The limits (Limits) bound the input size,
// nesting depth, element and attribute counts, text sizes and the number of
// findings, assets and statements. XML is read with document type
// declarations limited to an external identifier (an internal subset, and so
// any entity declaration, is refused, and no external resource is ever
// read), only the predefined entities, and only UTF-8, US-ASCII or
// ISO-8859-1 input. JSON must be valid UTF-8 and is depth-checked before it
// is decoded. Archives (OpenZip) refuse path traversal, absolute paths,
// links, nested archives and decompression bombs.
//
// Credentials and scan operator details are never copied into a report: the
// Nessus and Qualys mapping specs list the policy, preference and user
// fields as ignored, and the parsers skip them.
package importer
