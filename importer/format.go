package importer

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"sort"
	"strings"
)

// Format names a file format this package reads.
type Format string

const (
	// Nessus v2 XML (.nessus), written by Nessus and Tenable.sc.
	FormatNessus Format = "nessus"
	// Qualys VM host list detection XML (HOST_LIST_VM_DETECTION_OUTPUT).
	FormatQualys Format = "qualys"
	// Qualys KnowledgeBase XML (KNOWLEDGE_BASE_VULN_LIST_OUTPUT). Read only
	// as the companion of a detection file (Options.QualysKnowledgeBase).
	FormatQualysKB Format = "qualys_kb"
	// CycloneDX 1.4 to 1.6 JSON: an SBOM, a VDR or a VEX.
	FormatCycloneDX Format = "cyclonedx"
	// SPDX 2.2 / 2.3 JSON.
	FormatSPDX Format = "spdx"
	// osv-scanner JSON results (packages with their OSV records).
	FormatOSV Format = "osv"
	// CSAF 2.0 JSON (the VEX profile and the security advisory profile).
	FormatCSAF Format = "csaf"
	// OpenVEX JSON.
	FormatOpenVEX Format = "openvex"
	// DefectDojo Generic Findings Import JSON.
	FormatDefectDojo Format = "defectdojo"
	// SARIF 2.1.0 (any static analysis tool that writes SARIF).
	FormatSARIF Format = "sarif"
	// trivy JSON (image, file-system, repository and config scans).
	FormatTrivy Format = "trivy"
	// nuclei JSON lines (-jsonl) or a JSON array (-json-export).
	FormatNuclei Format = "nuclei"
	// semgrep JSON (--json).
	FormatSemgrep Format = "semgrep"
	// betterleaks JSON report (the gitleaks-compatible array).
	FormatBetterleaks Format = "betterleaks"
	// vuls JSON scan result (one server).
	FormatVuls Format = "vuls"
)

// AllFormats returns every format Parse reads, sorted.
func AllFormats() []Format {
	out := make([]Format, 0, len(parsers))
	for f := range parsers {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// IsValid reports whether f is a format Parse reads.
func (f Format) IsValid() bool {
	_, ok := parsers[f]
	return ok
}

// SniffLen is how many leading bytes Detect needs at most.
const SniffLen = 64 << 10

// Detect names the format of an input from its leading bytes (at most
// SniffLen are read). It recognizes the formats of AllFormats and
// FormatQualysKB. It never errors on hostile input; it returns false.
func Detect(head []byte) (Format, bool) {
	if len(head) > SniffLen {
		head = head[:SniffLen]
	}
	head = bytes.TrimPrefix(head, utf8BOM)
	trimmed := bytes.TrimLeft(head, " \t\r\n")
	if len(trimmed) == 0 {
		return "", false
	}
	switch trimmed[0] {
	case '<':
		return detectXML(trimmed)
	case '{', '[':
		return detectJSON(trimmed)
	}
	return "", false
}

var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// detectXML names the format by the local name of the root element.
func detectXML(head []byte) (Format, bool) {
	d := xml.NewDecoder(bytes.NewReader(head))
	d.Strict = true
	d.CharsetReader = charsetReader
	for i := 0; i < 64; i++ {
		tok, err := d.RawToken()
		if err != nil {
			return "", false
		}
		start, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch start.Name.Local {
		case "NessusClientData_v2":
			return FormatNessus, true
		case "HOST_LIST_VM_DETECTION_OUTPUT":
			return FormatQualys, true
		case "KNOWLEDGE_BASE_VULN_LIST_OUTPUT":
			return FormatQualysKB, true
		}
		return "", false
	}
	return "", false
}

// detectJSON names the format by the top-level members of the document (and
// the members of CSAF's "document"). The head may be cut anywhere; what was
// read before the cut decides. A top-level array is decided by its first
// element.
func detectJSON(head []byte) (Format, bool) {
	d := json.NewDecoder(bytes.NewReader(head))
	d.UseNumber()
	type frame struct {
		object    bool
		expectKey bool
		key       string
	}
	var stack []frame
	top := map[string]string{}
	docKeys := map[string]bool{}
	// Keys of the objects of a top-level "results" array (semgrep and
	// osv-scanner both use "results").
	resultKeys := map[string]bool{}
	// root is the depth of the document object: 1, or 2 under a top-level
	// array.
	root := 1
	// valueDone marks the end of a value in the enclosing object.
	valueDone := func() {
		if n := len(stack); n > 0 && stack[n-1].object {
			stack[n-1].expectKey = true
		}
	}
	done := false
	for i := 0; i < 100_000 && !done; i++ {
		tok, err := d.Token()
		if err != nil {
			break
		}
		switch v := tok.(type) {
		case json.Delim:
			switch v {
			case '{', '[':
				if len(stack) == 0 && v == '[' {
					root = 2
				}
				stack = append(stack, frame{object: v == '{', expectKey: v == '{'})
			default:
				if len(stack) == 0 {
					done = true
					continue
				}
				stack = stack[:len(stack)-1]
				if len(stack) < root {
					// The first document is complete.
					done = true
				}
				valueDone()
			}
			continue
		case string:
			n := len(stack)
			if n > 0 && stack[n-1].object && stack[n-1].expectKey {
				stack[n-1].key = v
				stack[n-1].expectKey = false
				switch {
				case n == root:
					top[v] = ""
				case n == root+1 && stack[root-1].object && stack[root-1].key == "document":
					docKeys[v] = true
				case n == root+2 && stack[root-1].object && stack[root-1].key == "results" && !stack[root].object:
					resultKeys[v] = true
				}
				continue
			}
			if n == root && stack[n-1].object {
				top[stack[n-1].key] = v
			}
		}
		valueDone()
	}

	if strings.EqualFold(top["bomFormat"], "CycloneDX") {
		return FormatCycloneDX, true
	}
	if _, ok := top["spdxVersion"]; ok {
		return FormatSPDX, true
	}
	if strings.Contains(top["@context"], "openvex.dev/ns") {
		return FormatOpenVEX, true
	}
	if docKeys["csaf_version"] {
		return FormatCSAF, true
	}
	has := func(keys ...string) bool {
		for _, k := range keys {
			if _, ok := top[k]; ok {
				return true
			}
		}
		return false
	}
	switch {
	case has("runs") && (top["version"] == "2.1.0" || strings.Contains(strings.ToLower(top["$schema"]), "sarif")):
		return FormatSARIF, true
	case has("SchemaVersion") && has("Results", "ArtifactName", "ArtifactType"):
		return FormatTrivy, true
	case has("template-id") && has("info"):
		return FormatNuclei, true
	case has("scannedCves") || has("jsonVersion") && has("serverName"):
		return FormatVuls, true
	case has("RuleID") && has("File", "Secret", "Match"):
		return FormatBetterleaks, true
	}
	if _, ok := top["results"]; ok {
		if resultKeys["check_id"] || (!resultKeys["source"] && !resultKeys["packages"] && has("paths", "skipped_rules", "interfile_languages_used")) {
			return FormatSemgrep, true
		}
		return FormatOSV, true
	}
	if _, ok := top["findings"]; ok {
		return FormatDefectDojo, true
	}
	return "", false
}
