package ctis

import (
	"strconv"
	"strings"
)

// Specification version and schema location.
//
// SchemaVersion is the MAJOR.MINOR of the CTIS specification this module
// implements, and the value producers put in Report.Version. It moves with the
// module's minor version: module v1.3.x implements CTIS 1.3. A parity test
// keeps it equal to the "default" of report.json#/properties/version.
//
// Compatibility rule (docs/spec.md, "Versioning"):
//   - A consumer accepts every report whose major equals SchemaMajor.
//   - A minor release only adds optional fields or enum values.
//   - A consumer that decodes strictly (unknown fields rejected) still refuses
//     a field newer than its own minor, so a producer must not send fields from
//     a minor newer than the consumer it talks to. Upgrade receivers first.
const (
	SchemaVersion = "1.3"
	SchemaMajor   = 1

	// SchemaBaseURL is the base of the published schema $ids. Every file in
	// schemas/v1 is reachable at SchemaBaseURL + its file name.
	SchemaBaseURL = "https://raw.githubusercontent.com/openctemio/ctis/main/schemas/v1/"

	// SchemaURL is the $id of the report schema, for Report.Schema.
	SchemaURL = SchemaBaseURL + "report.json"
)

// ParseVersion splits a CTIS version of the form MAJOR.MINOR. It accepts only
// non-negative decimal numbers without leading zeros, so "1.3" parses and
// "1", "v1.3", "1.03" and "1.3.0" do not.
func ParseVersion(v string) (major, minor int, ok bool) {
	maj, mnr, found := strings.Cut(v, ".")
	if !found {
		return 0, 0, false
	}
	major, ok1 := parseVersionPart(maj)
	minor, ok2 := parseVersionPart(mnr)
	if !ok1 || !ok2 {
		return 0, 0, false
	}
	return major, minor, true
}

func parseVersionPart(s string) (int, bool) {
	if s == "" || len(s) > 4 || (len(s) > 1 && s[0] == '0') {
		return 0, false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	n, err := strconv.Atoi(s)
	return n, err == nil
}

// IsCompatibleVersion reports whether a report declaring version v can be
// read by this module: same major, any minor. See the package compatibility
// rule on SchemaVersion for what a newer minor implies.
func IsCompatibleVersion(v string) bool {
	major, _, ok := ParseVersion(v)
	return ok && major == SchemaMajor
}
