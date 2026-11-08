package importer

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/openctemio/ctis/v2"
)

// Compliance result members beyond the check itself: the cross-framework
// reference list, the sub-checks of a multi-check actual value and the
// prose part of the description. CTIS 2.0 has one framework and no
// sub-checks on a compliance object, so these go to source_extra.

const (
	// Most framework mappings kept from compliance-reference.
	nessusMaxMappings = 64
	// Most sub-checks kept from a multi-check actual value, and their
	// title and detail sizes.
	nessusMaxSubChecks     = 32
	nessusMaxSubTitle      = 200
	nessusMaxSubDetail     = 300
	nessusSubChecksExtraKB = 4 << 10
)

// nessusRefFramework names a framework of compliance-reference in the CTIS
// registry where one fits (complianceFramework), with the version the name
// carries; any other name is kept lowercase as it is.
func nessusRefFramework(name string) (fw, version string) {
	n := strings.TrimSpace(name)
	l := strings.ToLower(n)
	switch {
	case strings.HasPrefix(l, "800-53"):
		return string(ctis.FrameworkNIST80053), strings.TrimPrefix(strings.TrimPrefix(l, "800-53"), "r")
	case strings.HasPrefix(l, "cscv"):
		return string(ctis.FrameworkCIS), "controls v" + strings.TrimPrefix(l, "cscv")
	case strings.HasPrefix(l, "pci-dssv") || strings.HasPrefix(l, "pci-dss"):
		return string(ctis.FrameworkPCIDSS), strings.TrimLeft(strings.TrimPrefix(l, "pci-dss"), "v")
	case strings.Contains(l, "27001"):
		return string(ctis.FrameworkISO27001), ""
	case strings.HasPrefix(l, "csf"):
		return string(ctis.FrameworkNISTCSF), strings.TrimPrefix(l, "csf")
	}
	if f := complianceFramework(n); f != "" && f.IsValid() {
		return string(f), ""
	}
	return line(l, 64), ""
}

// nessusComplianceMappings parses compliance-reference
// ("800-53|AC-3,CSCv8|3.3,PCI-DSSv3.2.1|7.1.2") into one mapping per line,
// "<framework>|<version>|<control>", distinct, at most nessusMaxMappings.
func nessusComplianceMappings(ref string) string {
	if strings.TrimSpace(ref) == "" {
		return ""
	}
	seen := map[string]bool{}
	var out []string
	for _, item := range strings.Split(ref, ",") {
		name, control, ok := strings.Cut(item, "|")
		control = line(control, 64)
		if !ok || control == "" || strings.TrimSpace(name) == "" {
			continue
		}
		fw, ver := nessusRefFramework(name)
		m := fw + "|" + line(ver, 32) + "|" + control
		if seen[m] {
			continue
		}
		seen[m] = true
		out = append(out, m)
		if len(out) >= nessusMaxMappings {
			break
		}
	}
	return strings.Join(out, "\n")
}

// nessusSubCheck is one check of a multi-check actual value.
type nessusSubCheck struct {
	Result string `json:"result"`
	Title  string `json:"title"`
	Detail string `json:"detail,omitempty"`
}

// reSubCheckHead is the first line of a sub-check, after its dashed line:
// "PASSED - title", "FAILED - title", "WARNING - title".
var reSubCheckHead = regexp.MustCompile(`^(PASSED|FAILED|WARNING|ERROR)\s+-\s+(.+)$`)

// nessusSubChecks reads a multi-check actual value: blocks that start with a
// line of dashes followed by "<RESULT> - <title>", then file, regex and
// matched-line detail. A value without such blocks gives nil.
func nessusSubChecks(actual string) []nessusSubCheck {
	lines := strings.Split(actual, "\n")
	var out []nessusSubCheck
	for i := 0; i+1 < len(lines); i++ {
		if !isDashLine(lines[i]) {
			continue
		}
		m := reSubCheckHead.FindStringSubmatch(strings.TrimSpace(lines[i+1]))
		if m == nil {
			continue
		}
		var detail []string
		j := i + 2
		for ; j < len(lines) && !isDashLine(lines[j]); j++ {
			if l := strings.TrimSpace(lines[j]); l != "" {
				detail = append(detail, l)
			}
		}
		out = append(out, nessusSubCheck{
			Result: nessusSubCheckResult(m[1]),
			Title:  line(m[2], nessusMaxSubTitle),
			Detail: line(strings.Join(detail, "; "), nessusMaxSubDetail),
		})
		if len(out) >= nessusMaxSubChecks {
			break
		}
		i = j - 1
	}
	return out
}

func isDashLine(s string) bool {
	s = strings.TrimSpace(s)
	return len(s) >= 3 && strings.Trim(s, "-") == ""
}

// nessusSetSubChecks stores the sub-checks as a JSON array in
// source_extra.compliance-subchecks, dropping trailing checks until the
// value fits, and their count per result in compliance-subcheck-counts.
func nessusSetSubChecks(f *ctis.Finding, subs []nessusSubCheck) {
	counts := map[string]int{}
	for _, s := range subs {
		counts[s.Result]++
	}
	for n := len(subs); n > 0; n-- {
		b, err := json.Marshal(subs[:n])
		if err == nil && len(b) <= nessusSubChecksExtraKB {
			extra(f, "compliance-subchecks", string(b))
			break
		}
	}
	var c []string
	for _, r := range []string{"pass", "fail", "review", "error", "not_applicable"} {
		if counts[r] > 0 {
			c = append(c, r+"="+itoa(counts[r]))
		}
	}
	extra(f, "compliance-subcheck-counts", strings.Join(c, " "))
}

// nessusSubCheckResult is a sub-check's result: the finding's kinds, and
// error for a sub-check that could not run (never folded into
// not_applicable).
func nessusSubCheckResult(s string) string {
	kind, outcome := nessusComplianceResult(s)
	if outcome == ComplianceOutcomeError {
		return ComplianceOutcomeError
	}
	return kind
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// reDescSection starts a section of a compliance description that repeats a
// member of its own.
var reDescSection = regexp.MustCompile(`(?m)^[ \t]*(Reference|Policy Value|Actual Value|Solution|See Also)[ \t]*:`)

// nessusComplianceDescription returns the prose of a compliance description
// before its first repeated section, and whether anything was cut. A
// description that is only sections is kept whole.
func nessusComplianceDescription(d string) (string, bool) {
	loc := reDescSection.FindStringIndex(d)
	if loc == nil {
		return d, false
	}
	head := strings.TrimSpace(d[:loc[0]])
	if head == "" {
		return d, false
	}
	return head, true
}
