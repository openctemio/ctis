package ctis

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"
)

func ptrF(v float64) *float64 { return &v }

func interopReport(f Finding) *Report {
	r := NewReport()
	r.Metadata.Timestamp = time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)
	if f.Type == "" {
		f.Type = FindingTypeVulnerability
	}
	if f.Title == "" {
		f.Title = "t"
	}
	if f.Severity == "" {
		f.Severity = SeverityHigh
	}
	r.Findings = []Finding{f}
	return r
}

func TestNormalizeNativeSeverity(t *testing.T) {
	cases := []struct {
		scheme NativeScheme
		in     string
		want   Severity
		ok     bool
	}{
		{NativeSchemeNessus, "0", SeverityInfo, true},
		{NativeSchemeNessus, "4", SeverityCritical, true},
		{NativeSchemeNessus, " High ", SeverityHigh, true},
		{NativeSchemeNessus, "5", "", false},
		{NativeSchemeQualys, "1", SeverityInfo, true},
		{NativeSchemeQualys, "3", SeverityMedium, true},
		{NativeSchemeQualys, "5", SeverityCritical, true},
		{NativeSchemeQualys, "0", "", false},
		{NativeSchemeDefectDojo, "Informational", SeverityInfo, true},
		{NativeSchemeDefectDojo, "Critical", SeverityCritical, true},
		{NativeSchemeSARIF, "error", SeverityHigh, true},
		{NativeSchemeSARIF, "note", SeverityLow, true},
		{NativeSchemeSARIF, "fatal", "", false},
		{NativeSchemeOther, "high", "", false},
		{"bogus", "high", "", false},
	}
	for _, c := range cases {
		got, ok := NormalizeNativeSeverity(c.scheme, c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("NormalizeNativeSeverity(%s, %q) = %q, %v; want %q, %v", c.scheme, c.in, got, ok, c.want, c.ok)
		}
	}
	// SARIF table agrees with the converter.
	for _, lvl := range []string{"error", "warning", "note", "none"} {
		got, _ := NormalizeNativeSeverity(NativeSchemeSARIF, lvl)
		if got != mapSARIFLevel(lvl) {
			t.Errorf("sarif %s: table %s, converter %s", lvl, got, mapSARIFLevel(lvl))
		}
	}
}

func TestNormalizeNativeStatus(t *testing.T) {
	cases := []struct {
		scheme NativeScheme
		in     string
		status FindingStatus
		state  SourceState
		ok     bool
	}{
		{NativeSchemeQualys, "Re-Opened", FindingStatusOpen, SourceStateReopened, true},
		{NativeSchemeQualys, "New", FindingStatusOpen, SourceStateNew, true},
		{NativeSchemeQualys, "Fixed", FindingStatusResolved, SourceStateFixed, true},
		{NativeSchemeNessus, "reopened", FindingStatusOpen, SourceStateReopened, true},
		{NativeSchemeNessus, "Mitigated", FindingStatusResolved, SourceStateFixed, true},
		{NativeSchemeDefectDojo, "False Positive", FindingStatusFalsePositive, "", true},
		{NativeSchemeDefectDojo, "risk_accepted", FindingStatusAcceptedRisk, "", true},
		{NativeSchemeDefectDojo, "out-of-scope", FindingStatusSuppressed, "", true},
		{NativeSchemeSARIF, "absent", FindingStatusResolved, SourceStateFixed, true},
		{NativeSchemeSARIF, "unchanged", FindingStatusOpen, SourceStateActive, true},
		{NativeSchemeQualys, "Closed", "", "", false},
		{NativeSchemeOther, "open", "", "", false},
	}
	for _, c := range cases {
		st, state, ok := NormalizeNativeStatus(c.scheme, c.in)
		if st != c.status || state != c.state || ok != c.ok {
			t.Errorf("NormalizeNativeStatus(%s, %q) = %q, %q, %v", c.scheme, c.in, st, state, ok)
		}
		if ok && !st.IsValid() {
			t.Errorf("%s %q maps to invalid status %q", c.scheme, c.in, st)
		}
	}
	// Every table row maps to valid enum values.
	for scheme, table := range nativeStatusTables {
		if !scheme.IsValid() {
			t.Errorf("table for invalid scheme %q", scheme)
		}
		for k, row := range table {
			if !row.status.IsValid() || (row.state != "" && !row.state.IsValid()) {
				t.Errorf("%s %q: invalid row %+v", scheme, k, row)
			}
		}
	}
	for scheme, table := range nativeSeverityTables {
		for k, sev := range table {
			if !sev.IsValid() {
				t.Errorf("%s %q: invalid severity %q", scheme, k, sev)
			}
		}
	}
}

func TestNormalizeDetectionType(t *testing.T) {
	for in, want := range map[string]DetectionType{
		"Confirmed": DetectionTypeConfirmed, "Potential": DetectionTypePotential,
		"Info": DetectionTypeInfo, "Information Gathered": DetectionTypeInfo, "IG": DetectionTypeInfo,
	} {
		if got, ok := NormalizeDetectionType(in); !ok || got != want {
			t.Errorf("%q: %q %v", in, got, ok)
		}
	}
	if _, ok := NormalizeDetectionType("maybe"); ok {
		t.Error("unknown detection type mapped")
	}
}

func TestNormalizeVEX(t *testing.T) {
	for in, want := range map[string]VEXStatus{
		"known_not_affected": VEXStatusNotAffected, "not_affected": VEXStatusNotAffected,
		"exploitable": VEXStatusAffected, "known_affected": VEXStatusAffected,
		"resolved": VEXStatusFixed, "resolved_with_pedigree": VEXStatusFixed,
		"in_triage": VEXStatusUnderInvestigation, "under_investigation": VEXStatusUnderInvestigation,
	} {
		if got, ok := NormalizeVEXStatus(in); !ok || got != want {
			t.Errorf("status %q: %q %v", in, got, ok)
		}
	}
	if _, ok := NormalizeVEXStatus("false_positive"); ok {
		t.Error("false_positive is a disposition, not a VEX status")
	}
	for in, want := range map[string]VEXJustification{
		"component_not_present":            VEXJustificationComponentNotPresent,
		"code_not_present":                 VEXJustificationVulnerableCodeNotPresent,
		"code_not_reachable":               VEXJustificationVulnerableCodeNotInExecutePath,
		"requires_environment":             VEXJustificationVulnerableCodeCannotBeControlledByAdversary,
		"protected_by_mitigating_control":  VEXJustificationInlineMitigationsAlreadyExist,
		"inline_mitigations_already_exist": VEXJustificationInlineMitigationsAlreadyExist,
	} {
		if got, ok := NormalizeVEXJustification(in); !ok || got != want {
			t.Errorf("justification %q: %q %v", in, got, ok)
		}
	}
	if _, ok := NormalizeVEXJustification("because"); ok {
		t.Error("unknown justification mapped")
	}
}

func TestNormalizeVulnerabilityID(t *testing.T) {
	cases := []struct {
		in  string
		typ VulnerabilityIDType
		id  string
		ok  bool
	}{
		{"cve-2024-3094", VulnerabilityIDCVE, "CVE-2024-3094", true},
		{" CVE-2021-44228 ", VulnerabilityIDCVE, "CVE-2021-44228", true},
		{"CVE-2024-1", "", "", false},
		{"GHSA-JFH8-C2JP-5V3Q", VulnerabilityIDGHSA, "GHSA-jfh8-c2jp-5v3q", true},
		{"GHSA-aaaa-bbbb-cccc", "", "", false}, // a, b not in the GHSA alphabet
		{"pysec-2021-1", VulnerabilityIDOSV, "PYSEC-2021-1", true},
		{"GO-2022-0001", VulnerabilityIDOSV, "GO-2022-0001", true},
		{"RHSA-2024:1234", VulnerabilityIDVendor, "RHSA-2024:1234", true},
		{"", "", "", false},
		{"has space", "", "", false},
		{"bad\x00id", "", "", false},
		{strings.Repeat("A", MaxVulnerabilityIDLen+1), "", "", false},
	}
	for _, c := range cases {
		got, ok := NormalizeVulnerabilityID(c.in)
		if ok != c.ok || got.Type != c.typ || got.ID != c.id {
			t.Errorf("NormalizeVulnerabilityID(%q) = %+v, %v", c.in, got, ok)
		}
	}
}

func TestVulnerabilityIDsAndPreferred(t *testing.T) {
	v := &VulnerabilityDetails{
		CVEID:  "cve-2024-9999",
		CVEIDs: []string{"CVE-2024-0001", "CVE-2024-9999", "junk"},
		IDs: []VulnerabilityID{
			{Type: VulnerabilityIDGHSA, ID: "GHSA-jfh8-c2jp-5v3q"},
			{Type: VulnerabilityIDCVE, ID: "CVE-2024-0001"},
			{Type: VulnerabilityIDCVE, ID: "GHSA-jfh8-c2jp-5v3q"}, // wrong type: dropped
			{Type: VulnerabilityIDVendor, ID: "RHSA-2024:1", Source: " redhat "},
		},
	}
	ids := VulnerabilityIDs(v)
	want := []string{"cve:CVE-2024-9999", "cve:CVE-2024-0001", "ghsa:GHSA-jfh8-c2jp-5v3q", "vendor:RHSA-2024:1"}
	if len(ids) != len(want) {
		t.Fatalf("ids = %+v", ids)
	}
	for i, id := range ids {
		if string(id.Type)+":"+id.ID != want[i] {
			t.Errorf("ids[%d] = %+v, want %s", i, id, want[i])
		}
	}
	if ids[3].Source != "redhat" {
		t.Errorf("source not trimmed: %q", ids[3].Source)
	}
	p, ok := PreferredVulnerabilityID(v)
	if !ok || p.ID != "CVE-2024-0001" {
		t.Errorf("preferred = %+v", p)
	}
	p, ok = PreferredVulnerabilityID(&VulnerabilityDetails{IDs: []VulnerabilityID{{Type: VulnerabilityIDOSV, ID: "PYSEC-2021-1"}, {Type: VulnerabilityIDGHSA, ID: "GHSA-jfh8-c2jp-5v3q"}}})
	if !ok || p.Type != VulnerabilityIDGHSA {
		t.Errorf("GHSA must win over OSV: %+v", p)
	}
	if _, ok := PreferredVulnerabilityID(nil); ok {
		t.Error("nil details")
	}
	// Capped.
	many := &VulnerabilityDetails{}
	for i := 0; i < MaxVulnerabilityIDs+10; i++ {
		many.IDs = append(many.IDs, VulnerabilityID{Type: VulnerabilityIDVendor, ID: "V-" + strings.Repeat("x", i%5) + string(rune('a'+i%26)) + itoa(i)})
	}
	if n := len(VulnerabilityIDs(many)); n != MaxVulnerabilityIDs {
		t.Errorf("not capped: %d", n)
	}
}

func TestLocationKey(t *testing.T) {
	cases := []struct {
		name string
		f    Finding
		want string
	}{
		{"purl without version", Finding{Vulnerability: &VulnerabilityDetails{PURL: "pkg:NPM/%40babel/core@7.0.0?arch=x#sub", Package: "x"}}, "pkg:npm/%40babel/core"},
		{"package by name", Finding{Vulnerability: &VulnerabilityDetails{Package: "lodash", Ecosystem: "NPM"}}, "pkg:npm/lodash"},
		{"url", Finding{Location: &FindingLocation{Path: "HTTPS://user:pw@Example.COM:443/a/b?q=1#frag"}}, "url:https://example.com/a/b"},
		{"url port", Finding{Location: &FindingLocation{Path: "http://example.com:8080"}}, "url:http://example.com:8080/"},
		{"ipv6", Finding{Location: &FindingLocation{Path: "http://[::1]:80/x"}}, "url:http://[::1]/x"},
		{"file", Finding{Location: &FindingLocation{Path: `.\src\..\src\app.py`, StartLine: 9}}, "file:src/app.py"},
		{"network port", Finding{Network: &NetworkLocation{Port: 22}}, "net:22/tcp"},
		{"network udp", Finding{Network: &NetworkLocation{Port: 161, Protocol: "UDP"}}, "net:161/udp"},
		{"host level", Finding{Network: &NetworkLocation{}}, "net:host"},
		{"resource", Finding{Misconfiguration: &MisconfigurationDetails{ResourceType: "aws_s3_bucket", ResourceName: "logs"}}, "resource:aws_s3_bucket/logs"},
		{"none", Finding{}, ""},
	}
	for _, c := range cases {
		if got := LocationKey(&c.f); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
	if LocationKey(nil) != "" {
		t.Error("nil finding")
	}
	long := LocationKey(&Finding{Location: &FindingLocation{Path: strings.Repeat("é/", 600)}})
	if len(long) > maxLocationKeyLen || !strings.Contains(long, "#") {
		t.Errorf("long key not bounded: %d", len(long))
	}
	if long != LocationKey(&Finding{Location: &FindingLocation{Path: strings.Repeat("é/", 600)}}) {
		t.Error("bounded key not stable")
	}
}

func TestSetSourceExtra(t *testing.T) {
	var f Finding
	if !SetSourceExtra(&f, " plugin_type ", "remote") || f.SourceExtra["plugin_type"] != "remote" {
		t.Fatalf("not stored: %v", f.SourceExtra)
	}
	for _, bad := range []string{"", "   ", "a\nb", strings.Repeat("k", MaxSourceExtraKeyLen+1)} {
		if SetSourceExtra(&f, bad, "v") {
			t.Errorf("key %q accepted", bad)
		}
	}
	SetSourceExtra(&f, "long", strings.Repeat("ü", MaxSourceExtraValueLen+50))
	if n := len([]rune(f.SourceExtra["long"])); n != MaxSourceExtraValueLen {
		t.Errorf("value not cut: %d", n)
	}
	// Entry cap.
	g := Finding{}
	for i := 0; i < MaxSourceExtraEntries; i++ {
		if !SetSourceExtra(&g, "k"+itoa(i), "v") {
			t.Fatalf("entry %d refused", i)
		}
	}
	if SetSourceExtra(&g, "one-more", "v") {
		t.Error("entry cap not enforced")
	}
	if !SetSourceExtra(&g, "k1", "replaced") {
		t.Error("replacing within limits refused")
	}
	// Byte cap.
	h := Finding{}
	for i := 0; ; i++ {
		if !SetSourceExtra(&h, "k"+itoa(i), strings.Repeat("x", MaxSourceExtraValueLen)) {
			break
		}
	}
	if sourceExtraBytes(h.SourceExtra) > MaxSourceExtraBytes {
		t.Errorf("byte cap exceeded: %d", sourceExtraBytes(h.SourceExtra))
	}
	if err := interopReport(h).Validate(); err != nil {
		t.Errorf("SetSourceExtra output must validate: %v", err)
	}
	if SetSourceExtra(nil, "k", "v") {
		t.Error("nil finding")
	}
}

func TestAllScores(t *testing.T) {
	f := &Finding{
		Scores: []Score{{System: ScoreSystemCVSS, Version: "4.0", Vector: "CVSS:4.0/AV:N", Value: ptrF(9.2), Source: "vendor"}},
		Vulnerability: &VulnerabilityDetails{
			CVSSScore: 8.1, CVSSVector: "CVSS:3.1/AV:N/AC:H", CVSSSource: "nvd",
			EPSSScore: 0.4, EPSSPercentile: 0.97, VPRScore: 7.4,
		},
	}
	got := AllScores(f)
	if len(got) != 5 {
		t.Fatalf("scores = %+v", got)
	}
	if got[1].System != ScoreSystemCVSS || got[1].Version != "3.1" || got[1].Source != "nvd" || *got[1].Value != 8.1 {
		t.Errorf("legacy cvss = %+v", got[1])
	}
	// A legacy score already present in scores is not repeated.
	f.Scores = append(f.Scores, Score{System: ScoreSystemCVSS, Version: "3.1", Source: "NVD", Value: ptrF(8.1)})
	if n := len(AllScores(f)); n != 5 {
		t.Errorf("duplicate legacy cvss: %d", n)
	}
	for _, s := range AllScores(f) {
		if p := scoreProblem(s); p != "" {
			t.Errorf("AllScores produced an invalid score %+v: %s", s, p)
		}
	}
	if AllScores(nil) != nil {
		t.Error("nil finding")
	}
	if n := len(AllScores(&Finding{Scores: f.Scores})); n != 2 {
		t.Errorf("no vulnerability block: %d", n)
	}
}

func TestCVSSVersionOfVector(t *testing.T) {
	for in, want := range map[string]string{
		"CVSS:3.0/AV:N": "3.0", "CVSS:3.1/AV:N": "3.1", "CVSS:4.0/AV:N": "4.0",
		"AV:N/AC:L/Au:N/C:P/I:P/A:P": "2.0", "(AV:N/AC:L)": "2.0", "nonsense": "", "": "",
	} {
		if got := CVSSVersionOfVector(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}

func TestValidateInterop(t *testing.T) {
	ok := []Finding{
		{Native: &NativeIdentity{Scheme: NativeSchemeQualys, VulnID: "38739", DetectionType: DetectionTypePotential}},
		{Scores: []Score{{System: ScoreSystemCVSS, Version: "2.0", Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P", Value: ptrF(7.5)}}},
		{Scores: []Score{{System: ScoreSystemSSVC, Label: "Act"}}},
		{Scores: []Score{{System: ScoreSystemVendor, Value: ptrF(-3), Source: "qualys"}}},
		{Scores: []Score{{System: ScoreSystemEPSS, Value: ptrF(0)}}},
		{VEX: &VEX{Status: VEXStatusNotAffected, Statement: "not loaded"}},
		{VEX: &VEX{Status: VEXStatusAffected}},
		{SourceLifecycle: &SourceLifecycle{TimesFound: 3, State: SourceStateActive}},
		{Remediation: &Remediation{SolutionType: SolutionTypePatch, Advisories: []Advisory{{ID: "MS24-001"}}}},
	}
	for i, f := range ok {
		if err := interopReport(f).Validate(); err != nil {
			t.Errorf("ok[%d]: %v", i, err)
		}
	}

	bad := map[string]Finding{
		"native scheme":            {Native: &NativeIdentity{Scheme: "tenable"}},
		"native detection type":    {Native: &NativeIdentity{DetectionType: "maybe"}},
		"native vuln id long":      {Native: &NativeIdentity{VulnID: strings.Repeat("x", MaxNativeIDLen+1)}},
		"native raw ref long":      {Native: &NativeIdentity{RawRef: strings.Repeat("x", MaxRawRefLen+1)}},
		"native severity long":     {Native: &NativeIdentity{Severity: strings.Repeat("x", MaxNativeValueLen+1)}},
		"score system":             {Scores: []Score{{System: "cvss3", Value: ptrF(1)}}},
		"cvss no version":          {Scores: []Score{{System: ScoreSystemCVSS, Value: ptrF(5)}}},
		"cvss bad version":         {Scores: []Score{{System: ScoreSystemCVSS, Version: "3", Value: ptrF(5)}}},
		"cvss above 10":            {Scores: []Score{{System: ScoreSystemCVSS, Version: "3.1", Value: ptrF(10.5)}}},
		"cvss vector mismatch":     {Scores: []Score{{System: ScoreSystemCVSS, Version: "4.0", Vector: "CVSS:3.1/AV:N", Value: ptrF(5)}}},
		"cvss v2 with v3 prefix":   {Scores: []Score{{System: ScoreSystemCVSS, Version: "2.0", Vector: "CVSS:3.1/AV:N"}}},
		"cvss empty":               {Scores: []Score{{System: ScoreSystemCVSS, Version: "3.1"}}},
		"epss above 1":             {Scores: []Score{{System: ScoreSystemEPSS, Value: ptrF(97)}}},
		"vpr negative":             {Scores: []Score{{System: ScoreSystemVPR, Value: ptrF(-1)}}},
		"nan":                      {Scores: []Score{{System: ScoreSystemVendor, Value: ptrF(math.NaN())}}},
		"inf":                      {Scores: []Score{{System: ScoreSystemVendor, Value: ptrF(math.Inf(1))}}},
		"vendor huge":              {Scores: []Score{{System: ScoreSystemVendor, Value: ptrF(1e9)}}},
		"vendor empty":             {Scores: []Score{{System: ScoreSystemVendor}}},
		"ssvc value":               {Scores: []Score{{System: ScoreSystemSSVC, Label: "Act", Value: ptrF(1)}}},
		"ssvc empty":               {Scores: []Score{{System: ScoreSystemSSVC}}},
		"score vector long":        {Scores: []Score{{System: ScoreSystemSSVC, Vector: strings.Repeat("x", MaxScoreVectorLen+1)}}},
		"score source long":        {Scores: []Score{{System: ScoreSystemSSVC, Label: "a", Source: strings.Repeat("x", MaxScoreSourceLen+1)}}},
		"score label long":         {Scores: []Score{{System: ScoreSystemSSVC, Label: strings.Repeat("x", MaxScoreLabelLen+1)}}},
		"too many scores":          {Scores: make([]Score, MaxScores+1)},
		"vex status":               {VEX: &VEX{Status: "unaffected"}},
		"vex justification":        {VEX: &VEX{Status: VEXStatusNotAffected, Justification: "because"}},
		"vex not_affected bare":    {VEX: &VEX{Status: VEXStatusNotAffected}},
		"vex justification status": {VEX: &VEX{Status: VEXStatusAffected, Justification: VEXJustificationComponentNotPresent}},
		"vex statement long":       {VEX: &VEX{Status: VEXStatusAffected, Statement: strings.Repeat("x", MaxVEXStatementLen+1)}},
		"vex source long":          {VEX: &VEX{Status: VEXStatusAffected, Source: strings.Repeat("x", MaxVEXSourceLen+1)}},
		"vex native long":          {VEX: &VEX{Status: VEXStatusAffected, NativeJustification: strings.Repeat("x", MaxNativeValueLen+1)}},
		"lifecycle state":          {SourceLifecycle: &SourceLifecycle{State: "closed"}},
		"lifecycle negative":       {SourceLifecycle: &SourceLifecycle{TimesFound: -1}},
		"lifecycle huge":           {SourceLifecycle: &SourceLifecycle{TimesFound: MaxTimesFound + 1}},
		"extra key control":        {SourceExtra: map[string]string{"a\x01": "v"}},
		"extra key empty":          {SourceExtra: map[string]string{"": "v"}},
		"extra value long":         {SourceExtra: map[string]string{"k": strings.Repeat("x", MaxSourceExtraValueLen+1)}},
		"extra too many":           {SourceExtra: manyExtra(MaxSourceExtraEntries + 1)},
		"extra too big":            {SourceExtra: bigExtra()},
		"id wrong type":            {Vulnerability: &VulnerabilityDetails{IDs: []VulnerabilityID{{Type: VulnerabilityIDCVE, ID: "GHSA-jfh8-c2jp-5v3q"}}}},
		"id bad type":              {Vulnerability: &VulnerabilityDetails{IDs: []VulnerabilityID{{Type: "nvd", ID: "CVE-2024-1234"}}}},
		"id empty":                 {Vulnerability: &VulnerabilityDetails{IDs: []VulnerabilityID{{Type: VulnerabilityIDVendor}}}},
		"id source long":           {Vulnerability: &VulnerabilityDetails{IDs: []VulnerabilityID{{Type: VulnerabilityIDVendor, ID: "X-1", Source: strings.Repeat("x", 65)}}}},
		"too many ids":             {Vulnerability: &VulnerabilityDetails{IDs: make([]VulnerabilityID, MaxVulnerabilityIDs+1)}},
		"solution type":            {Remediation: &Remediation{SolutionType: "reboot"}},
		"advisory empty":           {Remediation: &Remediation{Advisories: []Advisory{{Source: "x"}}}},
		"advisory long":            {Remediation: &Remediation{Advisories: []Advisory{{URL: "https://x/" + strings.Repeat("a", MaxAdvisoryURLLen)}}}},
		"too many advisories":      {Remediation: &Remediation{Advisories: make([]Advisory, MaxAdvisories+1)}},
	}
	for name, f := range bad {
		if err := interopReport(f).Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func manyExtra(n int) map[string]string {
	m := map[string]string{}
	for i := 0; i < n; i++ {
		m["k"+itoa(i)] = "v"
	}
	return m
}

func bigExtra() map[string]string {
	m := map[string]string{}
	for i := 0; i < 9; i++ {
		m["k"+itoa(i)] = strings.Repeat("x", MaxSourceExtraValueLen)
	}
	return m
}

func TestValidateIdentityHints(t *testing.T) {
	r := NewReport()
	r.Metadata.Timestamp = time.Now()
	r.Assets = []Asset{{Type: AssetTypeHost, Value: "10.0.0.1", IdentityHints: &IdentityHints{FQDN: "a.example.com", MACAddresses: []string{"00:11:22:33:44:55"}}}}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, h := range map[string]*IdentityHints{
		"fqdn long":  {FQDN: strings.Repeat("a", MaxIdentityHintLen+1)},
		"agent long": {ScannerAgentID: strings.Repeat("a", MaxIdentityHintLen+1)},
		"many macs":  {MACAddresses: make([]string, MaxIdentityHintMACs+1)},
		"mac long":   {MACAddresses: []string{strings.Repeat("a", 65)}},
	} {
		r.Assets[0].IdentityHints = h
		if err := r.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// A 1.3 report (no interop members) decodes strictly and validates under 1.4,
// and a 1.4 report round-trips through JSON unchanged.
func TestInteropBackwardCompatibleAndRoundTrip(t *testing.T) {
	old := []byte(`{"version":"1.3","metadata":{"timestamp":"2026-10-02T00:00:00Z"},"findings":[{"type":"vulnerability","title":"t","severity":"high","vulnerability":{"cve_id":"CVE-2021-23017","cvss_version":"3.1","cvss_score":7.7}}]}`)
	r, err := decodeStrict(old)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	cred := false
	f := Finding{
		Native:          &NativeIdentity{Scheme: NativeSchemeNessus, VulnID: "201194", Severity: "3", Credentialed: &cred},
		Scores:          []Score{{System: ScoreSystemCVSS, Version: "4.0", Vector: "CVSS:4.0/AV:N", Value: ptrF(0)}},
		VEX:             &VEX{Status: VEXStatusNotAffected, Justification: VEXJustificationComponentNotPresent},
		SourceLifecycle: &SourceLifecycle{TimesFound: 2, State: SourceStateReopened},
		SourceExtra:     map[string]string{"k": "v"},
	}
	rep := interopReport(f)
	raw, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	// Explicit false and zero survive: they are pointers.
	if !strings.Contains(string(raw), `"credentialed":false`) || !strings.Contains(string(raw), `"value":0`) {
		t.Errorf("explicit zero values lost: %s", raw)
	}
	back, err := decodeStrict(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := back.Validate(); err != nil {
		t.Fatal(err)
	}
	raw2, _ := json.Marshal(back)
	if string(raw) != string(raw2) {
		t.Errorf("round trip changed the report:\n%s\n%s", raw, raw2)
	}
	if errs := loadSchemaSet(t).validateJSON(raw, "report.json"); len(errs) > 0 {
		t.Errorf("schema rejects a valid 1.4 report: %v", errs)
	}
}

func TestSupportedSchemaVersions(t *testing.T) {
	got := SupportedSchemaVersions()
	want := []string{"1.0", "1.1", "1.2", "1.3", "1.4"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("SupportedSchemaVersions = %v, want %v", got, want)
	}
	if got[len(got)-1] != SchemaVersion {
		t.Errorf("last supported %s is not SchemaVersion %s", got[len(got)-1], SchemaVersion)
	}
	for _, v := range want {
		if !IsSupportedVersion(v) || !IsCompatibleVersion(v) {
			t.Errorf("%s not supported", v)
		}
		// Every supported version still decodes strictly and validates.
		raw := []byte(`{"version":"` + v + `","metadata":{"timestamp":"2026-10-02T00:00:00Z"},"findings":[{"type":"vulnerability","title":"t","severity":"high"}]}`)
		r, err := decodeStrict(raw)
		if err != nil {
			t.Fatalf("%s: %v", v, err)
		}
		if err := r.Validate(); err != nil {
			t.Errorf("%s: %v", v, err)
		}
	}
	for _, v := range []string{"1.5", "2.0", "0.9", "", "1.03"} {
		if IsSupportedVersion(v) {
			t.Errorf("%q reported supported", v)
		}
	}
}
