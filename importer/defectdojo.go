package importer

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode"

	"github.com/openctemio/ctis"
)

// DefectDojo Generic Findings Import JSON: {"name", "type", "version",
// "findings": [...]}. The mapping is spec_defectdojo.go.

func init() {
	parsers[FormatDefectDojo] = parseDefectDojo
	tools[FormatDefectDojo] = ctis.Tool{Name: "defectdojo"}
}

// flexStr reads a JSON string, number or boolean as text (DefectDojo
// exports write cwe, line, port and scores either way). null is empty.
type flexStr string

func (f *flexStr) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || bytes.Equal(b, []byte("null")) {
		*f = ""
		return nil
	}
	if b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*f = flexStr(s)
		return nil
	}
	if b[0] == '{' || b[0] == '[' {
		return fmt.Errorf("want a string, number or boolean")
	}
	*f = flexStr(b)
	return nil
}

func (f flexStr) String() string { return strings.TrimSpace(string(f)) }

// Bool reads true, "true", 1, "1", "yes".
func (f flexStr) Bool() bool { return truthy(f.String()) }

type ddEndpoint struct {
	Protocol flexStr `json:"protocol"`
	UserInfo flexStr `json:"userinfo"`
	Host     flexStr `json:"host"`
	Port     flexStr `json:"port"`
	Path     flexStr `json:"path"`
	Query    flexStr `json:"query"`
	Fragment flexStr `json:"fragment"`
}

// UnmarshalJSON reads an endpoint object or a URL string.
func (e *ddEndpoint) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) > 0 && b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		u, err := url.Parse(strings.TrimSpace(s))
		if err != nil || u.Host == "" {
			// A bare host name.
			*e = ddEndpoint{Host: flexStr(s)}
			return nil
		}
		*e = ddEndpoint{Protocol: flexStr(u.Scheme), Host: flexStr(u.Hostname()), Port: flexStr(u.Port()), Path: flexStr(u.EscapedPath()), Query: flexStr(u.RawQuery), Fragment: flexStr(u.Fragment)}
		return nil
	}
	type plain ddEndpoint
	var p plain
	if err := json.Unmarshal(b, &p); err != nil {
		return err
	}
	*e = ddEndpoint(p)
	return nil
}

type ddVulnID struct {
	ID flexStr `json:"vulnerability_id"`
}

type ddFinding struct {
	Title                     flexStr      `json:"title"`
	Description               flexStr      `json:"description"`
	Severity                  flexStr      `json:"severity"`
	NumericalSeverity         flexStr      `json:"numerical_severity"`
	SeverityJustification     flexStr      `json:"severity_justification"`
	Mitigation                flexStr      `json:"mitigation"`
	Impact                    flexStr      `json:"impact"`
	References                flexStr      `json:"references"`
	StepsToReproduce          flexStr      `json:"steps_to_reproduce"`
	Date                      flexStr      `json:"date"`
	PublishDate               flexStr      `json:"publish_date"`
	CVE                       flexStr      `json:"cve"`
	CWE                       flexStr      `json:"cwe"`
	VulnerabilityIDs          []ddVulnID   `json:"vulnerability_ids"`
	CVSSv3                    flexStr      `json:"cvssv3"`
	CVSSv3Score               flexStr      `json:"cvssv3_score"`
	CVSSv4                    flexStr      `json:"cvssv4"`
	CVSSv4Score               flexStr      `json:"cvssv4_score"`
	EPSSScore                 flexStr      `json:"epss_score"`
	EPSSPercentile            flexStr      `json:"epss_percentile"`
	KnownExploited            flexStr      `json:"known_exploited"`
	RansomwareUsed            flexStr      `json:"ransomware_used"`
	KEVDate                   flexStr      `json:"kev_date"`
	Active                    *flexStr     `json:"active"`
	Verified                  flexStr      `json:"verified"`
	FalseP                    flexStr      `json:"false_p"`
	Duplicate                 flexStr      `json:"duplicate"`
	OutOfScope                flexStr      `json:"out_of_scope"`
	RiskAccepted              flexStr      `json:"risk_accepted"`
	IsMitigated               flexStr      `json:"is_mitigated"`
	Mitigated                 flexStr      `json:"mitigated"`
	UnderReview               flexStr      `json:"under_review"`
	FilePath                  flexStr      `json:"file_path"`
	Line                      flexStr      `json:"line"`
	SASTSourceObject          flexStr      `json:"sast_source_object"`
	SASTSinkObject            flexStr      `json:"sast_sink_object"`
	SASTSourceLine            flexStr      `json:"sast_source_line"`
	SASTSourceFilePath        flexStr      `json:"sast_source_file_path"`
	ComponentName             flexStr      `json:"component_name"`
	ComponentVersion          flexStr      `json:"component_version"`
	FixAvailable              flexStr      `json:"fix_available"`
	FixVersion                flexStr      `json:"fix_version"`
	VulnIDFromTool            flexStr      `json:"vuln_id_from_tool"`
	UniqueIDFromTool          flexStr      `json:"unique_id_from_tool"`
	Endpoints                 []ddEndpoint `json:"endpoints"`
	Tags                      []flexStr    `json:"tags"`
	Service                   flexStr      `json:"service"`
	PlannedRemediationDate    flexStr      `json:"planned_remediation_date"`
	PlannedRemediationVersion flexStr      `json:"planned_remediation_version"`
	EffortForFixing           flexStr      `json:"effort_for_fixing"`
	StaticFinding             flexStr      `json:"static_finding"`
	DynamicFinding            flexStr      `json:"dynamic_finding"`
	Payload                   flexStr      `json:"payload"`
	Param                     flexStr      `json:"param"`
	NbOccurences              flexStr      `json:"nb_occurences"` //nolint:misspell // the source field is spelled this way
	HashCode                  flexStr      `json:"hash_code"`
}

type ddDocument struct {
	Name        flexStr           `json:"name"`
	Type        flexStr           `json:"type"`
	Version     flexStr           `json:"version"`
	Description flexStr           `json:"description"`
	Findings    []json.RawMessage `json:"findings"`
}

const ddFindings = "/findings[]"

func parseDefectDojo(b *builder, r io.Reader) error {
	data, err := readAll(r, FormatDefectDojo, b.lim)
	if err != nil {
		return err
	}
	doc, err := scanJSON(data, FormatDefectDojo, b.lim, b.obs, ddFindings)
	if err != nil {
		return err
	}
	var top ddDocument
	if err := doc.decode(&top); err != nil {
		return err
	}
	if top.Findings == nil {
		return &ParseError{Format: FormatDefectDojo, Msg: "no findings array", Err: ErrMalformed}
	}
	if name := line(top.Name.String(), capShort); name != "" {
		b.res.Report.Tool.Name = name
		if b.opts.ToolName != "" {
			b.res.Report.Tool.Name = b.opts.ToolName
		}
	}
	if v := line(top.Version.String(), 64); v != "" {
		b.res.Report.Tool.Version = v
	}
	props := ctis.Properties{}
	if t := line(top.Type.String(), capShort); t != "" {
		props["scan_type"] = t
	}
	if d := text(top.Description.String(), 4<<10); d != "" {
		props["description"] = d
	}
	if len(props) > 0 {
		b.res.Report.Metadata.Properties = props
	}

	for i, raw := range top.Findings {
		b.res.Stats.Records++
		if err := b.tick(); err != nil {
			return err
		}
		ptr := "/findings/" + strconv.Itoa(i)
		var f ddFinding
		if err := json.Unmarshal(raw, &f); err != nil {
			b.issue(doc.issueAt(ddFindings, i, ptr, "skipped: "+jsonErrText(err)))
			b.res.Stats.Skipped++
			continue
		}
		n, err := b.ddFinding(&f, doc, i, ptr)
		if err != nil {
			return err
		}
		if n == 0 {
			b.res.Stats.Skipped++
		}
	}
	return nil
}

// jsonErrText words a decode error without echoing input bytes.
func jsonErrText(err error) string {
	var te *json.UnmarshalTypeError
	if errors.As(err, &te) {
		field := te.Field
		if field == "" {
			field = "value"
		}
		return fmt.Sprintf("%s has the wrong type (JSON %s)", field, te.Value)
	}
	return "a member has a value of the wrong type"
}

// ddStatus returns the native status word of the flags, in the order a
// disposition outranks a lifecycle state.
func ddStatus(f *ddFinding) string {
	switch {
	case f.FalseP.Bool():
		return "false_positive"
	case f.RiskAccepted.Bool():
		return "risk_accepted"
	case f.OutOfScope.Bool():
		return "out_of_scope"
	case f.Duplicate.Bool():
		return "duplicate"
	case f.IsMitigated.Bool():
		return "is_mitigated"
	case f.Active != nil && !f.Active.Bool():
		return "inactive"
	case f.Verified.Bool():
		return "verified"
	}
	return "active"
}

// ddFinding adds one finding per endpoint host (one when there is none) and
// returns how many it added.
func (b *builder) ddFinding(d *ddFinding, doc *jsonDoc, i int, ptr string) (int, error) {
	title := line(d.Title.String(), capTitle)
	if title == "" {
		b.issue(doc.issueAt(ddFindings, i, ptr, "finding without a title: skipped"))
		return 0, nil
	}
	nativeSev := d.Severity.String()
	sev, ok := ctis.NormalizeNativeSeverity(ctis.NativeSchemeDefectDojo, nativeSev)
	if !ok {
		b.issue(doc.issueAt(ddFindings, i, ptr, fmt.Sprintf("unknown severity %q, kept as medium", line(nativeSev, 32))))
		sev = ctis.SeverityMedium
	}
	f := ctis.Finding{
		Type:        ctis.FindingTypeVulnerability,
		Title:       title,
		Severity:    sev,
		Description: text(d.Description.String(), capDescription),
		Native: &ctis.NativeIdentity{
			Scheme:     ctis.NativeSchemeDefectDojo,
			VulnID:     line(d.VulnIDFromTool.String(), ctis.MaxNativeIDLen),
			InstanceID: line(d.UniqueIDFromTool.String(), ctis.MaxNativeIDLen),
			Severity:   line(nativeSev, ctis.MaxNativeValueLen),
			RawRef:     ptr,
		},
	}
	if f.Native.VulnID != "" {
		f.RuleID = f.Native.VulnID
		f.RuleName = title
	}
	nativeStatus := ddStatus(d)
	f.Native.Status = nativeStatus
	lc := &ctis.SourceLifecycle{FirstFound: parseTime(d.Date.String()), LastFixed: parseTime(d.Mitigated.String())}
	if status, state, ok := ctis.NormalizeNativeStatus(ctis.NativeSchemeDefectDojo, nativeStatus); ok {
		f.Status = status
		lc.State = state
	}
	if d.Verified.Bool() && nativeStatus == "active" || nativeStatus == "verified" {
		f.Native.DetectionType = ctis.DetectionTypeConfirmed
	}
	if lc.FirstFound != nil || lc.LastFixed != nil || lc.State != "" {
		f.SourceLifecycle = lc
	}
	f.FirstSeenAt = lc.FirstFound

	vuln := &ctis.VulnerabilityDetails{}
	addVulnID(vuln, d.CVE.String())
	for _, v := range d.VulnerabilityIDs {
		addVulnID(vuln, v.ID.String())
	}
	if c := strings.TrimPrefix(strings.ToUpper(d.CWE.String()), "CWE-"); c != "" && c != "0" {
		if n, err := strconv.Atoi(c); err == nil && n > 0 {
			vuln.CWEID = "CWE-" + c
			vuln.CWEIDs = []string{vuln.CWEID}
		}
	}
	for _, c := range []struct{ vec, score, def string }{{d.CVSSv3.String(), d.CVSSv3Score.String(), "3.1"}, {d.CVSSv4.String(), d.CVSSv4Score.String(), "4.0"}} {
		if c.vec == "" && c.score == "" {
			continue
		}
		ver := ctis.CVSSVersionOfVector(c.vec)
		if ver == "" {
			ver = c.def
		}
		s := ctis.Score{System: ctis.ScoreSystemCVSS, Version: ver, Vector: line(c.vec, ctis.MaxScoreVectorLen), Source: "defectdojo"}
		if v, ok := parseScore(c.score, 10); ok {
			vc := v
			s.Value = &vc
			if vuln.CVSSVersion == "" {
				vuln.CVSSScore, vuln.CVSSVersion, vuln.CVSSVector, vuln.CVSSSource = v, ver, s.Vector, "vendor"
			}
		}
		addScore(&f, s)
	}
	if v, ok := parseScore(d.EPSSScore.String(), 1); ok {
		vuln.EPSSScore = v
		vc := v
		addScore(&f, ctis.Score{System: ctis.ScoreSystemEPSS, Value: &vc, Source: "first"})
	}
	if v, ok := parseScore(d.EPSSPercentile.String(), 1); ok {
		vuln.EPSSPercentile = v
		vc := v
		addScore(&f, ctis.Score{System: ctis.ScoreSystemEPSSPercentile, Value: &vc, Source: "first"})
	}
	if d.KnownExploited.Bool() {
		vuln.InCISAKEV = true
		vuln.ExploitAvailable = true
	}
	vuln.Package = line(d.ComponentName.String(), capShort)
	vuln.AffectedVersion = line(d.ComponentVersion.String(), 128)
	vuln.FixedVersion = line(d.FixVersion.String(), 128)
	vuln.PublishedAt = parseTime(d.PublishDate.String())
	if vuln.CVEID != "" || len(vuln.IDs) > 0 || vuln.CWEID != "" || vuln.CVSSScore > 0 || vuln.EPSSScore > 0 || vuln.Package != "" || vuln.InCISAKEV || vuln.PublishedAt != nil {
		f.Vulnerability = vuln
	}

	if m := text(d.Mitigation.String(), capRemediation); m != "" || d.FixAvailable.Bool() || d.FixVersion.String() != "" {
		f.Remediation = &ctis.Remediation{Recommendation: m, FixAvailable: d.FixAvailable.Bool() || d.FixVersion.String() != ""}
	}
	if e := strings.ToLower(d.EffortForFixing.String()); e == "low" || e == "medium" || e == "high" {
		if f.Remediation == nil {
			f.Remediation = &ctis.Remediation{}
		}
		f.Remediation.Effort = e
	}
	for _, ref := range splitLines(d.References.String()) {
		for _, w := range strings.Fields(ref) {
			if validURL(w) {
				f.References = addRefs(f.References, strings.Trim(w, "()<>[],"))
			}
		}
	}
	for _, t := range d.Tags {
		f.Tags = addTags(f.Tags, t.String())
	}
	if p := line(d.FilePath.String(), 1024); p != "" {
		f.Location = &ctis.FindingLocation{Path: p}
		if n, err := strconv.Atoi(d.Line.String()); err == nil && n > 0 {
			f.Location.StartLine = n
		}
	}
	if n, err := strconv.Atoi(d.NbOccurences.String()); err == nil && n > 0 {
		f.OccurrenceCount = n
	}
	if p := d.Payload.String(); p != "" {
		f.Evidence = text(p, capEvidence)
	}
	extras(&f,
		"impact", d.Impact.String(),
		"steps_to_reproduce", d.StepsToReproduce.String(),
		"severity_justification", d.SeverityJustification.String(),
		"references", d.References.String(),
		"ransomware_used", d.RansomwareUsed.String(),
		"kev_date", d.KEVDate.String(),
		"mitigated", d.Mitigated.String(),
		"under_review", d.UnderReview.String(),
		"sast_source_object", d.SASTSourceObject.String(),
		"sast_sink_object", d.SASTSinkObject.String(),
		"sast_source_line", d.SASTSourceLine.String(),
		"sast_source_file_path", d.SASTSourceFilePath.String(),
		"service", d.Service.String(),
		"planned_remediation_date", d.PlannedRemediationDate.String(),
		"planned_remediation_version", d.PlannedRemediationVersion.String(),
		"static_finding", d.StaticFinding.String(),
		"dynamic_finding", d.DynamicFinding.String(),
		"param", d.Param.String(),
	)

	// The asset: each endpoint host, else the file's code base, else the
	// import's default asset.
	type target struct {
		asset ctis.Asset
		ep    *ddEndpoint
	}
	var targets []target
	seen := map[string]bool{}
	for k := range d.Endpoints {
		ep := &d.Endpoints[k]
		host := strings.ToLower(strings.TrimSuffix(line(ep.Host.String(), capShort), "."))
		if host == "" || seen[host] {
			continue
		}
		seen[host] = true
		a := ctis.Asset{ID: "host-" + host, Type: ctis.AssetTypeDomain, Value: host, Name: host}
		if net.ParseIP(host) != nil {
			a.Type = ctis.AssetTypeIPAddress
		}
		targets = append(targets, target{a, ep})
	}
	if len(targets) == 0 {
		targets = append(targets, target{asset: b.defaultAsset()})
	}
	added := 0
	for _, t := range targets {
		id, err := b.asset(t.asset)
		if err != nil {
			return added, err
		}
		g := f
		g.AssetRef = id
		if t.ep != nil {
			g.Network, g.SourceExtra = ddNetwork(t.ep, t.asset.Value, f.SourceExtra)
		}
		before := len(b.res.Report.Findings)
		if err := b.finding(g); err != nil {
			return added, err
		}
		added += len(b.res.Report.Findings) - before
	}
	return added, nil
}

// ddNetwork returns the network location of an endpoint and the finding's
// source_extra with the endpoint's URL (a copy, so findings of other
// endpoints keep their own).
func ddNetwork(ep *ddEndpoint, host string, extraIn map[string]string) (*ctis.NetworkLocation, map[string]string) {
	proto := strings.ToLower(line(ep.Protocol.String(), 16))
	n := &ctis.NetworkLocation{Host: host}
	if p, err := strconv.Atoi(ep.Port.String()); err == nil && p > 0 && p <= 65535 {
		n.Port = p
		n.Protocol = "tcp"
	}
	switch proto {
	case "", "tcp", "udp":
		if proto != "" {
			n.Protocol = proto
		}
	default:
		n.Service = proto
		if n.Port == 0 {
			if p, ok := map[string]int{"http": 80, "https": 443, "ssh": 22, "ftp": 21}[proto]; ok {
				n.Port, n.Protocol = p, "tcp"
			}
		}
	}
	out := make(map[string]string, len(extraIn)+1)
	for k, v := range extraIn {
		out[k] = v
	}
	u := url.URL{Scheme: proto, Host: host, Path: ep.Path.String(), RawQuery: ep.Query.String(), Fragment: ep.Fragment.String()}
	if n.Port > 0 {
		u.Host = net.JoinHostPort(host, strconv.Itoa(n.Port))
	}
	if proto != "" && (u.Path != "" || u.RawQuery != "") {
		probe := ctis.Finding{SourceExtra: out}
		extra(&probe, "endpoint", u.String())
		out = probe.SourceExtra
	}
	if len(out) == 0 {
		out = nil
	}
	return n, out
}

// defaultAsset is the asset of records that name none: Options.DefaultAsset,
// else an unclassified asset named after the tool.
func (b *builder) defaultAsset() ctis.Asset {
	if a := b.opts.DefaultAsset; a != nil && a.Value != "" {
		out := *a
		if out.Type == "" {
			out.Type = ctis.AssetTypeUnclassified
		}
		if out.ID == "" {
			out.ID = string(out.Type) + "-" + out.Value
		}
		return out
	}
	name := "import"
	if b.res.Report.Tool != nil && b.res.Report.Tool.Name != "" {
		name = b.res.Report.Tool.Name
	}
	v := line(slug(name)+"-import", capShort)
	return ctis.Asset{ID: "unclassified-" + v, Type: ctis.AssetTypeUnclassified, Value: v, Name: v}
}

// slug lower-cases s and turns every run of other characters than letters
// and digits into one hyphen.
func slug(s string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(s) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
			dash = false
			continue
		}
		if !dash && b.Len() > 0 {
			b.WriteByte('-')
			dash = true
		}
	}
	return strings.TrimSuffix(b.String(), "-")
}
