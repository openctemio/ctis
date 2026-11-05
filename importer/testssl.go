package importer

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/openctemio/ctis/v2"
)

// testssl.sh JSON: the flat file (--jsonfile, one array of checks) or the
// pretty file (--jsonfile-pretty, checks grouped by section under each
// scanned endpoint). Each check names an endpoint ("name/address" and a
// port), a severity and a finding text. Checks of severity LOW and above
// become findings on the service; OK, INFO and DEBUG checks are passes and
// are not findings; WARN and FATAL are scan problems (issues). The mapping
// is spec_testssl.go.

func init() {
	parsers[FormatTestssl] = parseTestssl
	tools[FormatTestssl] = ctis.Tool{Name: "testssl.sh", InfoURL: "https://testssl.sh", Techniques: []ctis.Technique{ctis.TechniqueVA}}
}

// testsslCheck is one check of either file.
type testsslCheck struct {
	ID       string `json:"id"`
	IP       string `json:"ip"`
	Port     string `json:"port"`
	Severity string `json:"severity"`
	CVE      string `json:"cve"`
	CWE      string `json:"cwe"`
	Hint     string `json:"hint"`
	Finding  string `json:"finding"`
}

// testsslTarget is one endpoint of the pretty file.
type testsslTarget struct {
	TargetHost string `json:"targetHost"`
	IP         string `json:"ip"`
	Port       string `json:"port"`
	RDNS       string `json:"rDNS"`
	Service    string `json:"service"`
}

// testsslSeverity maps the check severities that are findings.
var testsslSeverity = map[string]ctis.Severity{
	"LOW":      ctis.SeverityLow,
	"MEDIUM":   ctis.SeverityMedium,
	"HIGH":     ctis.SeverityHigh,
	"CRITICAL": ctis.SeverityCritical,
}

func parseTestssl(b *Builder, r io.Reader) error {
	data, err := readAll(r, FormatTestssl, b.lim)
	if err != nil {
		return err
	}
	head := strings.TrimLeft(string(data[:min(len(data), 64)]), " \t\r\n")
	t := &testsslRun{b: b, seen: map[string]int{}}
	if strings.HasPrefix(head, "[") {
		doc, err := scanJSON(data, FormatTestssl, b.lim, b.obs, "/[]")
		if err != nil {
			return err
		}
		var checks []json.RawMessage
		if err := doc.decode(&checks); err != nil {
			return err
		}
		for i, raw := range checks {
			var c testsslCheck
			ptr := "/" + strconv.Itoa(i)
			if err := json.Unmarshal(raw, &c); err != nil {
				b.issue(doc.issueAt("/[]", i, ptr, "skipped: "+jsonErrText(err)))
				b.res.Stats.Records++
				b.res.Stats.Skipped++
				continue
			}
			host, ip := splitTestsslTarget(c.IP)
			if err := t.check(&c, host, ip, c.Port, ptr); err != nil {
				return err
			}
		}
	} else {
		doc, err := scanJSON(data, FormatTestssl, b.lim, b.obs, "/scanResult[]")
		if err != nil {
			return err
		}
		var pretty struct {
			Version    string                       `json:"version"`
			ScanResult []map[string]json.RawMessage `json:"scanResult"`
		}
		if err := doc.decode(&pretty); err != nil {
			return err
		}
		if v := line(pretty.Version, 64); v != "" && b.res.Report.Tool != nil {
			b.res.Report.Tool.Version = v
		}
		for i, sr := range pretty.ScanResult {
			var tg testsslTarget
			for k, dst := range map[string]*string{"targetHost": &tg.TargetHost, "ip": &tg.IP, "port": &tg.Port} {
				if raw, ok := sr[k]; ok {
					_ = json.Unmarshal(raw, dst)
				}
			}
			host, ip := splitTestsslTarget(tg.IP)
			if n, ok := dnsName(strings.TrimSuffix(tg.TargetHost, ".")); ok {
				host = n
			}
			sections := make([]string, 0, len(sr))
			for k := range sr {
				sections = append(sections, k)
			}
			sort.Strings(sections)
			for _, sec := range sections {
				var checks []testsslCheck
				if json.Unmarshal(sr[sec], &checks) != nil {
					continue // not a section: a member of the target
				}
				for j := range checks {
					ptr := fmt.Sprintf("/scanResult/%d/%s/%d", i, sec, j)
					if err := t.check(&checks[j], host, ip, tg.Port, ptr); err != nil {
						return err
					}
				}
			}
		}
	}
	if t.passes > 0 {
		b.issue(Issue{Message: fmt.Sprintf("%d checks passed or were informational (OK, INFO, DEBUG): not findings", t.passes)})
	}
	b.stampImportScope()
	return nil
}

type testsslRun struct {
	b      *Builder
	seen   map[string]int // asset id + check id -> finding index
	passes int
}

// splitTestsslTarget reads "name/address" (or a bare address or name).
func splitTestsslTarget(s string) (host, ip string) {
	s = strings.TrimSpace(s)
	name, addr, ok := strings.Cut(s, "/")
	if !ok {
		if p := net.ParseIP(s); p != nil {
			return "", p.String()
		}
		name = s
	}
	if p := net.ParseIP(strings.TrimSpace(addr)); p != nil {
		ip = p.String()
	}
	if n, ok := dnsName(strings.TrimSuffix(name, ".")); ok {
		host = n
	} else if p := net.ParseIP(name); p != nil && ip == "" {
		ip = p.String()
	}
	return host, ip
}

// endpoint returns the service asset of the endpoint, with its name and
// address assets.
func (t *testsslRun) endpoint(host, ip, port string) (string, int, error) {
	b := t.b
	p, err := strconv.Atoi(strings.TrimSpace(port))
	if err != nil || p < 1 || p > 65535 {
		return "", 0, nil
	}
	var hostID, ipID string
	if ip != "" {
		ver := 4
		if strings.Contains(ip, ":") {
			ver = 6
		}
		if ipID, err = b.asset(ctis.Asset{Type: ctis.AssetTypeIPAddress, Value: ip, Name: ip,
			Technical: &ctis.AssetTechnical{IPAddress: &ctis.IPAddressTechnical{Version: ver}}}); err != nil {
			return "", 0, err
		}
	}
	if host != "" {
		if hostID, err = b.asset(ctis.Asset{Type: ctis.AssetTypeDomainName, Value: host, Name: host}); err != nil {
			return "", 0, err
		}
		b.relate(ctis.RelResolvesTo, hostID, ipID)
	} else {
		hostID = ipID
	}
	if hostID == "" {
		return "", 0, nil
	}
	id := b.service(hostID, p, ctis.TransportTCP, "")
	if id != "" {
		if svc := b.assetByID(id); svc != nil && svc.Technical != nil && svc.Technical.Service != nil {
			svc.Technical.Service.IsTLS = true
			svc.Technical.Service.State = ctis.PortOpen
		}
	}
	return id, p, nil
}

func (t *testsslRun) check(c *testsslCheck, host, ip, port, ptr string) error {
	b := t.b
	if err := b.tick(); err != nil {
		return err
	}
	sevWord := strings.ToUpper(strings.TrimSpace(c.Severity))
	id := line(c.ID, capShort)
	if testsslSummary(id) {
		// The rating section sums up the other checks: a grade is not a
		// finding of its own.
		t.passes++
		return nil
	}
	switch sevWord {
	case "OK", "INFO", "DEBUG":
		t.passes++
		// The endpoint was scanned: it is an asset even without findings.
		_, _, err := t.endpoint(host, ip, port)
		return err
	case "WARN", "FATAL":
		b.issue(Issue{Path: ptr, Message: fmt.Sprintf("testssl %s %s: %s", strings.ToLower(sevWord), id, line(c.Finding, 200))})
		return nil
	}
	b.res.Stats.Records++
	sev, ok := testsslSeverity[sevWord]
	if !ok || id == "" {
		b.issue(Issue{Path: ptr, Message: fmt.Sprintf("check %q with severity %q: skipped", id, line(c.Severity, 16))})
		b.res.Stats.Skipped++
		return nil
	}
	assetID, p, err := t.endpoint(host, ip, port)
	if err != nil {
		return err
	}
	if assetID == "" {
		b.issue(Issue{Path: ptr, Message: fmt.Sprintf("check %s without a usable endpoint (%q port %q): skipped", id, line(c.IP, 100), line(port, 8))})
		b.res.Stats.Skipped++
		return nil
	}
	if i, dup := t.seen[assetID+"\x1f"+id]; dup {
		// The same check of the same name on another of its addresses.
		b.res.Report.Findings[i].OccurrenceCount++
		return nil
	}
	finding := line(c.Finding, capDescription)
	f := ctis.Finding{
		Type:     ctis.FindingTypeMisconfiguration,
		Title:    line("TLS check "+id+": "+line(c.Finding, 120), capTitle),
		Severity: sev,
		Category: "tls",
		RuleID:   id,
		AssetRef: assetID,
		Message:  finding,
		Network:  &ctis.NetworkLocation{Port: p, Transport: ctis.TransportTCP},
		Native: &ctis.NativeIdentity{
			Scheme:   ctis.NativeSchemeOther,
			VulnID:   id,
			Severity: line(sevWord, ctis.MaxNativeValueLen),
			RawRef:   line(ptr, ctis.MaxRawRefLen),
		},
		OccurrenceCount: 1,
	}
	for _, cve := range strings.Fields(c.CVE) {
		if f.Vulnerability == nil {
			f.Vulnerability = &ctis.VulnerabilityDetails{}
		}
		addVulnID(f.Vulnerability, cve)
	}
	for _, cwe := range strings.Fields(c.CWE) {
		if n, ok := strings.CutPrefix(strings.ToUpper(cwe), "CWE-"); ok {
			if _, err := strconv.Atoi(n); err == nil {
				if f.Vulnerability == nil {
					f.Vulnerability = &ctis.VulnerabilityDetails{}
				}
				f.Vulnerability.CWEIDs = appendUnique(f.Vulnerability.CWEIDs, "CWE-"+n)
			}
		}
	}
	if f.Vulnerability != nil && len(f.Vulnerability.IDs) > 0 {
		f.Type = ctis.FindingTypeVulnerability
	}
	if h := text(c.Hint, capRemediation); h != "" {
		f.Remediation = &ctis.Remediation{Recommendation: h}
	}
	if b.opts.DefaultConfidence > 0 {
		f.Confidence = b.opts.DefaultConfidence
	}
	t.seen[assetID+"\x1f"+id] = len(b.res.Report.Findings)
	n := len(b.res.Report.Findings)
	if err := b.finding(f); err != nil {
		return err
	}
	if len(b.res.Report.Findings) == n {
		delete(t.seen, assetID+"\x1f"+id) // below the minimum severity
	}
	return nil
}

// testsslSummary reports whether a check id is a score, a grade or a scan
// statistic rather than a check.
func testsslSummary(id string) bool {
	for _, p := range []string{"overall_grade", "final_score", "grade_cap_", "protocol_support_score", "key_exchange_score", "cipher_strength_score", "scanTime", "scanProblem"} {
		if id == p || (strings.HasSuffix(p, "_") && strings.HasPrefix(id, p)) {
			return true
		}
	}
	return false
}
