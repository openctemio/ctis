package ocsf

import (
	"os"

	"github.com/openctemio/ctis/v2"
	"github.com/openctemio/ctis/v2/internal/exportkit"
	"github.com/openctemio/ctis/v2/internal/interoptest"

	"encoding/json"
	"strings"
	"testing"
	"time"
)

// ocsfToCTIS is the test-only reverse of Events: it reads back every member
// the mapping in export_ocsf.go writes, so CTIS -> OCSF -> CTIS can be
// compared on the mapped members. No importer of OCSF exists; this is not
// one.
func ocsfToCTIS(ev *Event) ctis.Finding {
	f := ctis.Finding{
		Type:        ctis.FindingType(ev.Unmapped["ctis_type"]),
		Title:       ev.FindingInfo.Title,
		Description: ev.FindingInfo.Desc,
		Message:     ev.Message,
		Severity:    ocsfSeverityOf(ev.SeverityID),
		Status:      ocsfStatusOf(ev.StatusID, ev.Status),
		Confidence:  ev.ConfidenceScore,
		Fingerprint: ev.FindingInfo.UID,
		FirstSeenAt: millisTime(ev.FindingInfo.FirstSeenTime),
		LastSeenAt:  millisTime(ev.FindingInfo.LastSeenTime),
	}
	if len(ev.FindingInfo.Types) > 0 {
		f.Category = ev.FindingInfo.Types[0]
	}
	if a := ev.FindingInfo.Analytic; a != nil {
		f.RuleID, f.RuleName = a.UID, a.Name
	}
	if len(ev.Resources) > 0 {
		r := ev.Resources[0]
		f.AssetRef = r.UID
	}
	if ev.Unmapped["secret_type"] != "" || ev.Unmapped["secret_service"] != "" || ev.Unmapped["secret_masked_value"] != "" {
		f.Secret = &ctis.SecretDetails{Type: ev.Unmapped["secret_type"], Service: ev.Unmapped["secret_service"], MaskedValue: ev.Unmapped["secret_masked_value"]}
	}
	rem := ev.Remediation
	if c := ev.Compliance; c != nil {
		std := ""
		if len(c.Standards) > 0 {
			std = c.Standards[0]
		}
		if f.Type == ctis.FindingTypeMisconfiguration {
			f.Misconfiguration = &ctis.MisconfigurationDetails{PolicyID: c.Control, Provider: std}
		} else {
			f.Kind = strings.ToLower(c.Status)
			f.Compliance = &ctis.ComplianceDetails{Framework: ctis.ComplianceFramework(std), FrameworkVersion: ev.Unmapped["compliance_framework_version"], ControlID: c.Control}
		}
	}
	for i, v := range ev.Vulnerabilities {
		if i == 0 {
			f.References = v.References
			if v.Remediation != nil {
				rem = v.Remediation
			}
			if len(v.AffectedCode) > 0 {
				c := v.AffectedCode[0]
				f.Location = &ctis.FindingLocation{Path: c.File.Path, StartLine: c.StartLine, EndLine: c.EndLine}
			}
		}
		hasVuln := v.CVE != nil || v.CWE != nil || len(v.AffectedPackages) > 0 || v.IsExploitAvailable
		if !hasVuln {
			continue
		}
		if f.Vulnerability == nil {
			f.Vulnerability = &ctis.VulnerabilityDetails{}
		}
		vd := f.Vulnerability
		if i == 0 {
			if v.IsExploitAvailable {
				vd.ThreatSignals = []ctis.ThreatSignal{{Type: ctis.ThreatSignalPublicExploit, Source: "ocsf"}}
			}
			if len(v.AffectedPackages) > 0 {
				p := v.AffectedPackages[0]
				vd.PackageName, vd.InstalledVersion, vd.PURL = p.Name, p.Version, p.PURL
				if p.FixedInVersion != "" {
					vd.FixedVersions = []string{p.FixedInVersion}
				}
			}
		}
		if v.CVE != nil {
			vd.IDs = append(vd.IDs, ctis.VulnerabilityID{Type: ctis.VulnerabilityIDCVE, ID: v.CVE.UID})
			for _, c := range v.CVE.CVSS {
				s := ctis.Score{System: ctis.ScoreSystemCVSS, Version: c.Version, Vector: c.VectorString}
				if c.BaseScore != nil {
					val := *c.BaseScore
					s.Value = &val
				}
				f.Scores = append(f.Scores, s)
			}
			if e := v.CVE.EPSS; e != nil {
				if e.Score != "" {
					var val float64
					_ = json.Unmarshal([]byte(e.Score), &val)
					f.Scores = append(f.Scores, ctis.Score{System: ctis.ScoreSystemEPSS, Value: &val})
				}
				if e.Percentile != nil {
					val := *e.Percentile
					f.Scores = append(f.Scores, ctis.Score{System: ctis.ScoreSystemEPSSPercentile, Value: &val})
				}
			}
		}
		if v.CWE != nil {
			vd.CWEIDs = append(vd.CWEIDs, v.CWE.UID)
		}
	}
	if rem != nil {
		f.Remediation = &ctis.Remediation{Recommendation: rem.Desc}
		if len(f.References) == 0 {
			f.References = rem.References
		}
	}
	return f
}

func millisTime(ms int64) *time.Time {
	if ms == 0 {
		return nil
	}
	t := time.UnixMilli(ms).UTC()
	return &t
}

// ocsfStatusOf is the inverse of ocsfStatus.
func ocsfStatusOf(id int, caption string) ctis.FindingStatus {
	switch id {
	case 1:
		return ctis.FindingStatusOpen
	case 2:
		return ctis.FindingStatusInProgress
	case 3:
		return ctis.FindingStatusSuppressed
	case 4:
		return ctis.FindingStatusResolved
	case 99:
		switch caption {
		case "False Positive":
			return ctis.FindingStatusFalsePositive
		case "Accepted Risk":
			return ctis.FindingStatusAcceptedRisk
		}
	}
	return ""
}

// ocsfSeverityOf is the inverse of ocsfSeverity.
func ocsfSeverityOf(id int) ctis.Severity {
	switch id {
	case 5:
		return ctis.SeverityCritical
	case 4:
		return ctis.SeverityHigh
	case 3:
		return ctis.SeverityMedium
	case 2:
		return ctis.SeverityLow
	case 1:
		return ctis.SeverityInfo
	}
	return ""
}

// ocsfExpected is what the reverse mapper can give back for f: the
// redacted copy, with the asset resolved from the report, the fingerprint
// falling back to the id, the CVE ids in one list and the legacy CVSS
// members standing for a score when there is none.
func ocsfExpected(t *testing.T, r *ctis.Report, src *ctis.Finding) ctis.Finding {
	t.Helper()
	f, err := exportkit.Finding(src)
	if err != nil {
		t.Fatal(err)
	}
	if f.Fingerprint == "" {
		f.Fingerprint = f.ID
	}
	if f.Remediation != nil {
		f.Remediation = &ctis.Remediation{Recommendation: f.Remediation.Recommendation}
		if f.Remediation.Recommendation == "" {
			f.Remediation = nil
		}
	}
	if v := f.Vulnerability; v != nil {
		cves := ocsfCVEs(v)
		v.IDs = nil
		for _, id := range cves {
			v.IDs = append(v.IDs, ctis.VulnerabilityID{Type: ctis.VulnerabilityIDCVE, ID: id})
		}
		if ctis.HasThreatSignal(v, ctis.ThreatSignalPublicExploit, ctis.ThreatSignalWeaponized, ctis.ThreatSignalExploitedInWild, ctis.ThreatSignalKEV) {
			v.ThreatSignals = []ctis.ThreatSignal{{Type: ctis.ThreatSignalPublicExploit, Source: "ocsf"}}
		} else {
			v.ThreatSignals = nil
		}
		if len(v.FixedVersions) > 1 {
			v.FixedVersions = v.FixedVersions[:1]
		}
		if v.PackageName == "" {
			v.FixedVersions = nil
		}
		cvss, epss := ocsfScoresOf(&f)
		f.Scores = nil
		for _, c := range cvss {
			f.Scores = append(f.Scores, ctis.Score{System: ctis.ScoreSystemCVSS, Version: c.Version, Vector: c.VectorString, Value: c.BaseScore})
		}
		if epss != nil {
			if epss.Score != "" {
				var val float64
				_ = json.Unmarshal([]byte(epss.Score), &val)
				f.Scores = append(f.Scores, ctis.Score{System: ctis.ScoreSystemEPSS, Value: &val})
			}
			if epss.Percentile != nil {
				f.Scores = append(f.Scores, ctis.Score{System: ctis.ScoreSystemEPSSPercentile, Value: epss.Percentile})
			}
		}
		if len(v.IDs) == 0 {
			f.Scores = nil
		}
	}
	return f
}

func TestExportOCSFRoundTrip(t *testing.T) {
	for _, name := range []string{"vulnerability-sca", "network-vulnerability-interop", "sast", "secret", "compliance", "misconfiguration"} {
		t.Run(name, func(t *testing.T) {
			var r ctis.Report
			if err := json.Unmarshal(readFile(t, "../../../examples/"+name+".json"), &r); err != nil {
				t.Fatal(err)
			}
			events, err := Events(&r, nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(events) != len(r.Findings) || len(events) == 0 {
				t.Fatalf("%d events for %d findings", len(events), len(r.Findings))
			}
			out, err := json.MarshalIndent(events, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			interoptest.CheckGolden(t, "export/"+name+".golden.ocsf.json", out)
			want := make([]ctis.Finding, len(r.Findings))
			got := make([]ctis.Finding, len(events))
			for i := range events {
				want[i] = ocsfExpected(t, &r, &r.Findings[i])
				got[i] = ocsfToCTIS(&events[i])
				if ev := events[i]; ev.TypeUID != ev.ClassUID*100+ev.ActivityID || ev.CategoryUID != CategoryFindings || ev.Metadata.Version != Version {
					t.Errorf("event %d: bad class/type/version %+v", i, ev)
				}
			}
			for _, d := range interoptest.RoundTripDiff(t, map[string]any{"findings": want}, map[string]any{"findings": got}, ""+name+".losses.json") {
				t.Error(d)
			}
		})
	}
}

func readFile(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
