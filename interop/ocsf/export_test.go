package ctis

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// ocsfToCTIS is the test-only reverse of ToOCSF: it reads back every member
// the mapping in export_ocsf.go writes, so CTIS -> OCSF -> CTIS can be
// compared on the mapped members. No importer of OCSF exists; this is not
// one.
func ocsfToCTIS(ev *OCSFEvent) Finding {
	f := Finding{
		Type:        FindingType(ev.Unmapped["ctis_type"]),
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
		f.Secret = &SecretDetails{Type: ev.Unmapped["secret_type"], Service: ev.Unmapped["secret_service"], MaskedValue: ev.Unmapped["secret_masked_value"]}
	}
	rem := ev.Remediation
	if c := ev.Compliance; c != nil {
		std := ""
		if len(c.Standards) > 0 {
			std = c.Standards[0]
		}
		if f.Type == FindingTypeMisconfiguration {
			f.Misconfiguration = &MisconfigurationDetails{PolicyID: c.Control, Provider: std}
		} else {
			f.Kind = strings.ToLower(c.Status)
			f.Compliance = &ComplianceDetails{Framework: ComplianceFramework(std), FrameworkVersion: ev.Unmapped["compliance_framework_version"], ControlID: c.Control}
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
				f.Location = &FindingLocation{Path: c.File.Path, StartLine: c.StartLine, EndLine: c.EndLine}
			}
		}
		hasVuln := v.CVE != nil || v.CWE != nil || len(v.AffectedPackages) > 0 || v.IsExploitAvailable
		if !hasVuln {
			continue
		}
		if f.Vulnerability == nil {
			f.Vulnerability = &VulnerabilityDetails{}
		}
		vd := f.Vulnerability
		if i == 0 {
			if v.IsExploitAvailable {
				vd.ThreatSignals = []ThreatSignal{{Type: ThreatSignalPublicExploit, Source: "ocsf"}}
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
			vd.IDs = append(vd.IDs, VulnerabilityID{Type: VulnerabilityIDCVE, ID: v.CVE.UID})
			for _, c := range v.CVE.CVSS {
				s := Score{System: ScoreSystemCVSS, Version: c.Version, Vector: c.VectorString}
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
					f.Scores = append(f.Scores, Score{System: ScoreSystemEPSS, Value: &val})
				}
				if e.Percentile != nil {
					val := *e.Percentile
					f.Scores = append(f.Scores, Score{System: ScoreSystemEPSSPercentile, Value: &val})
				}
			}
		}
		if v.CWE != nil {
			vd.CWEIDs = append(vd.CWEIDs, v.CWE.UID)
		}
	}
	if rem != nil {
		f.Remediation = &Remediation{Recommendation: rem.Desc}
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
func ocsfStatusOf(id int, caption string) FindingStatus {
	switch id {
	case 1:
		return FindingStatusOpen
	case 2:
		return FindingStatusInProgress
	case 3:
		return FindingStatusSuppressed
	case 4:
		return FindingStatusResolved
	case 99:
		switch caption {
		case "False Positive":
			return FindingStatusFalsePositive
		case "Accepted Risk":
			return FindingStatusAcceptedRisk
		}
	}
	return ""
}

// ocsfSeverityOf is the inverse of ocsfSeverity.
func ocsfSeverityOf(id int) Severity {
	switch id {
	case 5:
		return SeverityCritical
	case 4:
		return SeverityHigh
	case 3:
		return SeverityMedium
	case 2:
		return SeverityLow
	case 1:
		return SeverityInfo
	}
	return ""
}

// ocsfExpected is what the reverse mapper can give back for f: the
// redacted copy, with the asset resolved from the report, the fingerprint
// falling back to the id, the CVE ids in one list and the legacy CVSS
// members standing for a score when there is none.
func ocsfExpected(t *testing.T, r *Report, src *Finding) Finding {
	t.Helper()
	f, err := exportFinding(src)
	if err != nil {
		t.Fatal(err)
	}
	if f.Fingerprint == "" {
		f.Fingerprint = f.ID
	}
	if f.Remediation != nil {
		f.Remediation = &Remediation{Recommendation: f.Remediation.Recommendation}
		if f.Remediation.Recommendation == "" {
			f.Remediation = nil
		}
	}
	if v := f.Vulnerability; v != nil {
		cves := ocsfCVEs(v)
		v.IDs = nil
		for _, id := range cves {
			v.IDs = append(v.IDs, VulnerabilityID{Type: VulnerabilityIDCVE, ID: id})
		}
		if HasThreatSignal(v, ThreatSignalPublicExploit, ThreatSignalWeaponized, ThreatSignalExploitedInWild, ThreatSignalKEV) {
			v.ThreatSignals = []ThreatSignal{{Type: ThreatSignalPublicExploit, Source: "ocsf"}}
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
			f.Scores = append(f.Scores, Score{System: ScoreSystemCVSS, Version: c.Version, Vector: c.VectorString, Value: c.BaseScore})
		}
		if epss != nil {
			if epss.Score != "" {
				var val float64
				_ = json.Unmarshal([]byte(epss.Score), &val)
				f.Scores = append(f.Scores, Score{System: ScoreSystemEPSS, Value: &val})
			}
			if epss.Percentile != nil {
				f.Scores = append(f.Scores, Score{System: ScoreSystemEPSSPercentile, Value: epss.Percentile})
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
			var r Report
			if err := json.Unmarshal(readTestdataRoot(t, "examples/"+name+".json"), &r); err != nil {
				t.Fatal(err)
			}
			events, err := ToOCSF(&r, nil)
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
			ExportCheckGolden(t, "export/ocsf/"+name+".golden.ocsf.json", out)
			want := make([]Finding, len(r.Findings))
			got := make([]Finding, len(events))
			for i := range events {
				want[i] = ocsfExpected(t, &r, &r.Findings[i])
				got[i] = ocsfToCTIS(&events[i])
				if ev := events[i]; ev.TypeUID != ev.ClassUID*100+ev.ActivityID || ev.CategoryUID != OCSFCategoryFindings || ev.Metadata.Version != OCSFVersion {
					t.Errorf("event %d: bad class/type/version %+v", i, ev)
				}
			}
			for _, d := range ExportRoundTripDiff(t, map[string]any{"findings": want}, map[string]any{"findings": got}, "ocsf/"+name+".losses.json") {
				t.Error(d)
			}
		})
	}
}
