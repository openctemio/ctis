package ctis

import (
	"unicode/utf8"
)

// tooLong reports whether s has more than n characters.
func tooLong(s string, n int) bool { return utf8.RuneCountInString(s) > n }

// validateInteropFinding checks the interoperability members of one finding.
func validateInteropFinding(i int, f *Finding, add func(string, ...any)) {
	if n := f.Native; n != nil {
		if n.Scheme != "" && !n.Scheme.IsValid() {
			add("findings[%d]: native.scheme %q is invalid", i, n.Scheme)
		}
		if n.DetectionType != "" && !n.DetectionType.IsValid() {
			add("findings[%d]: native.detection_type %q is invalid", i, n.DetectionType)
		}
		for _, m := range [][2]string{{"vuln_id", n.VulnID}, {"instance_id", n.InstanceID}, {"family", n.Family}} {
			if tooLong(m[1], MaxNativeIDLen) {
				add("findings[%d]: native.%s longer than %d", i, m[0], MaxNativeIDLen)
			}
		}
		if tooLong(n.Severity, MaxNativeValueLen) || tooLong(n.Status, MaxNativeValueLen) {
			add("findings[%d]: native.severity or native.status longer than %d", i, MaxNativeValueLen)
		}
		if tooLong(n.RawRef, MaxRawRefLen) {
			add("findings[%d]: native.raw_ref longer than %d", i, MaxRawRefLen)
		}
	}

	if len(f.Scores) > MaxScores {
		add("findings[%d]: %d scores, at most %d", i, len(f.Scores), MaxScores)
	}
	for j, s := range f.Scores {
		if j >= MaxScores {
			break
		}
		if p := scoreProblem(s); p != "" {
			add("findings[%d]: scores[%d]: %s", i, j, p)
		}
	}

	if x := f.VEX; x != nil {
		if !x.Status.IsValid() {
			add("findings[%d]: vex.status %q is invalid", i, x.Status)
		}
		if x.Justification != "" {
			if !x.Justification.IsValid() {
				add("findings[%d]: vex.justification %q is invalid", i, x.Justification)
			} else if x.Status != VEXStatusNotAffected {
				add("findings[%d]: vex.justification is only for status not_affected", i)
			}
		}
		if x.Status == VEXStatusNotAffected && x.Justification == "" && x.Statement == "" {
			add("findings[%d]: vex status not_affected needs a justification or a statement", i)
		}
		if tooLong(x.NativeJustification, MaxNativeValueLen) {
			add("findings[%d]: vex.native_justification longer than %d", i, MaxNativeValueLen)
		}
		if tooLong(x.Statement, MaxVEXStatementLen) {
			add("findings[%d]: vex.statement longer than %d", i, MaxVEXStatementLen)
		}
		if tooLong(x.Source, MaxVEXSourceLen) {
			add("findings[%d]: vex.source longer than %d", i, MaxVEXSourceLen)
		}
	}

	if l := f.SourceLifecycle; l != nil {
		if l.State != "" && !l.State.IsValid() {
			add("findings[%d]: source_lifecycle.state %q is invalid", i, l.State)
		}
		if l.TimesFound < 0 || l.TimesFound > MaxTimesFound {
			add("findings[%d]: source_lifecycle.times_found %d is outside 0-%d", i, l.TimesFound, MaxTimesFound)
		}
	}

	if len(f.SourceExtra) > MaxSourceExtraEntries {
		add("findings[%d]: source_extra has %d entries, at most %d", i, len(f.SourceExtra), MaxSourceExtraEntries)
	}
	if n := sourceExtraBytes(f.SourceExtra); n > MaxSourceExtraBytes {
		add("findings[%d]: source_extra is %d bytes, at most %d", i, n, MaxSourceExtraBytes)
	}
	for k, v := range f.SourceExtra {
		if !validExtraKey(k) {
			add("findings[%d]: source_extra key %q is empty, longer than %d or holds control characters", i, truncateRunes(k, 64), MaxSourceExtraKeyLen)
		}
		if tooLong(v, MaxSourceExtraValueLen) {
			add("findings[%d]: source_extra[%q] longer than %d", i, truncateRunes(k, 64), MaxSourceExtraValueLen)
		}
	}

	if v := f.Vulnerability; v != nil {
		if len(v.IDs) > MaxVulnerabilityIDs {
			add("findings[%d]: vulnerability.ids has %d entries, at most %d", i, len(v.IDs), MaxVulnerabilityIDs)
		}
		for j, id := range v.IDs {
			if j >= MaxVulnerabilityIDs {
				break
			}
			if _, ok := canonicalTypedID(id); !ok {
				add("findings[%d]: vulnerability.ids[%d] (%q, %q) is not a valid id of its type", i, j, id.Type, truncateRunes(id.ID, 64))
			}
			if tooLong(id.Source, MaxScoreSourceLen) {
				add("findings[%d]: vulnerability.ids[%d].source longer than %d", i, j, MaxScoreSourceLen)
			}
		}
	}

	if r := f.Remediation; r != nil {
		if r.SolutionType != "" && !r.SolutionType.IsValid() {
			add("findings[%d]: remediation.solution_type %q is invalid", i, r.SolutionType)
		}
		if len(r.Advisories) > MaxAdvisories {
			add("findings[%d]: remediation.advisories has %d entries, at most %d", i, len(r.Advisories), MaxAdvisories)
		}
		for j, a := range r.Advisories {
			if j >= MaxAdvisories {
				break
			}
			if a.ID == "" && a.URL == "" {
				add("findings[%d]: remediation.advisories[%d] needs an id or a url", i, j)
			}
			if tooLong(a.ID, MaxVulnerabilityIDLen) || tooLong(a.URL, MaxAdvisoryURLLen) || tooLong(a.Source, MaxScoreSourceLen) {
				add("findings[%d]: remediation.advisories[%d] has an over-long member", i, j)
			}
		}
	}
}

// validateIdentityHints checks one asset's identity hints.
func validateIdentityHints(i int, h *IdentityHints, add func(string, ...any)) {
	if h == nil {
		return
	}
	for _, m := range [][2]string{
		{"fqdn", h.FQDN}, {"netbios_name", h.NetBIOSName}, {"os_cpe", h.OSCPE},
		{"cloud_resource_id", h.CloudResourceID}, {"agent_id", h.AgentID},
	} {
		if tooLong(m[1], MaxIdentityHintLen) {
			add("assets[%d]: identity_hints.%s longer than %d", i, m[0], MaxIdentityHintLen)
		}
	}
	if len(h.MACAddresses) > MaxIdentityHintMACs {
		add("assets[%d]: identity_hints.mac_addresses has %d entries, at most %d", i, len(h.MACAddresses), MaxIdentityHintMACs)
	}
	for j, m := range h.MACAddresses {
		if j >= MaxIdentityHintMACs {
			break
		}
		if tooLong(m, 64) {
			add("assets[%d]: identity_hints.mac_addresses[%d] longer than 64", i, j)
		}
	}
}
