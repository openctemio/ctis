package importer

import (
	"encoding/xml"
	"slices"
	"sort"
	"strings"
	"time"
)

// What a .nessus file proves about the findings it does not hold
// (ImportCoverage): the plugin selection of its Policy, and per host whether
// its scan finished and whether the local checks ran.

// Bounds on the plugin selection read from a policy.
const (
	nessusMaxPolicyFamilies = 512
	nessusMaxPolicyPlugins  = 500_000
)

// nessusPolicy is the part of the Policy element that is read: the plugin
// selection. Nothing else of the policy (credentials, accounts, plugin
// preferences) is mapped, so it never reaches memory past the decoder.
type nessusPolicy struct {
	Prefs []struct {
		Name  string `xml:"name"`
		Value string `xml:"value"`
	} `xml:"Preferences>ServerPreferences>preference"`
	Families []struct {
		Name   string `xml:"FamilyName"`
		Status string `xml:"Status"`
	} `xml:"FamilySelection>FamilyItem"`
	Plugins []struct {
		ID     string `xml:"PluginId"`
		Status string `xml:"Status"`
	} `xml:"IndividualPluginSelection>PluginItem"`
}

// nessusReadPolicy reads the plugin selection of the Policy element: the
// plugin_set server preference (the ids of every enabled plugin,
// ";"-separated), the families enabled whole and the plugins enabled one by
// one. Every other preference value is dropped as soon as it is decoded.
func (b *Builder) nessusReadPolicy(dec *xml.Decoder, se *xml.StartElement) error {
	var p nessusPolicy
	if err := dec.DecodeElement(&p, se); err != nil {
		return asParseError(err, FormatNessus)
	}
	cov := b.nessusCov()
	b.nessusPolicy = true
	plugins := map[string]bool{}
	addPlugin := func(id string) {
		id = strings.TrimSpace(id)
		if len(id) <= 10 && len(plugins) < nessusMaxPolicyPlugins && isDigits(id) {
			plugins[id] = true
		}
	}
	for _, pref := range p.Prefs {
		if strings.TrimSpace(pref.Name) == "plugin_set" {
			for _, id := range strings.Split(pref.Value, ";") {
				addPlugin(id)
			}
		}
	}
	for _, f := range p.Families {
		name := line(f.Name, capShort)
		if name != "" && strings.EqualFold(strings.TrimSpace(f.Status), "enabled") && len(cov.Families) < nessusMaxPolicyFamilies && !slices.Contains(cov.Families, name) {
			cov.Families = append(cov.Families, name)
		}
	}
	for _, pl := range p.Plugins {
		if strings.EqualFold(strings.TrimSpace(pl.Status), "enabled") {
			addPlugin(pl.ID)
		}
	}
	for id := range plugins {
		cov.Plugins = append(cov.Plugins, id)
	}
	sort.Strings(cov.Families)
	sort.Strings(cov.Plugins)
	return nil
}

func isDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

func (b *Builder) nessusCov() *ImportCoverage {
	if b.nessusCoverage == nil {
		b.nessusCoverage = &ImportCoverage{Hosts: []HostCoverage{}}
	}
	return b.nessusCoverage
}

// The plugins whose result on a host says the local checks did not run
// there: authentication failed, or local checks are not available.
var nessusAuthIssuePlugins = []string{
	"21745",  // OS Security Patch Assessment Failed (authentication failure, local checks not run)
	"104410", // Target Credential Status by Authentication Protocol - Failure for Provided Credentials
	"110385", // Target Credential Issues by Authentication Protocol - Insufficient Privilege
	"117885", // Target Credential Issues by Authentication Protocol - Intermittent Authentication Failure
	"110723", // Target Credential Status by Authentication Protocol - No Credentials Provided
	"117886", // OS Security Patch Assessment Not Available (local checks not enabled)
}

// nessusHostCoverage records one host of the file.
func (b *Builder) nessusHostCoverage(h *nessusHost, assetID string, start, end *time.Time, credentialed *bool) {
	cov := b.nessusCov()
	hc := HostCoverage{AssetRef: assetID, ObservedAt: firstTime(end, start), Finished: end != nil}
	hc.Credentialed = credentialed != nil && *credentialed
	hc.LocalChecks = hc.Credentialed
	for i := range h.Items {
		if id := strings.TrimSpace(h.Items[i].PluginID); slices.Contains(nessusAuthIssuePlugins, id) {
			hc.LocalChecks = false
			if hc.AuthIssue == "" {
				hc.AuthIssue = id
			}
		}
	}
	for i := range cov.Hosts {
		if cov.Hosts[i].AssetRef == assetID {
			// The same host twice (two ReportHosts with one value): it
			// proves only what both prove.
			prev := &cov.Hosts[i]
			prev.Finished = prev.Finished && hc.Finished
			prev.LocalChecks = prev.LocalChecks && hc.LocalChecks
			prev.Credentialed = prev.Credentialed && hc.Credentialed
			if prev.AuthIssue == "" {
				prev.AuthIssue = hc.AuthIssue
			}
			if hc.ObservedAt != nil && (prev.ObservedAt == nil || hc.ObservedAt.Before(*prev.ObservedAt)) {
				prev.ObservedAt = hc.ObservedAt
			}
			return
		}
	}
	cov.Hosts = append(cov.Hosts, hc)
}

// nessusFinishCoverage sets the result's coverage: complete only with a
// plugin selection, plugin details and at least one host.
func (b *Builder) nessusFinishCoverage() {
	cov := b.nessusCov()
	if !b.nessusPolicy || (len(cov.Families) == 0 && len(cov.Plugins) == 0) {
		cov.Reasons = append(cov.Reasons, CoverageNoPolicy)
	}
	if c := b.nessusDetails; c.plugin > 0 && c.detailed == 0 {
		cov.Reasons = append(cov.Reasons, CoverageNoPluginDetails)
	}
	if len(cov.Hosts) == 0 {
		cov.Reasons = append(cov.Reasons, CoverageNoHosts)
	}
	cov.Complete = len(cov.Reasons) == 0
	b.res.Coverage = cov
}

func firstTime(ts ...*time.Time) *time.Time {
	for _, t := range ts {
		if t != nil {
			return t
		}
	}
	return nil
}
