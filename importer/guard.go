package importer

import (
	"fmt"
	"time"

	"github.com/openctemio/ctis"
)

// The report guard. Every parser builds CTIS entities from optional source
// fields, and a field CTIS requires (an asset value, a finding title, a
// dependency name, a unique id) can be missing or malformed in a hostile or
// broken file. Rather than trust each parser to check every member, the
// builder validates each entity on its own before the report leaves Parse:
// an entity that is not valid CTIS is dropped with a counted issue, a
// finding whose asset was dropped goes with it, and a later duplicate id is
// dropped. Parse never returns a report that fails ctis.Report.Validate;
// if one still would, that is a bug and Parse fails instead.

// probeTime is any non-zero time: Validate requires metadata.timestamp.
var probeTime = time.Unix(1, 0).UTC()

func probe() ctis.Report {
	return ctis.Report{Version: ctis.SchemaVersion, Metadata: ctis.ReportMetadata{Timestamp: probeTime}}
}

// guard drops the entities that are not valid CTIS and returns how many it
// dropped of each kind.
func (b *builder) guard() error {
	rep := b.res.Report
	var droppedAssets, droppedFindings, droppedDeps, droppedStatements int
	firstErr := map[string]string{}
	note := func(kind string, err error) {
		if _, ok := firstErr[kind]; !ok && err != nil {
			firstErr[kind] = err.Error()
		}
	}

	// Assets, one by one, unique ids.
	keptAssets := rep.Assets[:0]
	assetOK := map[string]bool{}
	for _, a := range rep.Assets {
		p := probe()
		p.Assets = []ctis.Asset{a}
		if err := p.Validate(); err != nil || (a.ID != "" && assetOK[a.ID]) {
			droppedAssets++
			note("asset", err)
			continue
		}
		if a.ID != "" {
			assetOK[a.ID] = true
		}
		keptAssets = append(keptAssets, a)
	}
	rep.Assets = keptAssets

	// Findings, each with its asset, unique ids.
	keptFindings := rep.Findings[:0]
	findingIDs := map[string]bool{}
	assetsByID := map[string]ctis.Asset{}
	for _, a := range rep.Assets {
		if a.ID != "" {
			assetsByID[a.ID] = a
		}
	}
	for _, f := range rep.Findings {
		p := probe()
		if f.AssetRef != "" {
			a, ok := assetsByID[f.AssetRef]
			if !ok {
				droppedFindings++
				note("finding", fmt.Errorf("its asset %q was not valid", f.AssetRef))
				continue
			}
			p.Assets = []ctis.Asset{a}
		}
		p.Findings = []ctis.Finding{f}
		if err := p.Validate(); err != nil || (f.ID != "" && findingIDs[f.ID]) {
			droppedFindings++
			note("finding", err)
			continue
		}
		if f.ID != "" {
			findingIDs[f.ID] = true
		}
		keptFindings = append(keptFindings, f)
	}
	rep.Findings = keptFindings

	// Dependencies, one by one, unique ids.
	keptDeps := rep.Dependencies[:0]
	depIDs := map[string]bool{}
	for _, d := range rep.Dependencies {
		p := probe()
		p.Dependencies = []ctis.Dependency{d}
		if err := p.Validate(); err != nil || (d.ID != "" && depIDs[d.ID]) {
			droppedDeps++
			note("component", err)
			continue
		}
		if d.ID != "" {
			depIDs[d.ID] = true
		}
		keptDeps = append(keptDeps, d)
	}
	rep.Dependencies = keptDeps

	// VEX statements: the statement must be a valid CTIS VEX.
	keptVEX := b.res.VEX[:0]
	for _, s := range b.res.VEX {
		p := probe()
		v := s.VEX
		p.Findings = []ctis.Finding{{Type: ctis.FindingTypeVulnerability, Title: "probe", Severity: ctis.SeverityInfo, VEX: &v}}
		if err := p.Validate(); err != nil || len(s.VulnerabilityIDs) == 0 || len(s.Products) == 0 {
			droppedStatements++
			note("VEX statement", err)
			continue
		}
		keptVEX = append(keptVEX, s)
	}
	b.res.VEX = keptVEX

	for _, d := range []struct {
		kind string
		n    int
	}{{"asset", droppedAssets}, {"finding", droppedFindings}, {"component", droppedDeps}, {"VEX statement", droppedStatements}} {
		if d.n == 0 {
			continue
		}
		msg := fmt.Sprintf("%d %s(s) left out: not valid CTIS", d.n, d.kind)
		if e := firstErr[d.kind]; e != "" {
			msg += " (first: " + line(e, 300) + ")"
		}
		b.issue(Issue{Message: msg})
	}
	b.res.Stats.Skipped += droppedFindings

	// Recount severities from what is left.
	b.res.Stats.BySeverity = map[ctis.Severity]int{}
	for _, f := range rep.Findings {
		b.res.Stats.BySeverity[f.Severity]++
	}

	if err := rep.Validate(); err != nil {
		return &ParseError{Format: b.format, Msg: "the converted report is not valid CTIS (an importer bug): " + line(err.Error(), 300), Err: ErrMalformed}
	}
	return nil
}
