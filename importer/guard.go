package importer

import (
	"fmt"

	"github.com/openctemio/ctis/v2"
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

// guard drops the entities that are not valid CTIS and returns how many it
// dropped of each kind.
func (b *Builder) guard() error {
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

	// Rules of the catalog, one by one, unique ids.
	keptRules := rep.Rules[:0]
	rulesByID := map[string]ctis.Rule{}
	for _, r := range rep.Rules {
		p := probe()
		p.Rules = []ctis.Rule{r}
		if err := p.Validate(); err != nil || rulesByID[r.ID].ID != "" {
			note("rule", err)
			continue
		}
		rulesByID[r.ID] = r
		keptRules = append(keptRules, r)
	}
	droppedRules := len(rep.Rules) - len(keptRules)
	rep.Rules = keptRules

	// Findings, each with its asset (and rule), unique ids.
	keptFindings := rep.Findings[:0]
	findingIDs := map[string]bool{}
	assetsByID := map[string]ctis.Asset{}
	for _, a := range rep.Assets {
		if a.ID != "" {
			assetsByID[a.ID] = a
		}
	}
	endpointsByID := map[string]ctis.Endpoint{}
	for _, e := range rep.Endpoints {
		if e.ID != "" {
			endpointsByID[e.ID] = e
		}
	}
	for _, f := range rep.Findings {
		p := probe()
		a, ok := assetsByID[f.AssetRef]
		if !ok {
			droppedFindings++
			note("finding", fmt.Errorf("its asset %q is missing or was not valid", f.AssetRef))
			continue
		}
		p.Assets = []ctis.Asset{a}
		// A dependency_ref is checked against the whole report below. A
		// rule_ref to a rule that was left out is cleared.
		if r, ok := rulesByID[f.RuleRef]; ok && f.RuleRef != "" {
			p.Rules = []ctis.Rule{r}
		} else {
			f.RuleRef = ""
		}
		pf := f
		pf.DependencyRef = ""
		// A web location may name an endpoint of the report: the probe
		// holds it (without its origin link, checked with the endpoints).
		if f.Web != nil && f.Web.EndpointRef != "" {
			if e, ok := endpointsByID[f.Web.EndpointRef]; ok {
				e.OriginRef = ""
				p.Endpoints = []ctis.Endpoint{e}
			}
		}
		p.Findings = []ctis.Finding{pf}
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

	// Endpoints, one by one; an origin_ref to an asset that was dropped is
	// cleared.
	keptEndpoints := rep.Endpoints[:0]
	droppedEndpoints := 0
	for _, e := range rep.Endpoints {
		if _, ok := assetOK[e.OriginRef]; !ok {
			e.OriginRef = ""
		}
		p := probe()
		p.Endpoints = []ctis.Endpoint{e}
		if e.OriginRef != "" {
			p.Endpoints[0].OriginRef = ""
		}
		if err := p.Validate(); err != nil {
			droppedEndpoints++
			note("endpoint", err)
			continue
		}
		keptEndpoints = append(keptEndpoints, e)
	}
	rep.Endpoints = keptEndpoints
	keptEndpointIDs := map[string]bool{}
	for _, e := range keptEndpoints {
		if e.ID != "" {
			keptEndpointIDs[e.ID] = true
		}
	}
	for i := range rep.Findings {
		if w := rep.Findings[i].Web; w != nil && w.EndpointRef != "" && !keptEndpointIDs[w.EndpointRef] {
			w.EndpointRef = ""
		}
	}

	// Dependencies, one by one, unique ids. An asset_ref to an asset that
	// was dropped is cleared; depends_on is checked against the whole report
	// below.
	keptDeps := rep.Dependencies[:0]
	depIDs := map[string]bool{}
	for _, d := range rep.Dependencies {
		if d.AssetRef != "" && !assetOK[d.AssetRef] {
			d.AssetRef = ""
		}
		p := probe()
		pd := d
		pd.DependsOn = nil
		pd.AssetRef = ""
		p.Dependencies = []ctis.Dependency{pd}
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
	for i := range rep.Dependencies {
		d := &rep.Dependencies[i]
		var keep []string
		for _, ref := range d.DependsOn {
			if depIDs[ref] {
				keep = append(keep, ref)
			}
		}
		d.DependsOn = keep
	}
	for i := range rep.Findings {
		if r := rep.Findings[i].DependencyRef; r != "" && !depIDs[r] {
			rep.Findings[i].DependencyRef = ""
		}
	}
	keptRels := rep.Relationships[:0]
	for _, rel := range rep.Relationships {
		if assetOK[rel.FromRef] && assetOK[rel.ToRef] {
			keptRels = append(keptRels, rel)
		}
	}
	rep.Relationships = keptRels

	// VEX statements: the statement must be a valid CTIS VEX.
	keptVEX := b.res.VEX[:0]
	for _, s := range b.res.VEX {
		p := probe()
		v := s.VEX
		p.Assets = []ctis.Asset{{ID: "probe", Type: ctis.AssetTypeHost, Value: "probe.invalid"}}
		p.Findings = []ctis.Finding{{Type: ctis.FindingTypeVulnerability, Title: "probe", Severity: ctis.SeverityInfo, AssetRef: "probe", VEX: &v}}
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
	}{{"asset", droppedAssets}, {"rule", droppedRules}, {"endpoint", droppedEndpoints}, {"finding", droppedFindings}, {"component", droppedDeps}, {"VEX statement", droppedStatements}} {
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
