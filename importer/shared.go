package importer

import (
	"github.com/openctemio/ctis/v2"
)

// Helpers shared by the importers of SBOM, VEX, OSV and generic findings
// files.

// assetByID returns the asset with the id, for in-place additions.
func (b *Builder) assetByID(id string) *ctis.Asset {
	if i, ok := b.assets[id]; ok {
		return &b.res.Report.Assets[i]
	}
	return nil
}

// dependency adds a component of the scanned asset.
func (b *Builder) dependency(d ctis.Dependency) error {
	if len(b.res.Report.Dependencies) >= b.lim.MaxComponents {
		return b.tooMany("components", b.lim.MaxComponents)
	}
	b.res.Report.Dependencies = append(b.res.Report.Dependencies, d)
	return nil
}

// statement adds a VEX statement.
func (b *Builder) statement(s VEXStatement) error {
	if len(b.res.VEX) >= b.lim.MaxStatements {
		return b.tooMany("VEX statements", b.lim.MaxStatements)
	}
	b.res.VEX = append(b.res.VEX, s)
	return nil
}

// dropIncomplete removes the evidence items MarkSensitive could not mark
// completely: an item is dropped rather than sent with a value unmarked.
func dropIncomplete(items []ctis.EvidenceItem, incomplete []int) []ctis.EvidenceItem {
	if len(incomplete) == 0 {
		return items
	}
	skip := make(map[int]bool, len(incomplete))
	for _, i := range incomplete {
		skip[i] = true
	}
	out := items[:0]
	for i := range items {
		if !skip[i] {
			out = append(out, items[i])
		}
	}
	return out
}
