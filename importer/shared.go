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
