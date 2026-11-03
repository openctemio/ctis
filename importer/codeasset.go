package importer

import (
	"strings"

	"github.com/openctemio/ctis/v2"
	"github.com/openctemio/ctis/v2/internal/importkit"
)

// The asset of a code report (SARIF, semgrep, betterleaks, a trivy
// file-system scan): one repository every finding is filed on.

// codeAssetID is the id of the one asset of a code report.
const codeAssetID = importkit.CodeAssetID

// codeAsset returns the asset a code report is filed on:
//
//  1. Options.Repository (with Options.Branch and Options.CommitSHA);
//  2. else the asset the file names (fromFile, when not nil);
//  3. else Options.DefaultAsset, else an unclassified asset named after
//     the tool, with an issue saying the file names no repository.
func (b *Builder) codeAsset(fromFile *ctis.Asset) ctis.Asset {
	if r := strings.TrimSpace(b.opts.Repository); r != "" {
		return repoAsset(r, b.opts.Branch, b.opts.CommitSHA, "import_options")
	}
	if fromFile != nil && strings.TrimSpace(fromFile.Value) != "" {
		a := *fromFile
		if a.ID == "" {
			a.ID = codeAssetID
		}
		return a
	}
	a := b.defaultAsset()
	if b.opts.DefaultAsset == nil {
		b.issue(Issue{Message: "the file names no repository and none was given: findings are filed on " + a.Value})
	}
	return a
}

// bindAll adds the asset and points every finding of the report at it.
func (b *Builder) bindAll(a ctis.Asset) error {
	id, err := b.asset(a)
	if err != nil {
		return err
	}
	if id == "" {
		// The value is no repository (host/owner/name): the findings stay
		// on an unclassified asset of the same name, not lost.
		a.Type, a.ID = ctis.AssetTypeUnclassified, ""
		if id, err = b.asset(a); err != nil {
			return err
		}
	}
	if id == "" {
		b.res.Stats.Skipped += len(b.res.Report.Findings)
		b.res.Report.Findings = nil
		b.res.Stats.BySeverity = map[ctis.Severity]int{}
		return nil
	}
	for i := range b.res.Report.Findings {
		b.res.Report.Findings[i].AssetRef = id
	}
	return nil
}
