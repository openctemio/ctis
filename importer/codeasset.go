package importer

import (
	"strings"

	"github.com/openctemio/ctis"
)

// The asset of a code report (SARIF, semgrep, betterleaks, a trivy
// file-system scan): one repository every finding is filed on.

// codeAssetID is the id of the one asset of a code report.
const codeAssetID = "asset-1"

// repoAsset is a repository asset with the branch and commit it was scanned
// at, and where the importer learned it (properties.source). It carries no
// criticality: that is the receiver's call (CTIS spec 4.1).
func repoAsset(value, branch, commit, source string) ctis.Asset {
	value = line(value, capShort)
	props := ctis.Properties{"source": source}
	if b := line(branch, capShort); b != "" {
		props["branch"] = b
	}
	if c := line(commit, 128); c != "" {
		props["commit_sha"] = c
	}
	return ctis.Asset{ID: codeAssetID, Type: ctis.AssetTypeRepository, Value: value, Name: value, Properties: props}
}

// codeAsset returns the asset a code report is filed on:
//
//  1. Options.Repository (with Options.Branch and Options.CommitSHA);
//  2. else the asset the file names (fromFile, when not nil);
//  3. else Options.DefaultAsset, else an unclassified asset named after
//     the tool, with an issue saying the file names no repository.
//
// With Options.Repository, the report's scope is named after it.
func (b *builder) codeAsset(fromFile *ctis.Asset) ctis.Asset {
	if r := strings.TrimSpace(b.opts.Repository); r != "" {
		b.res.Report.Metadata.Scope = &ctis.Scope{Name: line(r, capShort)}
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
func (b *builder) bindAll(a ctis.Asset) error {
	id, err := b.asset(a)
	if err != nil {
		return err
	}
	for i := range b.res.Report.Findings {
		b.res.Report.Findings[i].AssetRef = id
	}
	return nil
}
