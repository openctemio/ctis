package sarif

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/openctemio/ctis/v2"
	"github.com/openctemio/ctis/v2/importer"
)

// SARIF 2.1.0. The conversion is the module's Import; this file adds the
// importer's guards around it (size, depth, string and record limits,
// UTF-8, line numbers) and chooses the asset: Options.Repository, else the
// repository the log names in versionControlProvenance, else the default
// asset. The mapping is spec_sarif.go.

func init() {
	importer.Register(importer.FormatSARIF, importer.Adapter{
		Parse: parseSARIF,
		Tool:  ctis.Tool{Name: "sarif"},
		Spec:  importSpec(),
	})
}

type sarifView struct {
	Version string `json:"version"`
	Runs    []struct {
		Tool struct {
			Driver struct {
				Name string `json:"name"`
			} `json:"driver"`
		} `json:"tool"`
		Results                  []json.RawMessage `json:"results"`
		VersionControlProvenance []struct {
			RepositoryURI string `json:"repositoryUri"`
			RevisionID    string `json:"revisionId"`
			Branch        string `json:"branch"`
		} `json:"versionControlProvenance"`
	} `json:"runs"`
}

// sarifProvenance returns the first repository a run names in
// versionControlProvenance (SARIF 2.1.0 section 3.14.17), as an asset.
func sarifProvenance(v *sarifView) *ctis.Asset {
	for _, run := range v.Runs {
		for _, vc := range run.VersionControlProvenance {
			if u := line(stripUserinfo(vc.RepositoryURI), capShort); u != "" {
				a := repoAsset(u, vc.Branch, vc.RevisionID, "sarif_version_control_provenance")
				return &a
			}
		}
	}
	return nil
}

func parseSARIF(b *importer.Builder, r io.Reader) error {
	data, err := b.ReadAll(r)
	if err != nil {
		return err
	}
	doc, err := b.ScanJSON(data, "/runs[]/results[]")
	if err != nil {
		return err
	}
	var view sarifView
	if err := doc.Decode(&view); err != nil {
		return err
	}
	if v := strings.TrimSpace(view.Version); v != "" && v != "2.1.0" {
		return &importer.ParseError{Format: importer.FormatSARIF, Msg: fmt.Sprintf("SARIF version %q is not read; want 2.1.0", line(v, 16)), Err: importer.ErrUnknownFormat}
	}
	results := 0
	for _, run := range view.Runs {
		results += len(run.Results)
	}
	b.Result().Stats.Records = results
	if results > b.Limits().MaxFindings {
		return b.TooMany("results", b.Limits().MaxFindings)
	}
	if results == 0 && b.Options().Repository == "" {
		if len(view.Runs) > 0 && b.Options().ToolName == "" {
			if name := line(view.Runs[0].Tool.Driver.Name, capShort); name != "" {
				b.Result().Report.Tool = &ctis.Tool{Name: name}
			}
		}
		return nil
	}
	if len(view.Runs) > 0 && b.Options().ToolName == "" {
		if name := line(view.Runs[0].Tool.Driver.Name, capShort); name != "" {
			b.Result().Report.Tool = &ctis.Tool{Name: name}
		}
	}
	asset := b.CodeAsset(sarifProvenance(&view))
	if c, err := ctis.CanonicalAssetValue(asset.Type, asset.Value); err == nil {
		asset.Value = c
	}
	opts := DefaultOptions()
	opts.AssetType, opts.AssetValue, opts.AssetID = asset.Type, asset.Value, asset.ID
	switch b.Options().ToolType {
	case "sast", "sca", "secret", "iac", "web3":
		opts.ToolType = b.Options().ToolType
	}
	if c := b.Options().DefaultConfidence; c >= 1 && c <= 100 {
		opts.DefaultConfidence = c
	}
	if b.Options().Repository != "" && b.Options().Branch != "" {
		opts.Branch, opts.CommitSHA = line(b.Options().Branch, capShort), line(b.Options().CommitSHA, 128)
	}
	rep, err := Import(data, opts)
	if err != nil {
		return &importer.ParseError{Format: importer.FormatSARIF, Msg: err.Error(), Err: importer.ErrMalformed}
	}
	if rep.Tool != nil && rep.Tool.Name != "" && b.Options().ToolName == "" {
		b.Result().Report.Tool = rep.Tool
	} else if opts.ToolType != "" && rep.Tool != nil && b.Result().Report.Tool != nil {
		// A named tool keeps the techniques its type states.
		b.Result().Report.Tool.Techniques = rep.Tool.Techniques
	}
	b.Result().Report.Metadata.Branch = rep.Metadata.Branch
	b.Result().Report.Rules = rep.Rules
	assetID, err := b.Asset(asset)
	if err != nil {
		return err
	}
	if assetID == "" && asset.Type == ctis.AssetTypeRepository {
		asset.Type, asset.ID = ctis.AssetTypeUnclassified, ""
		if assetID, err = b.Asset(asset); err != nil {
			return err
		}
	}
	if assetID == "" {
		b.Result().Stats.Skipped += results
		return nil
	}
	asset.ID = assetID
	for i := range rep.Findings {
		if err := b.Tick(); err != nil {
			return err
		}
		f := rep.Findings[i]
		if strings.TrimSpace(f.Title) == "" {
			// No message, no rule: nothing names what was found.
			b.Issue(importer.Issue{Path: "/runs/results", Message: "result without a message or a rule: skipped"})
			b.Result().Stats.Skipped++
			continue
		}
		f.AssetRef = asset.ID
		if err := b.Finding(f); err != nil {
			return err
		}
	}
	b.Result().Stats.Skipped += results - len(rep.Findings) // results Import did not convert
	return nil
}
