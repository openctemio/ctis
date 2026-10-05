package importer

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/openctemio/ctis"
)

// SARIF 2.1.0. The conversion is the module's FromSARIF; this file adds the
// importer's guards around it (size, depth, string and record limits,
// UTF-8, line numbers) and chooses the asset: Options.Repository, else the
// repository the log names in versionControlProvenance, else the default
// asset. The mapping is spec_sarif.go.

func init() {
	parsers[FormatSARIF] = parseSARIF
	tools[FormatSARIF] = ctis.Tool{Name: "sarif"}
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

func parseSARIF(b *builder, r io.Reader) error {
	data, err := readAll(r, FormatSARIF, b.lim)
	if err != nil {
		return err
	}
	doc, err := scanJSON(data, FormatSARIF, b.lim, b.obs, "/runs[]/results[]")
	if err != nil {
		return err
	}
	var view sarifView
	if err := doc.decode(&view); err != nil {
		return err
	}
	if v := strings.TrimSpace(view.Version); v != "" && v != "2.1.0" {
		return &ParseError{Format: FormatSARIF, Msg: fmt.Sprintf("SARIF version %q is not read; want 2.1.0", line(v, 16)), Err: ErrUnknownFormat}
	}
	results := 0
	for _, run := range view.Runs {
		results += len(run.Results)
	}
	b.res.Stats.Records = results
	if results > b.lim.MaxFindings {
		return b.tooMany("results", b.lim.MaxFindings)
	}
	if results == 0 && b.opts.Repository == "" {
		if len(view.Runs) > 0 && b.opts.ToolName == "" {
			if name := line(view.Runs[0].Tool.Driver.Name, capShort); name != "" {
				b.res.Report.Tool = &ctis.Tool{Name: name}
			}
		}
		return nil
	}
	if len(view.Runs) > 0 && b.opts.ToolName == "" {
		if name := line(view.Runs[0].Tool.Driver.Name, capShort); name != "" {
			b.res.Report.Tool = &ctis.Tool{Name: name}
		}
	}
	asset := b.codeAsset(sarifProvenance(&view))
	opts := ctis.DefaultConvertOptions()
	opts.AssetType, opts.AssetValue, opts.AssetID = asset.Type, asset.Value, asset.ID
	if b.opts.Repository != "" && b.opts.Branch != "" {
		opts.Branch, opts.CommitSHA = line(b.opts.Branch, capShort), line(b.opts.CommitSHA, 128)
	}
	rep, err := ctis.FromSARIF(data, opts)
	if err != nil {
		return &ParseError{Format: FormatSARIF, Msg: err.Error(), Err: ErrMalformed}
	}
	if rep.Tool != nil && rep.Tool.Name != "" && b.opts.ToolName == "" {
		b.res.Report.Tool = rep.Tool
	}
	b.res.Report.Metadata.Branch = rep.Metadata.Branch
	if _, err := b.asset(asset); err != nil {
		return err
	}
	for i := range rep.Findings {
		if err := b.tick(); err != nil {
			return err
		}
		f := rep.Findings[i]
		if strings.TrimSpace(f.Title) == "" {
			// No message, no rule: nothing names what was found.
			b.issue(Issue{Path: "/runs/results", Message: "result without a message or a rule: skipped"})
			b.res.Stats.Skipped++
			continue
		}
		f.AssetRef = asset.ID
		if err := b.finding(f); err != nil {
			return err
		}
	}
	b.res.Stats.Skipped += results - len(rep.Findings) // results FromSARIF did not convert
	return nil
}
