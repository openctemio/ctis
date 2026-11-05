package importer

import (
	"bytes"
	"fmt"
	"io"

	"github.com/openctemio/ctis/v2"
)

// A CTIS 2.0 report as a file: what a tool that writes CTIS produced, or
// what an importer converted earlier (an offline conversion uploaded
// later). It is decoded strictly (ctis.Decode: an unknown member of this
// minor is an error) and every record is validated like the records of any
// other format. The report's own identity, channel, coverage and
// properties are not kept: the builder sets the report id, time and
// channel, and the receiver decides coverage. The receiver profile's
// extensions (io.openctem) are removed everywhere, so a document cannot say
// that a host is in scope or that an exposure was verified; host-bearing
// assets then get the importer's own scope verdict. The mapping is
// spec_ctis.go.

func init() {
	parsers[FormatCTIS] = parseCTIS
}

func parseCTIS(b *Builder, r io.Reader) error {
	data, err := readAll(r, FormatCTIS, b.lim)
	if err != nil {
		return err
	}
	// The streaming check bounds depth and text sizes before anything is
	// decoded, and records the member paths for the spec.
	if _, err := scanJSON(data, FormatCTIS, b.lim, b.obs); err != nil {
		return err
	}
	rep, unknown, err := ctis.Decode(bytes.NewReader(data))
	if err != nil {
		return &ParseError{Format: FormatCTIS, Msg: line(err.Error(), 300), Err: ErrMalformed}
	}
	for _, u := range unknown.Entries {
		b.issue(Issue{Path: line(u.Path, 200), Message: fmt.Sprintf("member of a newer CTIS minor not kept (%s)", u.Kind)})
	}
	if unknown.Omitted > 0 {
		b.issue(Issue{Message: fmt.Sprintf("%d more members of a newer CTIS minor not kept", unknown.Omitted)})
	}
	dropReceiverExtensions(&rep)

	out := b.res.Report
	if rep.Tool != nil && b.opts.ToolName == "" {
		if name := line(rep.Tool.Name, 64); name != "" {
			out.Tool = &ctis.Tool{
				Name:    name,
				Version: line(rep.Tool.Version, 64),
				Vendor:  line(rep.Tool.Vendor, capShort),
				InfoURL: webURL(rep.Tool.InfoURL),
			}
			for _, t := range rep.Tool.Techniques {
				if t.IsValid() {
					out.Tool.Techniques = append(out.Tool.Techniques, t)
				}
			}
		}
	}
	switch {
	case len(rep.Assets) > b.lim.MaxAssets:
		return b.tooMany("assets", b.lim.MaxAssets)
	case len(rep.Findings) > b.lim.MaxFindings:
		return b.tooMany("findings", b.lim.MaxFindings)
	case len(rep.Dependencies) > b.lim.MaxComponents:
		return b.tooMany("components", b.lim.MaxComponents)
	case len(rep.Endpoints) > b.lim.MaxEndpoints:
		return b.tooMany("endpoints", b.lim.MaxEndpoints)
	case len(rep.Relationships) > ctis.MaxRelationships:
		return b.tooMany("relationships", ctis.MaxRelationships)
	}
	for _, a := range rep.Assets {
		if _, dup := b.assets[a.ID]; dup || a.ID == "" {
			b.issue(Issue{Message: fmt.Sprintf("asset without an id or with a repeated id %q: left out", line(a.ID, 64))})
			continue
		}
		b.assets[a.ID] = len(out.Assets)
		out.Assets = append(out.Assets, a)
	}
	out.Rules = rep.Rules
	out.Dependencies = rep.Dependencies
	out.Relationships = rep.Relationships
	out.Endpoints = rep.Endpoints
	for _, f := range rep.Findings {
		b.res.Stats.Records++
		if err := b.tick(); err != nil {
			return err
		}
		// A claim that the finding was verified carries no weight in a
		// person's file: verification is the receiver's own step.
		f.Validation = nil
		if err := b.finding(f); err != nil {
			return err
		}
	}
	b.stampImportScope()
	return nil
}
