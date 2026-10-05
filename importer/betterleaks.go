package importer

import (
	"encoding/json"
	"io"
	"strconv"

	"github.com/openctemio/ctis"
)

// betterleaks JSON report: a JSON array of leak records (the report format
// gitleaks defined and betterleaks kept). The mapping is
// spec_betterleaks.go.

func init() {
	parsers[FormatBetterleaks] = parseBetterleaks
	tools[FormatBetterleaks] = ctis.Tool{Name: "betterleaks", Vendor: "Betterleaks", InfoURL: "https://github.com/betterleaks/betterleaks", Capabilities: []string{"secret"}}
}

func parseBetterleaks(b *builder, r io.Reader) error {
	return parseLeaks(b, r, FormatBetterleaks, "betterleaks")
}

// parseLeaks reads a leaks report (a JSON array of leak records) of the
// given format and tool.
func parseLeaks(b *builder, r io.Reader, format Format, tool string) error {
	data, err := readAll(r, format, b.lim)
	if err != nil {
		return err
	}
	doc, err := scanJSON(data, format, b.lim, b.obs, "/[]")
	if err != nil {
		return err
	}
	var records []json.RawMessage
	if err := doc.decode(&records); err != nil {
		return err
	}
	for i, raw := range records {
		b.res.Stats.Records++
		if err := b.tick(); err != nil {
			return err
		}
		ptr := "/" + strconv.Itoa(i)
		var rec leakRecord
		if err := json.Unmarshal(raw, &rec); err != nil {
			b.issue(doc.issueAt("/[]", i, ptr, "skipped: "+jsonErrText(err)))
			b.res.Stats.Skipped++
			continue
		}
		f, ok := leakFinding(&rec, tool)
		if !ok {
			b.issue(doc.issueAt("/[]", i, ptr, "record without RuleID or File: skipped"))
			b.res.Stats.Skipped++
			continue
		}
		f.Native.RawRef = ptr
		if err := b.finding(f); err != nil {
			return err
		}
	}
	if len(b.res.Report.Findings) == 0 && b.opts.Repository == "" {
		return nil
	}
	return b.bindAll(b.codeAsset(nil))
}
