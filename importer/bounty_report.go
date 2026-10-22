package importer

import (
	"bytes"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/openctemio/ctis"
)

// Generic bug-bounty / disclosure report: {"bounty_reports": [...]} as JSON,
// or one report per row as CSV (forced with Options.Format; Detect never
// names CSV). One record is one report is one finding. The mapping is
// spec_bounty_report.go; the importer never resolves a name, opens a socket
// or follows a URL, whatever a record says.

func init() {
	parsers[FormatBountyReport] = parseBountyReport
	tools[FormatBountyReport] = ctis.Tool{Name: "bounty_report"}
}

const (
	brRecords = "/bounty_reports[]"

	capBountyDescription = 64 << 10
	capBountySteps       = 64 << 10
	capBountyImpact      = 16 << 10
	capBountyURL         = 2048
	capBountyRef         = 128
	capBountyIntake      = 64
	capBountyResearcher  = 64

	// defaultBountyIntake is the intake of records that carry none, when
	// Options.BountyIntake is empty too.
	defaultBountyIntake = "import"
)

var (
	brIntakeRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)
	brCWERE    = regexp.MustCompile(`^CWE-[0-9]{1,6}$`)
	brAmountRE = regexp.MustCompile(`^[0-9]{1,12}(\.[0-9]{1,2})?$`)
	brCcyRE    = regexp.MustCompile(`^[A-Z]{3}$`)
	brVectorRE = regexp.MustCompile(`^CVSS:(3\.0|3\.1|4\.0)/[A-Za-z0-9:/.]+$`)
	brHostRE   = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+\.?$`)
	brSchemeRE = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9+.-]*):(.*)$`)

	brStates      = map[string]bool{"new": true, "triaged": true, "duplicate": true, "informative": true, "not_applicable": true, "resolved": true}
	brRewardState = map[string]bool{"none": true, "pending": true, "paid": true}
	brDisclosure  = map[string]bool{"private": true, "coordinated": true, "disclosed": true}
	// Schemes an application id may never start with: they are what a
	// consumer would follow or run.
	brBadSchemes = map[string]bool{"javascript": true, "data": true, "file": true, "gopher": true, "ftp": true, "vbscript": true, "blob": true, "ws": true, "wss": true}
)

type brReward struct {
	Amount   flexStr `json:"amount"`
	Currency flexStr `json:"currency"`
	Status   flexStr `json:"status"`
}

type brDisclosureIn struct {
	State      flexStr `json:"state"`
	AgreedDate flexStr `json:"agreed_date"`
}

// brRecord is one report; CSV rows are read into the same shape.
type brRecord struct {
	ReportRef        flexStr         `json:"report_ref"`
	Intake           flexStr         `json:"intake"`
	Title            flexStr         `json:"title"`
	SubmittedAt      flexStr         `json:"submitted_at"`
	Researcher       flexStr         `json:"researcher"`
	ReportedSeverity flexStr         `json:"reported_severity"`
	State            flexStr         `json:"state"`
	Weakness         flexStr         `json:"weakness"`
	CVSSVector       flexStr         `json:"cvss_vector"`
	URL              flexStr         `json:"url"`
	Asset            flexStr         `json:"asset"`
	Parameter        flexStr         `json:"parameter"`
	Description      flexStr         `json:"description"`
	Steps            flexStr         `json:"steps"`
	Impact           flexStr         `json:"impact"`
	Reward           *brReward       `json:"reward"`
	Disclosure       *brDisclosureIn `json:"disclosure"`
}

// brColumns maps a CSV column to its field and its spec path.
var brColumns = map[string]struct {
	set  func(*brRecord, string)
	path string
}{
	"report_ref":             {func(r *brRecord, v string) { r.ReportRef = flexStr(v) }, "report_ref"},
	"intake":                 {func(r *brRecord, v string) { r.Intake = flexStr(v) }, "intake"},
	"title":                  {func(r *brRecord, v string) { r.Title = flexStr(v) }, "title"},
	"submitted_at":           {func(r *brRecord, v string) { r.SubmittedAt = flexStr(v) }, "submitted_at"},
	"researcher":             {func(r *brRecord, v string) { r.Researcher = flexStr(v) }, "researcher"},
	"reported_severity":      {func(r *brRecord, v string) { r.ReportedSeverity = flexStr(v) }, "reported_severity"},
	"state":                  {func(r *brRecord, v string) { r.State = flexStr(v) }, "state"},
	"weakness":               {func(r *brRecord, v string) { r.Weakness = flexStr(v) }, "weakness"},
	"cvss_vector":            {func(r *brRecord, v string) { r.CVSSVector = flexStr(v) }, "cvss_vector"},
	"url":                    {func(r *brRecord, v string) { r.URL = flexStr(v) }, "url"},
	"asset":                  {func(r *brRecord, v string) { r.Asset = flexStr(v) }, "asset"},
	"parameter":              {func(r *brRecord, v string) { r.Parameter = flexStr(v) }, "parameter"},
	"description":            {func(r *brRecord, v string) { r.Description = flexStr(v) }, "description"},
	"steps":                  {func(r *brRecord, v string) { r.Steps = flexStr(v) }, "steps"},
	"impact":                 {func(r *brRecord, v string) { r.Impact = flexStr(v) }, "impact"},
	"reward_amount":          {func(r *brRecord, v string) { brRew(r).Amount = flexStr(v) }, "reward/amount"},
	"reward_currency":        {func(r *brRecord, v string) { brRew(r).Currency = flexStr(v) }, "reward/currency"},
	"reward_status":          {func(r *brRecord, v string) { brRew(r).Status = flexStr(v) }, "reward/status"},
	"disclosure_state":       {func(r *brRecord, v string) { brDisc(r).State = flexStr(v) }, "disclosure/state"},
	"disclosure_agreed_date": {func(r *brRecord, v string) { brDisc(r).AgreedDate = flexStr(v) }, "disclosure/agreed_date"},
}

func brRew(r *brRecord) *brReward {
	if r.Reward == nil {
		r.Reward = &brReward{}
	}
	return r.Reward
}

func brDisc(r *brRecord) *brDisclosureIn {
	if r.Disclosure == nil {
		r.Disclosure = &brDisclosureIn{}
	}
	return r.Disclosure
}

func parseBountyReport(b *builder, r io.Reader) error {
	intake := defaultBountyIntake
	if o := strings.ToLower(strings.TrimSpace(b.opts.BountyIntake)); o != "" {
		if !validIntake(o) {
			return &ParseError{Format: FormatBountyReport, Msg: "Options.BountyIntake is not a valid intake (1 to 64 characters of a-z, 0-9, '.', '_' and '-', starting with a letter or digit)", Err: ErrMalformed}
		}
		intake = o
	}
	data, err := readAll(r, FormatBountyReport, b.lim)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	first := byte(0)
	if t := bytes.TrimLeft(data, " \t\r\n"); len(t) > 0 {
		first = t[0]
	}
	switch first {
	case '{':
		return b.brJSON(data, intake, seen)
	case '[':
		return &ParseError{Format: FormatBountyReport, Msg: `a JSON array is not accepted; wrap the reports as {"bounty_reports": [...]}`, Err: ErrMalformed}
	}
	return b.brCSV(data, intake, seen)
}

func (b *builder) brJSON(data []byte, intake string, seen map[string]bool) error {
	doc, err := scanJSON(data, FormatBountyReport, b.lim, b.obs, brRecords)
	if err != nil {
		return err
	}
	var top struct {
		Reports []json.RawMessage `json:"bounty_reports"`
	}
	if err := doc.decode(&top); err != nil {
		return err
	}
	if top.Reports == nil {
		return &ParseError{Format: FormatBountyReport, Msg: "no bounty_reports array", Err: ErrMalformed}
	}
	for i, raw := range top.Reports {
		if err := b.brCount(i); err != nil {
			return err
		}
		ptr := "/bounty_reports/" + strconv.Itoa(i)
		at := func(msg string) Issue { return doc.issueAt(brRecords, i, ptr, msg) }
		var rec brRecord
		if err := json.Unmarshal(raw, &rec); err != nil {
			b.issue(at("skipped: " + jsonErrText(err)))
			b.res.Stats.Skipped++
			continue
		}
		if err := b.brFinding(&rec, intake, ptr, at, seen); err != nil {
			return err
		}
	}
	return nil
}

func (b *builder) brCSV(data []byte, intake string, seen map[string]bool) error {
	if !utf8.Valid(data) {
		return &ParseError{Format: FormatBountyReport, Msg: "input is not valid UTF-8", Err: ErrMalformed}
	}
	cr := csv.NewReader(bytes.NewReader(data))
	cr.FieldsPerRecord = 0 // every row has as many cells as the header
	cr.ReuseRecord = false
	head, err := cr.Read()
	if err != nil {
		return brCSVError(err, "no header row")
	}
	cols := make([]string, len(head))
	have := map[string]bool{}
	b.obs.add("/bounty_reports")
	b.obs.add(brRecords)
	for i, h := range head {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" || len(h) > b.lim.MaxTextBytes {
			return &ParseError{Format: FormatBountyReport, Line: 1, Msg: "a header cell is empty or too long", Err: ErrMalformed}
		}
		if have[h] {
			return &ParseError{Format: FormatBountyReport, Line: 1, Msg: "a column is named twice", Err: ErrMalformed}
		}
		have[h] = true
		cols[i] = h
		if c, ok := brColumns[h]; ok {
			if parent, _, nested := strings.Cut(c.path, "/"); nested {
				b.obs.add(brRecords + "/" + parent)
			}
			b.obs.add(brRecords + "/" + c.path)
		} else {
			b.obs.add(brRecords + "/" + line(h, 64))
		}
	}
	if !have["report_ref"] || !have["title"] {
		return &ParseError{Format: FormatBountyReport, Line: 1, Msg: "the header needs the columns report_ref and title", Err: ErrMalformed}
	}
	for i := 0; ; i++ {
		row, err := cr.Read()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return brCSVError(err, "")
		}
		if err := b.brCount(i); err != nil {
			return err
		}
		ln, _ := cr.FieldPos(0)
		var rec brRecord
		for k, cell := range row {
			if len(cell) > b.lim.MaxTextBytes {
				return &ParseError{Format: FormatBountyReport, Line: ln, Msg: fmt.Sprintf("a cell is longer than %d bytes", b.lim.MaxTextBytes), Err: ErrTooLarge}
			}
			if c, ok := brColumns[cols[k]]; ok && strings.TrimSpace(cell) != "" {
				c.set(&rec, cell)
			}
		}
		ptr := "/bounty_reports/" + strconv.Itoa(i)
		at := func(msg string) Issue { return Issue{Path: ptr, Line: ln, Message: msg} }
		if err := b.brFinding(&rec, intake, ptr, at, seen); err != nil {
			return err
		}
	}
}

// brCSVError turns a csv error into a ParseError without echoing the cell.
func brCSVError(err error, empty string) error {
	if errors.Is(err, io.EOF) && empty != "" {
		return &ParseError{Format: FormatBountyReport, Msg: empty, Err: ErrMalformed}
	}
	var pe *csv.ParseError
	if errors.As(err, &pe) {
		return &ParseError{Format: FormatBountyReport, Line: pe.Line, Column: pe.Column, Msg: "CSV is malformed (bad quoting or a row with a different number of cells than the header)", Err: ErrMalformed}
	}
	return &ParseError{Format: FormatBountyReport, Msg: "read input: " + err.Error(), Err: ErrMalformed}
}

// brCount counts a record and bounds how many one input may hold.
func (b *builder) brCount(i int) error {
	b.res.Stats.Records++
	if i >= b.lim.MaxFindings {
		return b.tooMany("records", b.lim.MaxFindings)
	}
	return b.tick()
}

// --- text hygiene -------------------------------------------------------

// isBidi reports the bidirectional control characters that can reorder the
// text around them.
func isBidi(r rune) bool {
	return (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) || r == 0x200E || r == 0x200F
}

// precut bounds a value to about limit characters before it is processed, so
// a huge value costs no more than the cap.
func precut(s string, limit int) string {
	if n := limit*4 + 64; len(s) > n {
		s = s[:n]
		for len(s) > 0 && !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
	}
	return s
}

// cleanText removes NUL and the other control characters, the bidi controls
// and invalid UTF-8. multi keeps newlines (CR and CRLF become one) and tabs;
// otherwise they become spaces.
func cleanText(s string, multi bool) string {
	if multi {
		s = strings.ReplaceAll(s, "\r\n", "\n")
	}
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			if multi {
				if r == '\r' {
					return '\n'
				}
				return r
			}
			return ' '
		case unicode.IsControl(r) || r == utf8.RuneError || isBidi(r):
			return -1
		}
		return r
	}, s)
}

// brLine cleans a one-line value (title, parameter).
func brLine(s string, limit int) string {
	return line(cleanText(precut(s, limit), false), limit)
}

// brMulti cleans a multi-line value and cuts it to limit characters; it
// reports whether it had to cut.
func brMulti(s string, limit int) (string, bool) {
	c := strings.TrimSpace(cleanText(precut(s, limit), true))
	cut := utf8.RuneCountInString(c) > limit || len(s) > limit*4+64
	return text(c, limit), cut
}

// plainID reports whether s has nothing but printable characters (no bidi
// control, no control character, no unusual space).
func plainID(s string) bool {
	for _, r := range s {
		if !unicode.IsPrint(r) || isBidi(r) || r == utf8.RuneError {
			return false
		}
	}
	return true
}

func validIntake(s string) bool {
	return len(s) >= 1 && len(s) <= capBountyIntake && brIntakeRE.MatchString(s)
}

func validRef(s string) bool {
	if len(s) < 1 || len(s) > capBountyRef {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7E {
			return false
		}
	}
	return true
}

// --- one record -----------------------------------------------------------

func normBountySeverity(s string) (sev ctis.Severity, prop string, ok bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return ctis.SeverityCritical, "critical", true
	case "high":
		return ctis.SeverityHigh, "high", true
	case "medium":
		return ctis.SeverityMedium, "medium", true
	case "low":
		return ctis.SeverityLow, "low", true
	case "info", "informational":
		return ctis.SeverityInfo, "info", true
	case "none":
		return ctis.SeverityInfo, "none", true
	}
	return "", "", false
}

func (b *builder) brFinding(rec *brRecord, defIntake, ptr string, at func(string) Issue, seen map[string]bool) error {
	skip := func(msg string) error {
		b.issue(at(msg))
		b.res.Stats.Skipped++
		return nil
	}
	iss := func(msg string) { b.issue(at(msg)) }

	ref := rec.ReportRef.String()
	if ref == "" {
		return skip("record without a report_ref: skipped")
	}
	if !validRef(ref) {
		return skip("report_ref is not valid (1 to 128 printable ASCII characters, no spaces): skipped")
	}
	intake := defIntake
	if v := rec.Intake.String(); v != "" {
		v = strings.ToLower(v)
		if !validIntake(v) {
			return skip("intake is not valid (1 to 64 characters of a-z, 0-9, '.', '_' and '-', starting with a letter or digit): skipped")
		}
		intake = v
	}
	title := brLine(rec.Title.String(), capTitle)
	if title == "" {
		return skip("record without a title: skipped")
	}
	key := intake + "\x00" + ref
	if seen[key] {
		return skip("report_ref repeated for the same intake: the first record is kept, this one skipped")
	}
	seen[key] = true

	sum := sha256.Sum256([]byte(key))
	f := ctis.Finding{
		Type:        ctis.FindingTypeVulnerability,
		Title:       title,
		Fingerprint: "bounty_report:v1:" + hex.EncodeToString(sum[:]),
		Native:      &ctis.NativeIdentity{Scheme: ctis.NativeSchemeOther, InstanceID: ref, RawRef: ptr},
	}
	props := map[string]any{"intake": intake, "ref": ref}

	// Description.
	desc, cut := brMulti(rec.Description.String(), capBountyDescription)
	if cut {
		iss("description is longer than 64 KiB: truncated")
	}
	if s, c := brMulti(rec.Steps.String(), capBountySteps); s != "" {
		desc += "\n\n## Steps to reproduce\n\n" + s
		if c {
			iss("steps is longer than 64 KiB: truncated")
		}
	}
	if s, c := brMulti(rec.Impact.String(), capBountyImpact); s != "" {
		desc += "\n\n## Impact\n\n" + s
		if c {
			iss("impact is longer than 16 KiB: truncated")
		}
	}
	f.Description = strings.TrimSpace(desc)

	// Severity.
	rawSev := rec.ReportedSeverity.String()
	sev, sevProp, ok := normBountySeverity(rawSev)
	if rawSev != "" {
		f.Native.Severity = brLine(rawSev, ctis.MaxNativeValueLen)
		if !ok {
			iss("unknown reported_severity: not kept")
		}
	}
	if ok {
		props["reported_severity"] = sevProp
	} else {
		// No scoring helper exists in the library for a CVSS vector, so a
		// report without a usable severity is medium.
		sev = ctis.SeverityMedium
	}
	f.Severity = sev
	f.Native.Status = brLine(rec.State.String(), ctis.MaxNativeValueLen)

	// State.
	if raw := rec.State.String(); raw != "" {
		st := strings.Join(strings.Fields(strings.ReplaceAll(strings.ToLower(raw), "-", " ")), "_")
		if brStates[st] {
			props["state"] = st
		} else {
			iss("unknown state: not kept")
		}
	}

	// People and times.
	if r := rec.Researcher.String(); r != "" {
		if utf8.RuneCountInString(r) <= capBountyResearcher && plainID(r) {
			props["researcher"] = r
		} else {
			iss("researcher is not valid (at most 64 printable characters on one line): dropped")
		}
	}
	if s := rec.SubmittedAt.String(); s != "" {
		if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
			t = t.UTC()
			props["submitted_at"] = t.Format(time.RFC3339)
			f.FirstSeenAt = &t
			f.SourceLifecycle = &ctis.SourceLifecycle{FirstFound: &t}
		} else {
			iss("submitted_at is not an RFC 3339 time: dropped")
		}
	}

	// Weakness and CVSS.
	vuln := &ctis.VulnerabilityDetails{}
	if w := rec.Weakness.String(); w != "" {
		if brCWERE.MatchString(w) {
			props["weakness"] = w
			vuln.CWEID, vuln.CWEIDs = w, []string{w}
		} else {
			iss("weakness is not of the form CWE-<n>: dropped")
		}
	}
	if v := rec.CVSSVector.String(); v != "" {
		if len(v) <= ctis.MaxScoreVectorLen && brVectorRE.MatchString(v) {
			addScore(&f, ctis.Score{System: ctis.ScoreSystemCVSS, Version: ctis.CVSSVersionOfVector(v), Vector: v, Source: "reporter"})
		} else {
			iss("cvss_vector is not a CVSS 3.0, 3.1 or 4.0 vector: dropped")
		}
	}
	if vuln.CWEID != "" {
		f.Vulnerability = vuln
	}

	// Parameter, URL, reward, disclosure.
	if p := brLine(rec.Parameter.String(), capShort); p != "" {
		props["parameter"] = p
	}
	if u := rec.URL.String(); u != "" {
		if brHTTPS(u) {
			props["url"] = u
		} else {
			iss("url is not an https URL without credentials of at most 2048 characters: dropped")
		}
	}
	if rw := brRewardOf(rec.Reward, iss); rw != nil {
		props["reward"] = rw
	}
	if d := brDisclosureOf(rec.Disclosure, iss); d != nil {
		props["disclosure"] = d
	}

	// Asset.
	a, path, ok := brAsset(rec.Asset.String(), iss)
	if !ok {
		a = b.defaultAsset()
	}
	if path != "" {
		props["endpoint_path"] = path
	}
	f.Properties = ctis.Properties{"bounty_report": props}
	id, err := b.asset(a)
	if err != nil {
		return err
	}
	f.AssetRef = id
	return b.finding(f)
}

// brHTTPS reports whether u may be kept as the record's url: https only, a
// host, no credentials, at most 2048 characters, nothing unprintable.
func brHTTPS(u string) bool {
	if len(u) > capBountyURL || strings.ContainsAny(u, " \\") || !plainID(u) {
		return false
	}
	p, err := url.Parse(u)
	if err != nil || p.Scheme != "https" || p.Hostname() == "" || p.User != nil || p.Opaque != "" {
		return false
	}
	return true
}

func brRewardOf(r *brReward, iss func(string)) map[string]any {
	if r == nil {
		return nil
	}
	out := map[string]any{}
	if v := r.Amount.String(); v != "" {
		if brAmountRE.MatchString(v) {
			out["amount"] = v
		} else {
			iss("reward amount is not a decimal of at most 12 digits and 2 decimals: dropped")
		}
	}
	if v := r.Currency.String(); v != "" {
		if brCcyRE.MatchString(v) {
			out["currency"] = v
		} else {
			iss("reward currency is not three capital letters: dropped")
		}
	}
	if v := r.Status.String(); v != "" {
		if s := strings.ToLower(v); brRewardState[s] {
			out["status"] = s
		} else {
			iss("reward status is not none, pending or paid: dropped")
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func brDisclosureOf(d *brDisclosureIn, iss func(string)) map[string]any {
	if d == nil {
		return nil
	}
	out := map[string]any{}
	if v := d.State.String(); v != "" {
		if s := strings.ToLower(v); brDisclosure[s] {
			out["state"] = s
		} else {
			iss("disclosure state is not private, coordinated or disclosed: dropped")
		}
	}
	if v := d.AgreedDate.String(); v != "" {
		if t, err := time.Parse("2006-01-02", v); err == nil {
			out["agreed_date"] = t.Format("2006-01-02")
		} else {
			iss("disclosure agreed_date is not a YYYY-MM-DD date: dropped")
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// brAsset reads the asset of a record. ok is false when there is none (or an
// unusable one, with an issue): the caller files the finding on the default
// asset. path is the path of an http(s) URL (never its query, fragment or
// credentials). Nothing is resolved or contacted.
func brAsset(raw string, iss func(string)) (a ctis.Asset, path string, ok bool) {
	s := brLine(raw, 2048)
	if s == "" {
		return a, "", false
	}
	host := func(h string) (ctis.Asset, bool) {
		h = strings.ToLower(strings.TrimSuffix(h, "."))
		if h == "" || len(h) > capShort {
			return ctis.Asset{}, false
		}
		t := ctis.AssetTypeDomain
		if net.ParseIP(h) != nil {
			t = ctis.AssetTypeIPAddress
		}
		return ctis.Asset{ID: "host-" + h, Type: t, Value: h, Name: h}, true
	}
	low := strings.ToLower(s)
	if strings.HasPrefix(low, "http://") || strings.HasPrefix(low, "https://") {
		u, err := url.Parse(s)
		if err != nil || u.Hostname() == "" {
			iss("asset is not a valid URL: the default asset is used")
			return a, "", false
		}
		if u.User != nil {
			iss("asset URL carried credentials: removed")
		}
		h, good := host(u.Hostname())
		if !good {
			iss("asset URL has an unusable host: the default asset is used")
			return a, "", false
		}
		p := brLine(u.EscapedPath(), 1024)
		return h, p, true
	}
	if ip, err := netip.ParseAddr(s); err == nil && ip.Zone() == "" {
		h, good := host(ip.String())
		return h, "", good
	}
	if brHostRE.MatchString(s) {
		h, good := host(s)
		return h, "", good
	}
	if m := brSchemeRE.FindStringSubmatch(s); m != nil && (strings.HasPrefix(m[2], "//") || brBadSchemes[strings.ToLower(m[1])]) {
		iss("asset names a URL that is not http or https: the default asset is used")
		return a, "", false
	}
	v := brLine(s, capShort)
	return ctis.Asset{ID: "app-" + v, Type: ctis.AssetTypeWebApplication, Value: v, Name: v}, "", true
}
