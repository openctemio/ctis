package importer

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/openctemio/ctis"
	"github.com/openctemio/ctis/weburl"
)

// A bundle is several files that together describe one run of one tool: a
// reconFTW results directory. ParseBundle joins them into one CTIS report.
// The mapping is spec_reconftw.go.

const (
	// FormatReconFTW is a reconFTW results directory. It is read with
	// ParseBundle, never with Parse.
	FormatReconFTW Format = "reconftw"

	// formatReconFTWv3 is the spec key of the older layout; Result.Format is
	// still FormatReconFTW and Result.Layout is "v3".
	formatReconFTWv3 Format = "reconftw_v3"
)

func init() {
	parsers[FormatReconFTW] = func(*builder, io.Reader) error {
		return &ParseError{Format: FormatReconFTW, Msg: "a recon results directory holds many files; read it with ParseBundle", Err: ErrUnknownFormat}
	}
	t := ctis.Tool{Name: "reconftw", Vendor: "six2dez", InfoURL: "https://github.com/six2dez/reconftw", Capabilities: []string{"subdomain", "http_probe", "crawler", "easm"}}
	tools[FormatReconFTW] = t
	tools[formatReconFTWv3] = t
}

// BundleLimits bound what ParseBundle accepts. A zero field takes its
// default (DefaultBundleLimits). A recon directory is large, so these differ
// from the single-file defaults of ArchiveLimits.
type BundleLimits struct {
	// Most files listed in the archive.
	MaxFilesListed int
	// Most files whose content is read.
	MaxFilesRead int
	// Largest uncompressed file.
	MaxFileBytes int64
	// Largest sum of the files that are read.
	MaxTotalBytes int64
	// Longest line of a list file; a longer line is skipped.
	MaxLineBytes int
	// Most lines read from one file.
	MaxLines int
	// Deepest directory nesting of a file name.
	MaxPathDepth int
	// Largest ratio of uncompressed to compressed size of one file.
	MaxRatio int64
}

// DefaultBundleLimits returns the limits a zero BundleLimits stands for.
func DefaultBundleLimits() BundleLimits {
	return BundleLimits{
		MaxFilesListed: 50_000,
		MaxFilesRead:   300,
		MaxFileBytes:   256 << 20,
		MaxTotalBytes:  2 << 30,
		MaxLineBytes:   64 << 10,
		MaxLines:       2_000_000,
		MaxPathDepth:   32,
		MaxRatio:       200,
	}
}

func (l BundleLimits) withDefaults() BundleLimits {
	d := DefaultBundleLimits()
	if l.MaxFilesListed <= 0 {
		l.MaxFilesListed = d.MaxFilesListed
	}
	if l.MaxFilesRead <= 0 {
		l.MaxFilesRead = d.MaxFilesRead
	}
	if l.MaxFileBytes <= 0 {
		l.MaxFileBytes = d.MaxFileBytes
	}
	if l.MaxTotalBytes <= 0 {
		l.MaxTotalBytes = d.MaxTotalBytes
	}
	if l.MaxLineBytes <= 0 {
		l.MaxLineBytes = d.MaxLineBytes
	}
	if l.MaxLines <= 0 {
		l.MaxLines = d.MaxLines
	}
	if l.MaxPathDepth <= 0 {
		l.MaxPathDepth = d.MaxPathDepth
	}
	if l.MaxRatio <= 0 {
		l.MaxRatio = d.MaxRatio
	}
	return l
}

// OpenBundleZip lists the files of a ZIP archive that holds a bundle, with
// the guards of OpenZip (traversal, absolute and backslash paths, links,
// encrypted and nested archives, bombs) at the bundle limits.
func OpenBundleZip(r io.ReaderAt, size int64, lim BundleLimits) ([]ArchiveFile, error) {
	lim = lim.withDefaults()
	return OpenZip(r, size, ArchiveLimits{
		MaxEntries:    lim.MaxFilesListed,
		MaxEntryBytes: lim.MaxFileBytes,
		MaxTotalBytes: lim.MaxTotalBytes,
		MaxRatio:      lim.MaxRatio,
	})
}

// bundleMarkers are the files whose position names the directory of a recon
// run.
var bundleMarkers = []string{"report/report.json", "subdomains/subdomains.txt", "webs/webs.txt", "hosts/ips.txt", "webs/web_full_info.txt"}

// bundleDirs are the top-level directories of a recon run. A bundle needs two
// of them.
var bundleDirs = map[string]bool{
	"report": true, "subdomains": true, "hosts": true, "webs": true, "js": true, "gf": true,
	"nuclei_output": true, "osint": true, "fuzzing": true, "vulns": true, "screenshots": true, ".log": true,
}

// DetectBundle names the format of a bundle from the file names alone: it
// recognizes a reconFTW results directory by its layout. It never reads a
// file and never errors on hostile names.
func DetectBundle(names []string) (Format, bool) {
	_, err := bundleRoot(names)
	if err != nil {
		return "", false
	}
	return FormatReconFTW, true
}

// bundleRoot returns the directory of the recon run ("" or ending in "/").
func bundleRoot(names []string) (string, error) {
	roots := map[string]bool{}
	for _, n := range names {
		for _, m := range bundleMarkers {
			if n == m {
				roots[""] = true
			} else if strings.HasSuffix(n, "/"+m) {
				root := n[:len(n)-len(m)]
				if strings.Count(root, "/") <= 4 {
					roots[root] = true
				}
			}
		}
	}
	switch len(roots) {
	case 0:
		return "", &ParseError{Msg: "the files are not a recognized recon results directory; supported: reconftw", Err: ErrUnknownFormat}
	case 1:
	default:
		return "", &ParseError{Format: FormatReconFTW, Msg: "the archive holds more than one recon directory; import one run at a time", Err: ErrMalformed}
	}
	var root string
	for r := range roots {
		root = r
	}
	dirs := map[string]bool{}
	for _, n := range names {
		if !strings.HasPrefix(n, root) {
			continue
		}
		rest := n[len(root):]
		if i := strings.IndexByte(rest, '/'); i > 0 && bundleDirs[rest[:i]] {
			dirs[rest[:i]] = true
		}
	}
	if len(dirs) < 2 {
		return "", &ParseError{Msg: "the files are not a recognized recon results directory; supported: reconftw", Err: ErrUnknownFormat}
	}
	return root, nil
}

// ParseBundle joins the files of one tool run into one CTIS report. Only
// FormatReconFTW is a bundle format; opts.Format may name it or be empty.
//
// It returns a *ParseError (wrapping ErrUnknownFormat, ErrTooLarge,
// ErrUnsafe or ErrMalformed) when the bundle cannot be read at all: an
// unsafe path, a decompression bomb, more files or bytes than the limits
// allow, or no recognizable layout. Problems with single lines or files do
// not fail the parse; they are in Result.Issues. Files that are not read are
// in Result.Skipped (on purpose) or Result.Unmapped (not known).
func ParseBundle(ctx context.Context, files []ArchiveFile, opts Options) (*Result, error) {
	res, _, err := parseBundle(ctx, files, opts)
	return res, err
}

// bundleRun is the state of one ParseBundle.
type bundleRun struct {
	ctx   context.Context
	b     *builder
	bl    BundleLimits
	now   time.Time
	files map[string]ArchiveFile // rel -> file
	spec  Spec

	total     int64
	filesRead int

	domain string // the target domain
	scope  []string

	// What the list files held.
	subs     []ctis.SubdomainInput
	subSeen  map[string]bool
	ips      []string
	ipSeen   map[string]bool
	cdn      map[string]cdnInfo
	ports    []ctis.OpenPortInput
	live     []ctis.LiveHostInput
	liveSeen map[string]bool
	plain    []ctis.LiveHostInput
	urls     []ctis.DiscoveredURLInput
	wafs     map[string]string
	takeover map[string]string
	buckets  []bucketCand
	nuclei   []string
}

type cdnInfo struct{ provider, kind string }

type bucketCand struct{ host, kind, provider, label string }

func parseBundle(ctx context.Context, files []ArchiveFile, opts Options) (*Result, []string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if opts.Format != "" && opts.Format != FormatReconFTW {
		return nil, nil, &ParseError{Format: opts.Format, Msg: "not a bundle format; supported: " + string(FormatReconFTW), Err: ErrUnknownFormat}
	}
	opts.Limits = opts.Limits.withDefaults()
	bl := opts.Bundle.withDefaults()
	if len(files) > bl.MaxFilesListed {
		return nil, nil, &ParseError{Format: FormatReconFTW, Msg: fmt.Sprintf("more than %d files", bl.MaxFilesListed), Err: ErrTooLarge}
	}

	// Names: every file is checked as an archive entry is, whatever made it.
	names := make([]string, 0, len(files))
	byName := make(map[string]ArchiveFile, len(files))
	for _, f := range files {
		if err := checkEntryName(f.Name); err != nil {
			return nil, nil, &ParseError{Format: FormatReconFTW, Msg: fmt.Sprintf("file %q: %v", safeLabel(f.Name), err), Err: ErrUnsafe}
		}
		name := path.Clean(f.Name)
		if strings.Count(name, "/")+1 > bl.MaxPathDepth {
			return nil, nil, &ParseError{Format: FormatReconFTW, Msg: fmt.Sprintf("file %q is nested deeper than %d directories", safeLabel(f.Name), bl.MaxPathDepth), Err: ErrUnsafe}
		}
		if _, dup := byName[name]; dup {
			return nil, nil, &ParseError{Format: FormatReconFTW, Msg: fmt.Sprintf("file %q is listed twice", safeLabel(name)), Err: ErrUnsafe}
		}
		byName[name] = f
		names = append(names, name)
	}
	root, err := bundleRoot(names)
	if err != nil {
		return nil, nil, err
	}

	b := newBuilder(ctx, FormatReconFTW, opts)
	now := b.res.Report.Metadata.Timestamp
	r := &bundleRun{
		ctx: ctx, b: b, bl: bl, now: now,
		files:   map[string]ArchiveFile{},
		subSeen: map[string]bool{}, ipSeen: map[string]bool{}, liveSeen: map[string]bool{},
		cdn: map[string]cdnInfo{}, wafs: map[string]string{}, takeover: map[string]string{},
	}
	sort.Strings(names)
	var rels, outside []string
	for _, n := range names {
		if strings.HasPrefix(n, root) {
			rel := "/" + n[len(root):]
			r.files[rel] = byName[n]
			rels = append(rels, rel)
		} else {
			outside = append(outside, n)
		}
	}

	// The target domain: the report, else the directory's own name.
	if root != "" {
		if d, ok := dnsName(path.Base(strings.TrimSuffix(root, "/"))); ok && strings.Contains(d, ".") {
			r.domain = d
		}
	}

	// Layout and version come first: they decide which spec reads the rest.
	hasReport := false
	if _, ok := r.files["/report/report.json"]; ok {
		hasReport = true
		if err := r.readReport(); err != nil {
			return nil, nil, err
		}
	}
	version, err := r.readVersion(rels)
	if err != nil {
		return nil, nil, err
	}
	layout := "v3"
	if hasReport || versionMajor(version) >= 4 {
		layout = "v4"
	}
	b.format = FormatReconFTW
	if layout == "v3" {
		b.format = formatReconFTWv3
	}
	r.spec = specs[b.format]
	if version == "" {
		version = "unknown-" + layout
	}
	b.res.Report.Tool.Version = version
	b.res.Layout = layout
	b.res.Report.Metadata.SourceType = firstNonEmpty(opts.SourceType, "manual")
	if r.domain != "" {
		b.res.Report.Metadata.Scope = &ctis.Scope{Name: r.domain, Type: "domain"}
		b.res.Report.Metadata.SourceRef = "reconftw:" + r.domain
	}
	r.scope = opts.ScopeDomains
	if len(r.scope) == 0 && r.domain != "" {
		r.scope = []string{r.domain}
	}
	for i, d := range r.scope {
		r.scope[i] = strings.ToLower(strings.Trim(strings.TrimSpace(d), "."))
	}

	// Every file is matched against the spec; only mapped files are opened.
	var seen []string
	var unmapped []string
	for _, rel := range rels {
		seen = append(seen, rel)
		f, ok := r.spec.Match(rel)
		switch {
		case !ok:
			unmapped = append(unmapped, rel)
		case f.Ignored != "":
			b.res.Skipped = append(b.res.Skipped, SkippedPath{Path: rel, Reason: f.Ignored})
		default:
			if err := r.readFile(rel, f.Path); err != nil {
				return nil, nil, err
			}
		}
	}
	for _, n := range outside {
		unmapped = append(unmapped, "(outside the recon directory) /"+n)
	}

	if err := r.assemble(); err != nil {
		return nil, nil, err
	}
	for _, rel := range r.nuclei {
		if err := r.readNuclei(rel); err != nil {
			return nil, nil, err
		}
	}
	r.stamp()

	if err := b.guard(); err != nil {
		return nil, nil, err
	}
	res := b.finish()
	res.Format = FormatReconFTW
	if len(unmapped) > 0 {
		if max := opts.Limits.MaxObservedPaths; len(unmapped) > max {
			b.issue(Issue{Message: fmt.Sprintf("more than %d files are not mapped; the unmapped list is incomplete", max)})
			unmapped = unmapped[:max]
		}
		res.Unmapped = append(res.Unmapped, unmapped...)
		sort.Strings(res.Unmapped)
	}
	sort.Slice(res.Skipped, func(i, j int) bool { return res.Skipped[i].Path < res.Skipped[j].Path })
	return res, append(seen, b.obs.paths()...), nil
}

// open returns the content of a bundle file within the file and total
// limits. At most MaxFilesRead files are opened.
func (r *bundleRun) open(rel string) (io.ReadCloser, error) {
	if r.filesRead >= r.bl.MaxFilesRead {
		return nil, errReadLimit
	}
	r.filesRead++
	rc, err := r.files[rel].Open()
	if err != nil {
		return nil, err
	}
	return &meterReader{rc: rc, run: r, name: rel}, nil
}

var errReadLimit = errors.New("read limit")

type meterReader struct {
	rc   io.ReadCloser
	run  *bundleRun
	name string
	read int64
}

func (m *meterReader) Read(p []byte) (int, error) {
	n, err := m.rc.Read(p)
	m.read += int64(n)
	m.run.total += int64(n)
	switch {
	case m.read > m.run.bl.MaxFileBytes:
		return n, &ParseError{Format: FormatReconFTW, Msg: fmt.Sprintf("file %q is larger than %d bytes", safeLabel(m.name), m.run.bl.MaxFileBytes), Err: ErrTooLarge}
	case m.run.total > m.run.bl.MaxTotalBytes:
		return n, &ParseError{Format: FormatReconFTW, Msg: fmt.Sprintf("the bundle is larger than %d bytes", m.run.bl.MaxTotalBytes), Err: ErrTooLarge}
	}
	return n, err
}

func (m *meterReader) Close() error { return m.rc.Close() }

// fatal reports whether an error of reading a file ends the whole bundle.
func fatal(err error) bool {
	return errors.Is(err, ErrTooLarge) || errors.Is(err, ErrUnsafe) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// problem records a non-fatal problem with a file, or returns the fatal one.
func (r *bundleRun) problem(rel string, err error) error {
	if fatal(err) {
		return err
	}
	if errors.Is(err, errReadLimit) {
		r.b.res.Skipped = append(r.b.res.Skipped, SkippedPath{Path: rel, Reason: fmt.Sprintf("not read: more than %d files are read per bundle", r.bl.MaxFilesRead)})
		return nil
	}
	r.b.res.Stats.Skipped++
	r.b.issue(Issue{Path: rel, Message: "file not read: " + line(err.Error(), 200)})
	return nil
}

var (
	versionRE = regexp.MustCompile(`(?i)reconftw\s+version\s*[:=]?\s*v?([0-9]+(?:\.[0-9]+){0,3}[0-9A-Za-z.+-]{0,16})`)
	ansiRE    = regexp.MustCompile("\x1b\\[[0-9;]*[A-Za-z]")
)

// readVersion reads the version line of the first logs (64 KiB each).
func (r *bundleRun) readVersion(rels []string) (string, error) {
	n := 0
	for _, rel := range rels {
		if !strings.HasPrefix(rel, "/.log/") || !strings.HasSuffix(rel, ".txt") {
			continue
		}
		if n++; n > 5 {
			break
		}
		rc, err := r.open(rel)
		if err != nil {
			if e := r.problem(rel, err); e != nil {
				return "", e
			}
			continue
		}
		head, err := io.ReadAll(io.LimitReader(rc, 64<<10))
		_ = rc.Close()
		if err != nil {
			if e := r.problem(rel, err); e != nil {
				return "", e
			}
			continue
		}
		if m := versionRE.FindSubmatch(ansiRE.ReplaceAll(head, nil)); m != nil {
			return string(m[1]), nil
		}
	}
	return "", nil
}

func versionMajor(v string) int {
	end := strings.IndexFunc(v, func(r rune) bool { return r < '0' || r > '9' })
	if end < 0 {
		end = len(v)
	}
	n, err := strconv.Atoi(v[:end])
	if err != nil {
		return 0
	}
	return n
}

// readReport reads report/report.json: the target, the mode and the time of
// the run. Counts in it are never used.
func (r *bundleRun) readReport() error {
	const rel = "/report/report.json"
	rc, err := r.open(rel)
	if err != nil {
		return r.problem(rel, err)
	}
	data, err := io.ReadAll(io.LimitReader(rc, 1<<20+1))
	_ = rc.Close()
	if err != nil {
		return r.problem(rel, err)
	}
	if len(data) > 1<<20 {
		return r.problem(rel, errors.New("larger than 1 MiB"))
	}
	obs := newObserver(r.b.lim.MaxObservedPaths)
	doc, err := scanJSON(bytes.TrimPrefix(data, utf8BOM), FormatReconFTW, r.b.lim, obs)
	if err != nil {
		return r.problem(rel, err)
	}
	for _, p := range obs.paths() {
		r.b.obs.add(rel + p)
	}
	var rep struct {
		Domain      string `json:"domain"`
		Mode        string `json:"mode"`
		GeneratedAt string `json:"generated_at"`
	}
	if err := doc.decode(&rep); err != nil {
		return r.problem(rel, err)
	}
	if d, ok := dnsName(rep.Domain); ok {
		r.domain = d
	}
	if m := line(rep.Mode, 32); m != "" {
		if r.b.res.Report.Properties == nil {
			r.b.res.Report.Properties = ctis.Properties{}
		}
		r.b.res.Report.Properties["reconftw_mode"] = m
	}
	if t := parseTime(rep.GeneratedAt); t != nil && t.Before(r.now) {
		r.b.res.Report.Metadata.Timestamp = *t
		r.now = *t
	}
	return nil
}

// readFile reads one mapped file with the reader its spec row names.
func (r *bundleRun) readFile(rel, rowPath string) error {
	var read func(rel string, rd io.Reader) error
	switch rowPath {
	case "/report/report.json", "/.log/*.txt":
		return nil // read first
	case "/nuclei_output/*_json.txt":
		r.nuclei = append(r.nuclei, rel)
		return nil
	case "/subdomains/subdomains.txt":
		read = r.readSubdomains
	case "/hosts/ips.txt":
		read = r.readIPs
	case "/hosts/cdn_providers.txt":
		read = r.readCDN
	case "/hosts/naabu*.txt":
		read = r.readNaabu
	case httpxFile:
		read = r.readHTTPX
	case "/webs/webs.txt", "/webs/webs_uncommon_ports.txt":
		read = r.readWebs
	case "/webs/webs_wafs.txt":
		read = r.readWAFs
	case "/webs/url_extract.txt", "/webs/urls_by_ext.txt", "/gf/*.txt":
		read = r.urlList("import", "")
	case "/js/js_livelinks.txt":
		read = r.urlList("js", "script")
	case "/js/js_endpoints.txt":
		read = r.urlList("js", "")
	case "/webs/takeover.txt":
		read = r.readTakeovers
	case "/subdomains/s3buckets.txt":
		read = r.readBuckets("storage_bucket")
	case "/subdomains/cloud_assets.txt":
		read = r.readBuckets("cloud_asset")
	default:
		return nil
	}
	rc, err := r.open(rel)
	if err != nil {
		return r.problem(rel, err)
	}
	defer func() { _ = rc.Close() }()
	if err := read(rel, rc); err != nil {
		return r.problem(rel, err)
	}
	return nil
}

// eachLine reads a list file line by line within the line limits. fn gets a
// clean line (no line end, trimmed, valid UTF-8, no control characters) and
// reports whether it used it. Lines that are too long, not clean text, or
// refused by fn are counted and reported in one issue.
func (r *bundleRun) eachLine(rel string, rd io.Reader, fn func(line string) bool) error {
	br := bufio.NewReaderSize(rd, r.bl.MaxLineBytes+2)
	var tooLong, unclean, refused, n int
	first := true
	for {
		chunk, err := br.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			tooLong++
			for errors.Is(err, bufio.ErrBufferFull) {
				_, err = br.ReadSlice('\n')
			}
			if err != nil && !errors.Is(err, io.EOF) {
				return err
			}
			if err == nil {
				continue
			}
			break
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		if first {
			chunk = bytes.TrimPrefix(chunk, utf8BOM)
			first = false
		}
		if n++; n > r.bl.MaxLines {
			r.b.issue(Issue{Path: rel, Message: fmt.Sprintf("more than %d lines: the rest of the file is not read", r.bl.MaxLines)})
			break
		}
		if e := r.b.tick(); e != nil {
			return e
		}
		raw := bytes.TrimSpace(bytes.TrimRight(chunk, "\r\n"))
		if len(raw) > 0 {
			switch {
			case !cleanLineBytes(raw):
				unclean++
			case !fn(string(raw)):
				refused++
			default:
				r.b.res.Stats.Records++
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
	}
	if tooLong+unclean+refused > 0 {
		r.b.res.Stats.Skipped += tooLong + unclean + refused
		r.b.issue(Issue{Path: rel, Message: fmt.Sprintf("%d lines skipped: %d longer than %d bytes, %d with invalid UTF-8 or control characters, %d not usable", tooLong+unclean+refused, tooLong, r.bl.MaxLineBytes, unclean, refused)})
	}
	return nil
}

// cleanLineBytes reports whether b is valid UTF-8 with no control character
// (tab excepted), so a NUL, a bare CR or an escape sequence never reaches a
// parser.
func cleanLineBytes(b []byte) bool {
	if !utf8.Valid(b) {
		return false
	}
	for _, c := range string(b) {
		if c == '\t' {
			continue
		}
		if unicode.IsControl(c) || unicode.Is(unicode.Bidi_Control, c) {
			return false
		}
	}
	return true
}

// dnsName returns the normalized form of a DNS name; an address, a wildcard,
// a URL or anything with a path, port or user info is refused.
func dnsName(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 253 || strings.ContainsAny(s, "/?#@ \t:[]\\*%") {
		return "", false
	}
	u, err := weburl.Parse("http://" + s)
	if err != nil || net.ParseIP(u.Host) != nil {
		return "", false
	}
	return u.Host, true
}

// hostOf returns the host of a URL or bare name or address.
func hostOf(tok string) (string, bool) {
	tok = strings.TrimRight(tok, ".,;")
	if strings.Contains(tok, "://") {
		u, err := weburl.Parse(tok)
		if err != nil {
			return "", false
		}
		return u.Host, true
	}
	if ip := net.ParseIP(tok); ip != nil {
		return ip.String(), true
	}
	return dnsName(tok)
}

func (r *bundleRun) readSubdomains(rel string, rd io.Reader) error {
	return r.eachLine(rel, rd, func(l string) bool {
		h, ok := dnsName(l)
		if !ok {
			return false
		}
		r.addSub(h)
		return true
	})
}

func (r *bundleRun) addSub(h string) {
	if r.subSeen[h] || len(r.subs) >= r.b.lim.MaxAssets {
		return
	}
	r.subSeen[h] = true
	s := ctis.SubdomainInput{Host: h, Source: "reconftw"}
	if r.domain != "" && (h == r.domain || strings.HasSuffix(h, "."+r.domain)) {
		s.Domain = r.domain
	}
	r.subs = append(r.subs, s)
}

func (r *bundleRun) readIPs(rel string, rd io.Reader) error {
	return r.eachLine(rel, rd, func(l string) bool {
		ip := net.ParseIP(l)
		if ip == nil {
			return false
		}
		if s := ip.String(); !r.ipSeen[s] && len(r.ips) < r.b.lim.MaxAssets {
			r.ipSeen[s] = true
			r.ips = append(r.ips, s)
		}
		return true
	})
}

// readCDN reads `<address> [cdn] [provider]` lines.
func (r *bundleRun) readCDN(rel string, rd io.Reader) error {
	return r.eachLine(rel, rd, func(l string) bool {
		f := strings.Fields(l)
		if len(f) == 0 {
			return false
		}
		ip := net.ParseIP(f[0])
		if ip == nil {
			return false
		}
		var info cdnInfo
		for _, w := range f[1:] {
			w = strings.Trim(w, "[]()")
			switch strings.ToLower(w) {
			case "cdn", "waf", "cloud":
				info.kind = strings.ToLower(w)
			default:
				if info.provider == "" {
					info.provider = boundText(w, 64)
				}
			}
		}
		if info.provider == "" {
			return false
		}
		r.cdn[ip.String()] = info
		return true
	})
}

func boundText(s string, n int) string { return line(s, n) }

// readNaabu reads `host:port` lines.
func (r *bundleRun) readNaabu(rel string, rd io.Reader) error {
	return r.eachLine(rel, rd, func(l string) bool {
		host, ps, err := net.SplitHostPort(l)
		if err != nil {
			return false
		}
		port, err := strconv.Atoi(ps)
		if err != nil || port < 1 || port > 65535 {
			return false
		}
		in := ctis.OpenPortInput{Port: port, Protocol: "tcp"}
		if ip := net.ParseIP(host); ip != nil {
			in.IP = ip.String()
		} else if h, ok := dnsName(host); ok {
			in.Host = h
		} else {
			return false
		}
		if len(r.ports) < r.b.lim.MaxAssets {
			r.ports = append(r.ports, in)
		}
		return true
	})
}

func (r *bundleRun) readHTTPX(rel string, rd io.Reader) error {
	return r.eachLine(rel, rd, func(l string) bool {
		h, err := ctis.ParseHTTPXLine([]byte(l), func(p string) { r.b.obs.add(rel + p) })
		if err != nil {
			return false
		}
		if !r.liveSeen[h.URL] && len(r.live) < r.b.lim.MaxAssets {
			r.liveSeen[h.URL] = true
			r.live = append(r.live, h)
		}
		return true
	})
}

// liveFromURL is the minimal live host of a URL list line.
func liveFromURL(raw string) (ctis.LiveHostInput, bool) {
	u, err := weburl.Parse(raw)
	if err != nil {
		return ctis.LiveHostInput{}, false
	}
	h := ctis.LiveHostInput{URL: u.Origin(), Host: u.Host, Scheme: u.Scheme, Port: 80}
	if u.Scheme == "https" {
		h.Port = 443
	}
	if u.Port != "" {
		h.Port, _ = strconv.Atoi(u.Port)
	}
	return h, true
}

func (r *bundleRun) readWebs(rel string, rd io.Reader) error {
	return r.eachLine(rel, rd, func(l string) bool {
		h, ok := liveFromURL(l)
		if !ok {
			return false
		}
		if len(r.plain) < r.b.lim.MaxAssets {
			r.plain = append(r.plain, h)
		}
		return true
	})
}

var wafRE = regexp.MustCompile(`^(?:The site\s+)?(https?://\S+)\s+is behind\s+(.+?)(?:\s+WAF)?\.?$`)

func (r *bundleRun) readWAFs(rel string, rd io.Reader) error {
	return r.eachLine(rel, rd, func(l string) bool {
		m := wafRE.FindStringSubmatch(l)
		if m == nil {
			return false
		}
		h, ok := liveFromURL(m[1])
		if !ok {
			return false
		}
		name := m[2]
		if i := strings.Index(name, " ("); i > 0 {
			name = name[:i]
		}
		if name = boundText(name, 64); name == "" {
			return false
		}
		if len(r.wafs) < r.b.lim.MaxAssets {
			r.wafs[h.URL] = name
		}
		return true
	})
}

// urlList reads a file of URLs, one per line, as endpoints.
func (r *bundleRun) urlList(source, typ string) func(string, io.Reader) error {
	return func(rel string, rd io.Reader) error {
		return r.eachLine(rel, rd, func(l string) bool {
			if _, err := weburl.Parse(l); err != nil {
				return false
			}
			if len(r.urls) < 5*r.b.lim.MaxEndpoints {
				r.urls = append(r.urls, ctis.DiscoveredURLInput{URL: l, Source: source, Type: typ})
			}
			return true
		})
	}
}

var labelRE = regexp.MustCompile(`^[A-Za-z0-9 ._:/-]{1,64}$`)

// candidateLine reads a line that names a host and, in brackets, what was
// found there: the first bracketed word is the label.
func candidateLine(l string) (host, label string, ok bool) {
	for _, f := range strings.Fields(l) {
		if strings.HasPrefix(f, "[") && strings.HasSuffix(f, "]") {
			if w := strings.Trim(f, "[]"); label == "" && labelRE.MatchString(w) {
				label = w
			}
			continue
		}
		if host == "" {
			if h, hok := hostOf(f); hok {
				host = h
			}
		}
	}
	return host, label, host != ""
}

func (r *bundleRun) readTakeovers(rel string, rd io.Reader) error {
	return r.eachLine(rel, rd, func(l string) bool {
		h, label, ok := candidateLine(l)
		if !ok || net.ParseIP(h) != nil {
			return false
		}
		r.addSub(h)
		if _, dup := r.takeover[h]; !dup && len(r.takeover) < r.b.lim.MaxAssets {
			r.takeover[h] = label
		}
		return true
	})
}

func (r *bundleRun) readBuckets(kind string) func(string, io.Reader) error {
	return func(rel string, rd io.Reader) error {
		return r.eachLine(rel, rd, func(l string) bool {
			h, label, ok := candidateLine(l)
			if !ok || net.ParseIP(h) != nil {
				return false
			}
			if len(r.buckets) < r.b.lim.MaxAssets {
				r.buckets = append(r.buckets, bucketCand{host: h, kind: kind, provider: storageProvider(h), label: label})
			}
			return true
		})
	}
}

func storageProvider(host string) string {
	switch {
	case strings.HasSuffix(host, ".amazonaws.com"):
		return "aws_s3"
	case strings.HasSuffix(host, ".blob.core.windows.net"):
		return "azure_blob"
	case host == "storage.googleapis.com" || strings.HasSuffix(host, ".storage.googleapis.com"):
		return "gcs"
	case strings.HasSuffix(host, ".digitaloceanspaces.com"):
		return "do_spaces"
	}
	return "unknown"
}

var idCleanRE = regexp.MustCompile(`[^a-z0-9]+`)

// newID returns an asset id unused in the report.
func (r *bundleRun) newID(prefix, value string) string {
	base := prefix + "-" + strings.Trim(idCleanRE.ReplaceAllString(strings.ToLower(value), "-"), "-")
	if len(base) > 100 {
		base = base[:100]
	}
	id := base
	for i := 2; r.b.assetExists(id); i++ {
		id = base + "-" + strconv.Itoa(i)
	}
	return id
}

func (b *builder) assetExists(id string) bool {
	_, ok := b.assets[id]
	return ok
}

// assemble turns what the files held into assets and endpoints.
func (r *bundleRun) assemble() error {
	b := r.b
	// A URL the plain lists name that httpx did not probe is a bare service.
	live := r.live
	for _, h := range r.plain {
		if !r.liveSeen[h.URL] {
			r.liveSeen[h.URL] = true
			live = append(live, h)
		}
	}
	for u := range r.wafs {
		if !r.liveSeen[u] {
			r.liveSeen[u] = true
			h, _ := liveFromURL(u)
			live = append(live, h)
		}
	}
	rep, err := ctis.ConvertReconToCTIS(&ctis.ReconToCTISInput{
		ScannerName: "reconftw", ScannerVersion: b.res.Report.Tool.Version, Target: r.domain,
		Subdomains: r.subs, OpenPorts: r.ports, LiveHosts: live,
	}, &ctis.ReconConverterOptions{
		DiscoverySource: "import:reconftw", DiscoveryTool: "reconftw",
		DefaultConfidence: 60, GroupByDomain: true, GroupByIP: true,
	})
	if err != nil {
		return &ParseError{Format: b.format, Msg: "convert: " + err.Error(), Err: ErrMalformed}
	}
	for _, a := range rep.Assets {
		if _, err := b.asset(a); err != nil {
			return err
		}
	}
	rp := &b.res.Report.Assets
	find := func(t ...ctis.AssetType) func(string) int {
		return func(v string) int {
			for i := range *rp {
				for _, tt := range t {
					if (*rp)[i].Type == tt && (*rp)[i].Value == v {
						return i
					}
				}
			}
			return -1
		}
	}
	findIP, findHost, findSvc := find(ctis.AssetTypeIPAddress), find(ctis.AssetTypeDomain, ctis.AssetTypeSubdomain), find(ctis.AssetTypeHTTPService)
	base := func(prefix, value string, t ctis.AssetType) ctis.Asset {
		return ctis.Asset{
			ID: r.newID(prefix, value), Type: t, Value: value, Name: value, Confidence: 60,
			Properties: ctis.Properties{"discovery_source": "import:reconftw", "discovery_tool": "reconftw"},
		}
	}
	for _, ip := range r.ips {
		if findIP(ip) >= 0 {
			continue
		}
		a := base("import-ip", ip, ctis.AssetTypeIPAddress)
		ver := 4
		if strings.Contains(ip, ":") {
			ver = 6
		}
		a.Technical = &ctis.AssetTechnical{IPAddress: &ctis.IPAddressTechnical{Version: ver}}
		if _, err := b.asset(a); err != nil {
			return err
		}
	}
	for ip, c := range r.cdn {
		i := findIP(ip)
		if i < 0 {
			a := base("import-ip", ip, ctis.AssetTypeIPAddress)
			if _, err := b.asset(a); err != nil {
				return err
			}
			i = findIP(ip)
		}
		p := (*rp)[i].Properties
		if p == nil {
			p = ctis.Properties{}
			(*rp)[i].Properties = p
		}
		p["cdn"], p["hosted_by"] = c.provider, c.provider
		if c.kind != "" {
			p["cdn_type"] = c.kind
		}
	}
	for host, label := range r.takeover {
		if i := findHost(host); i >= 0 {
			p := (*rp)[i].Properties
			p["candidate_exposure"] = "subdomain_takeover"
			p["candidate_unverified"] = true
			if label != "" {
				p["candidate_detail"] = label
			}
		}
	}
	for _, c := range r.buckets {
		if findStorage(*rp, c.host) >= 0 {
			continue
		}
		a := base("import-storage", c.host, ctis.AssetTypeStorage)
		a.Properties["candidate_exposure"] = c.kind
		a.Properties["candidate_unverified"] = true
		a.Properties["storage_provider"] = c.provider
		if c.label != "" {
			a.Properties["candidate_detail"] = c.label
		}
		if _, err := b.asset(a); err != nil {
			return err
		}
	}
	for u, name := range r.wafs {
		if i := findSvc(u); i >= 0 {
			(*rp)[i].Properties["waf"] = name
		}
	}

	// Endpoints.
	origins := map[string]string{}
	for _, a := range *rp {
		if a.Type == ctis.AssetTypeHTTPService {
			if u, err := weburl.Parse(a.Value); err == nil {
				if _, ok := origins[u.Origin()]; !ok {
					origins[u.Origin()] = a.ID
				}
			}
		}
	}
	eps := ctis.ConvertEndpoints(r.urls)
	if len(eps) > b.lim.MaxEndpoints {
		b.issue(Issue{Message: fmt.Sprintf("more than %d endpoints: the rest are left out", b.lim.MaxEndpoints)})
		eps = eps[:b.lim.MaxEndpoints]
	}
	for i := range eps {
		eps[i].OriginRef = origins[eps[i].Origin]
		// An address in a path is personal data: the template stands for
		// it ({email}) and the concrete path is not kept.
		if strings.Contains(eps[i].Template, "{email}") {
			eps[i].Path = eps[i].Template
		}
	}
	b.res.Report.Endpoints = eps
	return nil
}

func findStorage(as []ctis.Asset, v string) int {
	for i := range as {
		if as[i].Type == ctis.AssetTypeStorage && as[i].Value == v {
			return i
		}
	}
	return -1
}

// readNuclei reads a nuclei result file with the nuclei importer and files
// each finding on the bundle's asset of the same host.
func (r *bundleRun) readNuclei(rel string) error {
	b := r.b
	rc, err := r.open(rel)
	if err != nil {
		return r.problem(rel, err)
	}
	defer func() { _ = rc.Close() }()
	sub, paths, err := parse(r.ctx, rc, Options{Format: FormatNuclei, Limits: b.lim, Now: r.now})
	if err != nil {
		return r.problem(rel, err)
	}
	for _, p := range specs[FormatNuclei].Unmapped(paths) {
		b.obs.add(rel + p)
	}
	b.res.Stats.Records += sub.Stats.Records
	b.res.Stats.Skipped += sub.Stats.Skipped
	for _, is := range sub.Issues {
		is.Path = rel + " " + is.Path
		b.issue(is)
	}
	byOld := map[string]string{}
	for _, a := range sub.Report.Assets {
		oldID, id := a.ID, ""
		for _, e := range b.res.Report.Assets {
			if e.Value == a.Value && (e.Type == a.Type || (a.Type == ctis.AssetTypeDomain && e.Type == ctis.AssetTypeSubdomain)) {
				id = e.ID
				break
			}
		}
		if id == "" {
			a.ID = r.newID("import-host", a.Value)
			if a.Properties == nil {
				a.Properties = ctis.Properties{}
			}
			a.Properties["discovery_source"], a.Properties["discovery_tool"] = "import:reconftw", "reconftw"
			if _, err := b.asset(a); err != nil {
				return err
			}
			id = a.ID
		}
		byOld[oldID] = id
	}
	for _, f := range sub.Report.Findings {
		f.AssetRef = byOld[f.AssetRef]
		if f.Native != nil && f.Native.RawRef != "" {
			f.Native.RawRef = rel + " " + f.Native.RawRef
		}
		if err := b.finding(f); err != nil {
			return err
		}
	}
	return nil
}

// stamp marks every host asset with its scope and gives every asset the
// time of the run.
func (r *bundleRun) stamp() {
	for i := range r.b.res.Report.Assets {
		a := &r.b.res.Report.Assets[i]
		if a.DiscoveredAt == nil || a.DiscoveredAt.After(r.now) {
			t := r.now
			a.DiscoveredAt = &t
		}
		if a.Type == ctis.AssetTypeCertificate {
			continue
		}
		host := a.Value
		if a.Type == ctis.AssetTypeHTTPService {
			if u, err := weburl.Parse(a.Value); err == nil {
				host = u.Host
			}
		}
		if a.Properties == nil {
			a.Properties = ctis.Properties{}
		}
		a.Properties["import_scope"] = r.scopeOf(host)
	}
}

func (r *bundleRun) scopeOf(host string) string {
	if len(r.scope) == 0 || net.ParseIP(host) != nil {
		return "unknown"
	}
	for _, d := range r.scope {
		if d != "" && (host == d || strings.HasSuffix(host, "."+d)) {
			return "in_target"
		}
	}
	return "outside_target"
}
