package ctis

import (
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Data flow normalization: the bounds, paths and redaction every producer's
// taint trace gets before it leaves a converter.
//
// A trace is tool output about the scanned code, read from a file the
// receiver does not trust: it can be huge, can name files by the absolute
// path of the machine that ran the scan (a CI runner's home and work
// directory), and its snippets are lines of source code, which can hold a
// hard-coded credential the finding is not about. NormalizeDataFlow keeps a
// bounded number of steps with bounded text, paths relative to the
// repository, and credentials in snippets and labels masked.

// Bounds on one data flow.
const (
	// MaxDataFlowSteps is the most locations a data flow keeps, over its
	// sources, intermediates, sanitizers and sinks together.
	MaxDataFlowSteps = 100
	// MaxDataFlowContentLen is the longest snippet of a step, in characters.
	MaxDataFlowContentLen = 2048
	// MaxDataFlowPathLen is the longest file path of a step, in characters.
	// A longer path is dropped, not cut, so no path is invented.
	MaxDataFlowPathLen = 1024
	// MaxDataFlowLabelLen is the longest label, function, class, module or
	// note of a step, in characters.
	MaxDataFlowLabelLen = 255
	// maxDataFlowLine is the largest line or column number kept; larger
	// values do not fit a 32-bit column and are dropped.
	maxDataFlowLine = 1<<31 - 1
)

// NormalizeDataFlow bounds, cleans and redacts df in place and returns it,
// or nil when no location is left.
//
//   - At most MaxDataFlowSteps locations are kept, in step order; the step
//     indexes are renumbered 0..n-1 in that order.
//   - Text is cut at the limits above; control characters other than tab,
//     newline and carriage return are removed.
//   - Paths become repository-relative POSIX paths: a file URI or an
//     absolute path is made relative to the first of roots it lies under,
//     else to the root a relative path elsewhere in the flow reveals (an
//     absolute path ending in that relative path), else it is dropped. A
//     path that leaves the repository ("../"), a non-file URI or an
//     over-long path is dropped. The location itself is kept: its line and
//     snippet still say what the step is.
//   - Snippets, labels and notes have credentials masked (RedactCodeSecrets).
//   - Tainted is true when the flow has both a source and a sink.
func NormalizeDataFlow(df *DataFlow, roots ...string) *DataFlow {
	if df == nil {
		return nil
	}
	type slot struct {
		loc *DataFlowLocation
		dst *[]DataFlowLocation
	}
	// Step order: the producers' indexes, then the list order.
	var all []slot
	for _, l := range []*[]DataFlowLocation{&df.Sources, &df.Intermediates, &df.Sanitizers, &df.Sinks} {
		for i := range *l {
			all = append(all, slot{&(*l)[i], l})
		}
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].loc.Index < all[j].loc.Index })
	if len(all) > MaxDataFlowSteps {
		all = all[:MaxDataFlowSteps]
	}

	cleanRoots := make([]string, 0, len(roots))
	for _, r := range roots {
		if p, abs := flowPath(r); abs && p != "" {
			cleanRoots = append(cleanRoots, strings.TrimSuffix(p, "/")+"/")
		}
	}
	var rel []string
	for _, s := range all {
		if p, abs := flowPath(s.loc.Path); !abs && p != "" {
			rel = append(rel, p)
		}
	}

	out := map[*[]DataFlowLocation][]DataFlowLocation{}
	for i, s := range all {
		l := *s.loc
		l.Index = i
		l.Path = repoRelative(l.Path, cleanRoots, rel)
		l.Line, l.EndLine = flowNum(l.Line), flowNum(l.EndLine)
		l.Column, l.EndColumn = flowNum(l.Column), flowNum(l.EndColumn)
		l.ParameterIndex = flowNum(l.ParameterIndex)
		l.Content = RedactCodeSecrets(flowText(l.Content, MaxDataFlowContentLen))
		l.Label = RedactCodeSecrets(flowLine(l.Label, MaxDataFlowLabelLen))
		l.Notes = RedactCodeSecrets(flowText(l.Notes, MaxDataFlowLabelLen))
		l.Function = flowLine(l.Function, MaxDataFlowLabelLen)
		l.Class = flowLine(l.Class, MaxDataFlowLabelLen)
		l.Module = flowLine(l.Module, MaxDataFlowLabelLen)
		l.CalledFunction = flowLine(l.CalledFunction, MaxDataFlowLabelLen)
		l.Operation = flowLine(l.Operation, MaxDataFlowLabelLen)
		l.TaintState = flowLine(l.TaintState, MaxDataFlowLabelLen)
		l.Transformation = flowLine(l.Transformation, MaxDataFlowLabelLen)
		out[s.dst] = append(out[s.dst], l)
	}
	df.Sources, df.Intermediates = out[&df.Sources], out[&df.Intermediates]
	df.Sanitizers, df.Sinks = out[&df.Sanitizers], out[&df.Sinks]
	if len(all) == 0 {
		return nil
	}
	if len(df.CallPath) > MaxDataFlowSteps {
		df.CallPath = df.CallPath[:MaxDataFlowSteps]
	}
	for i := range df.CallPath {
		df.CallPath[i] = flowLine(df.CallPath[i], MaxDataFlowLabelLen)
	}
	df.Summary = RedactCodeSecrets(flowText(df.Summary, MaxDataFlowContentLen))
	df.TaintType = flowLine(df.TaintType, MaxDataFlowLabelLen)
	df.VulnerabilityType = flowLine(df.VulnerabilityType, MaxDataFlowLabelLen)
	if df.Confidence < 0 || df.Confidence > 100 {
		df.Confidence = 0
	}
	df.Tainted = len(df.Sources) > 0 && len(df.Sinks) > 0
	df.CrossFile = false
	first := ""
	for _, l := range df.GetFullPath() {
		if l.Path == "" {
			continue
		}
		if first == "" {
			first = l.Path
		} else if l.Path != first {
			df.CrossFile = true
		}
	}
	return df
}

func flowNum(n int) int {
	if n < 0 || n > maxDataFlowLine {
		return 0
	}
	return n
}

// flowText removes control characters other than tab, newline and carriage
// return, trims the ends and cuts at limit characters.
func flowText(s string, limit int) string {
	s = strings.TrimSpace(strings.Map(func(r rune) rune {
		if r == '\t' || r == '\n' || r == '\r' {
			return r
		}
		if unicode.IsControl(r) || r == utf8.RuneError {
			return -1
		}
		return r
	}, s))
	if utf8.RuneCountInString(s) <= limit {
		return s
	}
	return string([]rune(s)[:limit])
}

// flowLine is flowText on one line: white space runs become one space.
func flowLine(s string, limit int) string {
	return flowText(strings.Join(strings.Fields(s), " "), limit)
}

// flowPath cleans a path or file URI to a POSIX path and says whether it is
// absolute. It returns "" for a value that is no file path: another URI
// scheme, an empty value, a path with control characters.
func flowPath(p string) (string, bool) {
	p = strings.TrimSpace(p)
	if p == "" || strings.IndexFunc(p, unicode.IsControl) >= 0 {
		return "", false
	}
	if i := strings.Index(p, ":"); i > 1 && !strings.ContainsAny(p[:i], `/\`) {
		scheme := strings.ToLower(p[:i])
		if scheme != "file" {
			return "", false
		}
		u, err := url.Parse(p)
		if err != nil {
			return "", false
		}
		p = u.Path
		if p == "" {
			p = u.Opaque
		}
		if !strings.HasPrefix(p, "/") {
			// file:relative/path is relative to the base the producer
			// named.
			return cleanRel(p)
		}
	} else if dec, err := url.PathUnescape(p); err == nil {
		// SARIF artifact URIs are percent-encoded ("my%20file.js").
		p = dec
	}
	p = strings.ReplaceAll(p, `\`, "/")
	// A Windows drive path, "/C:/..." from a file URI or "C:/..." bare.
	if len(p) >= 3 && p[0] == '/' && isDriveLetter(p[1]) && p[2] == ':' {
		p = p[3:]
	} else if len(p) >= 2 && isDriveLetter(p[0]) && p[1] == ':' {
		p = "/" + strings.TrimPrefix(p[2:], "/")
	}
	if strings.HasPrefix(p, "/") {
		return path.Clean(p), true
	}
	return cleanRel(p)
}

func cleanRel(p string) (string, bool) {
	p = path.Clean(strings.ReplaceAll(p, `\`, "/"))
	if p == "." || p == ".." || strings.HasPrefix(p, "../") || strings.HasPrefix(p, "/") {
		return "", false
	}
	return p, false
}

func isDriveLetter(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

// repoRelative returns p relative to the repository, or "".
func repoRelative(p string, roots, rel []string) string {
	c, abs := flowPath(p)
	if c == "" {
		return ""
	}
	if abs {
		c = stripRoot(c, roots, rel)
	}
	if c == "" || utf8.RuneCountInString(c) > MaxDataFlowPathLen {
		return ""
	}
	return c
}

func stripRoot(p string, roots, rel []string) string {
	for _, r := range roots {
		if strings.HasPrefix(p, r) {
			c, _ := cleanRel(p[len(r):])
			return c
		}
	}
	// A relative path of the same flow names the repository part: the root
	// is what precedes it. The longest match wins.
	best := ""
	for _, r := range rel {
		if len(r) > len(best) && strings.HasSuffix(p, "/"+r) {
			best = r
		}
	}
	return best
}

// Credentials in code. A snippet of a taint step is a line of the scanned
// source: a connection string or a hard-coded key on that line is not what
// the finding is about and must not be stored with it.
var (
	// A value assigned to, or keyed by, a credential name: password = "...",
	// "apiKey": "...", token: '...'. The value is the quoted literal.
	reCodeSecretKV = regexp.MustCompile("(?i)((?:pass(?:word|wd|phrase)?|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|auth[_-]?key|credentials?)\\w*[\"'`]?\\s*(?::=|=>|[:=])\\s*)([\"'`])([^\"'`\\r\\n]{4,})([\"'`])")
	// User info in a URL: scheme://user:password@host.
	reCodeURLCreds = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://[^\s:/@"'` + "`" + `]*:)([^\s/@"'` + "`" + `]+)(@)`)
	// Credentials recognisable by their form alone.
	reCodeTokens  = regexp.MustCompile(`\b(?:AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|glpat-[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|sk_live_[A-Za-z0-9]{16,}|rk_live_[A-Za-z0-9]{16,}|AIza[0-9A-Za-z_-]{35}|eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})`)
	reCodePrivKey = regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)`)
)

// RedactCodeSecrets masks the credentials in a line or a block of source
// code: a quoted value assigned to a credential name (password, secret,
// token, api key, access key, private key, client secret, credentials), the
// password of a URL's user info, tokens of a recognisable form (cloud
// access keys, repository and chat tokens, payment keys, JSON web tokens)
// and private key blocks. Masks use MaskSecretMatch. Values already masked
// (asterisks, REDACTED) and placeholders are kept. Everything else in the
// code is left as it is: a taint step's code is what the reader needs.
func RedactCodeSecrets(s string) string {
	if s == "" {
		return s
	}
	s = reCodePrivKey.ReplaceAllString(s, "-----BEGIN PRIVATE KEY-----"+redactedSecret+"-----END PRIVATE KEY-----")
	s = reCodeURLCreds.ReplaceAllStringFunc(s, func(m string) string {
		g := reCodeURLCreds.FindStringSubmatch(m)
		if isMasked(g[2]) || isPlaceholder(g[2]) {
			return m
		}
		return g[1] + maskSecret(g[2]) + g[3]
	})
	s = reCodeSecretKV.ReplaceAllStringFunc(s, func(m string) string {
		g := reCodeSecretKV.FindStringSubmatch(m)
		if g[2] != g[4] || isMasked(g[3]) || isPlaceholder(g[3]) {
			return m
		}
		return g[1] + g[2] + maskSecret(g[3]) + g[4]
	})
	return reCodeTokens.ReplaceAllStringFunc(s, func(m string) string {
		if isMasked(m) {
			return m
		}
		return maskSecret(m)
	})
}

// isPlaceholder reports a value that names where a secret comes from rather
// than holding one: an interpolation or a reference ("${DB_PASSWORD}",
// "{{ .Token }}", "%s", "<password>", "env:API_KEY").
func isPlaceholder(v string) bool {
	t := strings.TrimSpace(v)
	switch {
	case strings.HasPrefix(t, "${"), strings.HasPrefix(t, "{{"), strings.HasPrefix(t, "%"),
		strings.HasPrefix(t, "<") && strings.HasSuffix(t, ">"), strings.HasPrefix(strings.ToLower(t), "env:"):
		return true
	}
	return false
}
