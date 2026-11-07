package importer

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/openctemio/ctis/v2"
)

// What a credentialed Nessus scan reports about the inside of a host: the
// application CPEs of HostProperties, the installed packages of the software
// enumeration plugins, the listening sockets of netstat and the SSH host key.
// The mapping is spec_nessus.go; docs/importers/nessus.md explains it.

// Bounds on what one host contributes. Larger inputs are cut with an issue,
// never refused: the findings of the file matter more than its inventory.
const (
	// Most installed packages kept per host from the enumeration plugins.
	nessusMaxPackagesPerHost = 10_000
	// Most listening sockets kept per host from the netstat tags.
	nessusMaxListenersPerHost = 1024
	// Most SSH host keys kept per host.
	nessusMaxSSHKeys = 8
	// Longest package line read; longer lines are not a package.
	nessusMaxPackageLine = 1024
	// Longest package name and version kept.
	nessusMaxPackageName    = 256
	nessusMaxPackageVersion = 128
)

// The software enumeration plugins whose output lists installed packages,
// by plugin id. The plugin name is checked too, so a renumbered plugin of the
// same name is still read.
const (
	// Software Enumeration (SSH): dpkg, rpm or apk package list of a Unix host.
	nessusPluginSSHSoftware = "22869"
	// Microsoft Windows Installed Software Enumeration (credentialed check).
	nessusPluginWindowsSoftware = "20811"
)

func nessusInventoryKind(it *nessusItem) string {
	name := strings.ToLower(strings.TrimSpace(it.PluginName))
	switch {
	case strings.TrimSpace(it.PluginID) == nessusPluginSSHSoftware || name == "software enumeration (ssh)":
		return "ssh"
	case strings.TrimSpace(it.PluginID) == nessusPluginWindowsSoftware || strings.HasPrefix(name, "microsoft windows installed software enumeration"):
		return "windows"
	}
	return ""
}

// nessusCPETag is one cpe-N host property: "cpe:/a:vendor:product:version ->
// Display Name". x-cpe values are the scanner's own names outside the CPE
// dictionary.
type nessusCPETag struct {
	cpe     string // CPE 2.3, canonical; "" for an x-cpe value
	part    string // a, o or h
	vendor  string
	product string
	version string
	label   string // the display name after "->"
}

func parseNessusCPETag(v string) (nessusCPETag, bool) {
	v = strings.TrimSpace(v)
	raw, label, _ := strings.Cut(v, "->")
	raw, label = strings.TrimSpace(raw), line(label, ctis.MaxTechnologyNameLen)
	var t nessusCPETag
	t.label = label
	lower := strings.ToLower(raw)
	if rest, ok := strings.CutPrefix(lower, "x-"); ok {
		// x-cpe:/a:vendor:product:version: not a dictionary CPE; the
		// product is kept by name.
		lower = rest
	} else {
		c, err := ctis.CanonicalCPE(raw)
		if err != nil || len(c) > ctis.MaxTechnologyCPELen {
			return t, false
		}
		t.cpe = c
		lower = c
	}
	parts := splitCPEParts(lower)
	if len(parts) < 4 {
		return t, false
	}
	t.part, t.vendor, t.product = parts[0], parts[1], parts[2]
	if len(parts) > 3 && parts[3] != "*" && parts[3] != "-" {
		t.version = parts[3]
	}
	if t.product == "" || t.product == "*" {
		return t, false
	}
	return t, true
}

// splitCPEParts returns part, vendor, product, version, ... of a CPE 2.3
// formatted string or a CPE 2.2 URI.
func splitCPEParts(s string) []string {
	if rest, ok := strings.CutPrefix(s, "cpe:2.3:"); ok {
		return strings.Split(rest, ":")
	}
	if rest, ok := strings.CutPrefix(s, "cpe:/"); ok {
		return strings.Split(rest, ":")
	}
	return nil
}

// nessusCPETechnologies returns the technologies of the cpe-N host
// properties, distinct by CPE (or by name and version for x-cpe values), in
// the order of N. The operating system CPE goes to the operating-system
// technology the caller already has (os, when not nil).
func nessusCPETechnologies(tags []nessusTag, os *ctis.Technology) []ctis.Technology {
	type numbered struct {
		n int
		v string
	}
	var vals []numbered
	for _, t := range tags {
		name := strings.TrimSpace(t.Name)
		if name == "cpe" {
			vals = append(vals, numbered{-1, t.Value})
			continue
		}
		if rest, ok := strings.CutPrefix(name, "cpe-"); ok {
			if n, err := strconv.Atoi(rest); err == nil && n >= 0 {
				vals = append(vals, numbered{n, t.Value})
			}
		}
	}
	sort.SliceStable(vals, func(i, j int) bool { return vals[i].n < vals[j].n })
	seen := map[string]bool{}
	var out []ctis.Technology
	for _, nv := range vals {
		c, ok := parseNessusCPETag(nv.v)
		if !ok {
			continue
		}
		if c.part == "o" {
			if os != nil && os.CPE == "" && c.cpe != "" {
				os.CPE = c.cpe
				if os.Version == "" && c.version != "" {
					os.Version = line(c.version, ctis.MaxTechnologyVerLen)
				}
			}
			continue
		}
		name := c.label
		if name == "" {
			name = line(strings.ReplaceAll(c.product, "_", " "), ctis.MaxTechnologyNameLen)
		}
		ver := line(cpeUnescape(c.version), ctis.MaxTechnologyVerLen)
		// The display name often ends with the version; the version is
		// its own member.
		if ver != "" {
			name = strings.TrimSpace(strings.TrimSuffix(name, " "+ver))
		}
		key := c.cpe
		if key == "" {
			key = "x\x1f" + strings.ToLower(name) + "\x1f" + ver
		}
		if seen[key] || name == "" {
			continue
		}
		seen[key] = true
		cat := "application"
		if c.part == "h" {
			cat = "hardware"
		}
		out = append(out, ctis.Technology{Name: name, Version: ver, CPE: c.cpe, Categories: []string{cat}})
	}
	return out
}

// cpeUnescape removes the backslash escapes of a CPE 2.3 component.
func cpeUnescape(s string) string { return strings.ReplaceAll(s, `\`, "") }

// nessusSSHFingerprints reads the ssh-fingerprint host property: one key per
// line, "<key type> <fingerprint>", where the fingerprint is an MD5 colon-hex
// string, a SHA256:<base64> string or the base64 public key itself (then the
// SHA-256 fingerprint is computed). Returns "<key type> <fingerprint>"
// entries, distinct, sorted, at most nessusMaxSSHKeys.
func nessusSSHFingerprints(v string) []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range strings.Split(v, "\n") {
		f := strings.Fields(l)
		if len(f) < 2 {
			continue
		}
		typ, fp := strings.ToLower(f[0]), f[1]
		if !reSSHKeyType.MatchString(typ) {
			continue
		}
		switch {
		case reMD5Fingerprint.MatchString(fp):
			fp = "MD5:" + strings.ToLower(fp)
		case strings.HasPrefix(fp, "SHA256:") && reB64.MatchString(strings.TrimPrefix(fp, "SHA256:")) && len(fp) <= 64:
		case strings.HasPrefix(fp, "AAAA") && len(fp) <= 16<<10:
			blob, err := base64.StdEncoding.DecodeString(fp)
			if err != nil || len(blob) < 16 {
				continue
			}
			sum := sha256.Sum256(blob)
			fp = "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
		default:
			continue
		}
		e := typ + " " + fp
		if !seen[e] {
			seen[e] = true
			out = append(out, e)
		}
	}
	sort.Strings(out)
	if len(out) > nessusMaxSSHKeys {
		out = out[:nessusMaxSSHKeys]
	}
	return out
}

var (
	reSSHKeyType     = regexp.MustCompile(`^(ssh-(rsa|dss|ed25519|ed448)|ecdsa-sha2-nistp(256|384|521)|sk-[a-z0-9@.-]+)$`)
	reMD5Fingerprint = regexp.MustCompile(`^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){15}$`)
	reB64            = regexp.MustCompile(`^[A-Za-z0-9+/]+=*$`)
)

// nessusListener is one listening socket of a netstat-listen-* host property.
type nessusListener struct {
	port      int
	transport ctis.Transport
	bind      string // the bind address; "" for every interface
	process   string
}

// reNetstatTag names the listening sockets: netstat-listen-tcp4-0,
// netstat-listen-udp6-3. netstat-established-* are connections to peers and
// are not read.
var reNetstatTag = regexp.MustCompile(`^netstat-listen-(tcp|udp)(4|6)-[0-9]+$`)

// parseNessusListener reads "addr:port" or "[addr]:port", optionally followed
// by the process ("0.0.0.0:22 sshd", "[::]:443 (1234/nginx)"). loopback is
// true for a socket bound to a loopback address only.
func parseNessusListener(name, v string) (l nessusListener, loopback, ok bool) {
	m := reNetstatTag.FindStringSubmatch(strings.TrimSpace(name))
	if m == nil {
		return l, false, false
	}
	l.transport = ctis.Transport(m[1])
	fields := strings.Fields(v)
	if len(fields) == 0 {
		return l, false, false
	}
	hostPort := fields[0]
	host, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		return l, false, false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return l, false, false
	}
	l.port = port
	host = strings.TrimSpace(host)
	switch host {
	case "", "*", "0.0.0.0", "::", "0:0:0:0:0:0:0:0":
		l.bind = ""
	default:
		h, _, _ := strings.Cut(host, "%") // zone
		ip := net.ParseIP(h)
		if ip == nil {
			return l, false, false
		}
		if ip.IsLoopback() {
			return l, true, true
		}
		l.bind = ip.String()
	}
	if len(fields) > 1 {
		p := strings.Trim(strings.Join(fields[1:], " "), "()")
		if _, name, ok := strings.Cut(p, "/"); ok {
			p = name
		}
		l.process = line(p, 128)
	}
	return l, false, true
}

// nessusLocalServices adds the listening sockets of the netstat tags as
// services of the host, marked as observed from inside the host
// (observed_from host); a socket the scanner also reached is observed_from
// network. Loopback-only sockets are counted and skipped: nothing off the
// host can reach them, so they are not attack surface of the host.
func (b *Builder) nessusLocalServices(tags []nessusTag, hostID string, reached map[string]bool, lineNo int) {
	kept, loopback := 0, 0
	seen := map[string]bool{}
	for _, t := range tags {
		l, lo, ok := parseNessusListener(t.Name, t.Value)
		if !ok {
			continue
		}
		if lo {
			loopback++
			continue
		}
		key := fmt.Sprintf("%d/%s", l.port, l.transport)
		if seen[key] {
			continue
		}
		seen[key] = true
		if kept >= nessusMaxListenersPerHost {
			b.issue(Issue{Line: lineNo, Path: nsTag, Message: fmt.Sprintf("host %s: more than %d listening sockets, the rest left out", b.assetValue(hostID), nessusMaxListenersPerHost)})
			break
		}
		id := b.service(hostID, l.port, l.transport, "")
		if id == "" {
			continue
		}
		kept++
		svc := b.assetByID(id)
		st := svc.Technical.Service
		if st.Details == nil {
			st.Details = map[string]string{}
		}
		if reached[key] {
			st.Details["observed_from"] = "network"
		} else {
			st.Details["observed_from"] = "host"
		}
		if l.bind == "" {
			st.Details["bind_address"] = "any"
		} else {
			st.Details["bind_address"] = l.bind
		}
		if l.process != "" {
			st.Details["process"] = l.process
		}
	}
	if loopback > 0 {
		b.issue(Issue{Line: lineNo, Path: nsTag, Message: fmt.Sprintf("host %s: %d listening sockets bound to loopback only were not kept as services", b.assetValue(hostID), loopback)})
	}
}

// nessusPackage is one installed package of an enumeration plugin.
type nessusPackage struct {
	name, version, arch, epoch, vendor string
	manager                            string // deb, rpm, apk or windows
}

var (
	// dpkg -l: "ii  name  version  arch  description".
	reDpkgLine = regexp.MustCompile(`^[a-z][a-zA-Z ]?[a-z]?\s+([a-z0-9][a-z0-9+.\-]*(?::[a-z0-9]+)?)\s+(\S+)\s+(\S+)`)
	// Windows: "Name  [version 1.2.3]  [installed on 2024/01/01]".
	reWinVersion   = regexp.MustCompile(`\[version ([^\]]{1,128})\]`)
	reWinPublisher = regexp.MustCompile(`\[(?:publisher|vendor) ([^\]]{1,128})\]`)
	rePkgName      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+._\-]*$`)
	reArchSuffix   = regexp.MustCompile(`\.(x86_64|noarch|i[3-6]86|aarch64|ppc64le|s390x|armv7hl)$`)
)

// parseNessusPackages reads the plugin output of a software enumeration
// plugin. Lines that are not a package are skipped.
func parseNessusPackages(kind, out string, max int) (pkgs []nessusPackage, more bool) {
	for _, raw := range strings.Split(out, "\n") {
		if len(raw) > nessusMaxPackageLine {
			continue
		}
		l := strings.TrimSpace(raw)
		if l == "" || strings.HasSuffix(l, ":") {
			continue
		}
		var p nessusPackage
		var ok bool
		if kind == "windows" {
			p, ok = parseWindowsPackage(l)
		} else {
			p, ok = parseUnixPackage(l)
		}
		if !ok {
			continue
		}
		if len(pkgs) >= max {
			return pkgs, true
		}
		pkgs = append(pkgs, p)
	}
	return pkgs, false
}

func parseWindowsPackage(l string) (nessusPackage, bool) {
	m := reWinVersion.FindStringSubmatchIndex(l)
	if m == nil {
		return nessusPackage{}, false
	}
	name := strings.TrimSpace(l[:m[0]])
	ver := strings.TrimSpace(l[m[2]:m[3]])
	// Some names repeat the version after a dash ("Runtime - 14.2").
	name = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(strings.TrimSuffix(name, ver)), "-"))
	p := nessusPackage{name: line(name, nessusMaxPackageName), version: line(ver, nessusMaxPackageVersion), manager: "windows"}
	if pm := reWinPublisher.FindStringSubmatch(l); pm != nil {
		p.vendor = line(pm[1], capShort)
	}
	return p, p.name != "" && p.version != ""
}

func parseUnixPackage(l string) (nessusPackage, bool) {
	// dpkg.
	if m := reDpkgLine.FindStringSubmatch(l); m != nil && strings.HasPrefix(l, "ii") {
		name, _, _ := strings.Cut(m[1], ":") // name:arch
		p := nessusPackage{name: name, version: m[2], arch: m[3], manager: "deb"}
		return p, validPackage(p)
	}
	// rpm: "name-version-release|epoch|..." (epoch "(none)" when unset).
	if nvr, rest, ok := strings.Cut(l, "|"); ok {
		nvr = strings.TrimSpace(nvr)
		arch := ""
		if m := reArchSuffix.FindStringSubmatch(nvr); m != nil {
			arch = m[1]
			nvr = strings.TrimSuffix(nvr, m[0])
		}
		name, ver, rel, ok := splitNVR(nvr)
		if !ok {
			return nessusPackage{}, false
		}
		p := nessusPackage{name: name, version: ver + "-" + rel, arch: arch, manager: "rpm"}
		epoch, _, _ := strings.Cut(rest, "|")
		if n, err := strconv.Atoi(strings.TrimSpace(epoch)); err == nil && n > 0 {
			p.epoch = strconv.Itoa(n)
		}
		return p, validPackage(p)
	}
	// apk: "name-version-rN".
	if f := strings.Fields(l); len(f) == 1 {
		name, ver, rel, ok := splitNVR(f[0])
		if ok && strings.HasPrefix(rel, "r") {
			p := nessusPackage{name: name, version: ver + "-" + rel, manager: "apk"}
			return p, validPackage(p)
		}
	}
	return nessusPackage{}, false
}

// splitNVR splits name-version-release on its last two dashes; the version
// must start with a digit.
func splitNVR(s string) (name, ver, rel string, ok bool) {
	i := strings.LastIndexByte(s, '-')
	if i <= 0 {
		return "", "", "", false
	}
	rel = s[i+1:]
	j := strings.LastIndexByte(s[:i], '-')
	if j <= 0 {
		return "", "", "", false
	}
	name, ver = s[:j], s[j+1:i]
	if ver == "" || rel == "" || ver[0] < '0' || ver[0] > '9' {
		return "", "", "", false
	}
	return name, ver, rel, true
}

func validPackage(p nessusPackage) bool {
	if p.name == "gpg-pubkey" {
		return false // an imported signing key, not a package
	}
	return rePkgName.MatchString(p.name) && len(p.name) <= nessusMaxPackageName &&
		p.version != "" && len(p.version) <= nessusMaxPackageVersion && !strings.ContainsAny(p.version, " \t/?#@")
}

// nessusDistro reads the purl namespace and distro qualifier of a Unix host
// from its operating-system property ("Linux Kernel 6.8 on Ubuntu 24.04").
func nessusDistro(os, manager string) (namespace, distro string) {
	o := strings.ToLower(os)
	type d struct{ word, ns, short string }
	var table []d
	switch manager {
	case "deb":
		table = []d{{"ubuntu", "ubuntu", "ubuntu"}, {"debian", "debian", "debian"}}
	case "rpm":
		table = []d{
			{"red hat", "redhat", "rhel"}, {"centos", "centos", "centos"}, {"rocky", "rocky", "rocky"},
			{"alma", "almalinux", "almalinux"}, {"fedora", "fedora", "fedora"}, {"amazon", "amzn", "amzn"},
			{"oracle", "oracle", "ol"}, {"suse", "opensuse", "sles"},
		}
	case "apk":
		return "alpine", ""
	}
	for _, e := range table {
		if i := strings.Index(o, e.word); i >= 0 {
			if m := reDistroVersion.FindStringSubmatch(o[i:]); m != nil {
				return e.ns, e.short + "-" + m[1]
			}
			return e.ns, ""
		}
	}
	return "", ""
}

var reDistroVersion = regexp.MustCompile(`^[a-z ]*?(?:linux|enterprise|server|release| )*\s*([0-9]+(?:\.[0-9]+)?)`)

// purl returns the package URL of an installed package: deb, rpm or apk with
// the distribution as namespace when the host's operating system names one,
// else a generic purl. Natural key: the receiver derives the component's
// identity from it.
func (p nessusPackage) purl(os string) string {
	esc := url.PathEscape
	q := url.Values{}
	if p.arch != "" {
		q.Set("arch", p.arch)
	}
	if p.epoch != "" {
		q.Set("epoch", p.epoch)
	}
	var s string
	switch p.manager {
	case "deb", "rpm", "apk":
		ns, distro := nessusDistro(os, p.manager)
		if ns == "" {
			s = "pkg:generic/" + esc(p.name) + "@" + esc(p.version)
			break
		}
		if distro != "" {
			q.Set("distro", distro)
		}
		s = "pkg:" + p.manager + "/" + ns + "/" + esc(p.name) + "@" + esc(p.version)
	default:
		s = "pkg:generic/"
		if p.vendor != "" {
			s += esc(p.vendor) + "/"
		}
		s += esc(p.name) + "@" + esc(p.version)
	}
	if len(q) > 0 {
		s += "?" + q.Encode()
	}
	if _, _, err := ctis.CanonicalPurl(s); err != nil {
		return ""
	}
	return s
}

// nessusInventory adds the packages of a software enumeration plugin result
// as components of the host. The plugin output stays the finding's raw
// evidence.
func (b *Builder) nessusInventory(it *nessusItem, kind, hostID, os string, seen map[string]bool, lineNo int) {
	var out string
	for _, f := range it.Fields {
		if f.XMLName.Local == "plugin_output" {
			out = f.Value
			break
		}
	}
	if out == "" {
		return
	}
	pkgs, more := parseNessusPackages(kind, out, nessusMaxPackagesPerHost-len(seen))
	if more {
		b.issue(Issue{Line: lineNo, Path: nsItem, Message: fmt.Sprintf("host %s: more than %d installed packages, the rest left out", b.assetValue(hostID), nessusMaxPackagesPerHost)})
	}
	for _, p := range pkgs {
		purl := p.purl(os)
		key := purl
		if key == "" {
			key = p.manager + "\x1f" + p.name + "\x1f" + p.version
		}
		if seen[key] {
			continue
		}
		if len(b.res.Report.Dependencies) >= b.lim.MaxComponents {
			b.issue(Issue{Line: lineNo, Path: nsItem, Message: fmt.Sprintf("more than %d components: the installed packages of %s and later hosts left out", b.lim.MaxComponents, b.assetValue(hostID))})
			return
		}
		seen[key] = true
		typ := ctis.DependencyTypeLibrary
		if p.manager == "windows" {
			typ = ctis.DependencyTypeApplication
		}
		d := ctis.Dependency{
			ID:       docRef("pkg", hostID+"|"+key),
			Name:     p.name,
			Version:  p.version,
			Type:     typ,
			PURL:     purl,
			AssetRef: hostID,
		}
		addDepProperty(&d, "package_manager", p.manager)
		addDepProperty(&d, "vendor", p.vendor)
		addDepProperty(&d, "source_plugin", strings.TrimSpace(it.PluginID))
		_ = b.dependency(d) // the limit is checked above
	}
}
