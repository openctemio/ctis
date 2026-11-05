package importer

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/openctemio/ctis/v2"
)

// nmap XML (-oX). Every host that is up becomes an address; the names the
// user gave for it become DNS names that resolve to it; every open port
// becomes a service with nmap's product, version and CPE. NSE script output
// is free text a script author chose, so it is not read; nmap reports no
// findings of its own. The mapping is spec_nmap.go.

func init() {
	parsers[FormatNmap] = parseNmap
	tools[FormatNmap] = ctis.Tool{Name: "nmap", InfoURL: "https://nmap.org", Techniques: []ctis.Technique{ctis.TechniqueEASM}}
}

type nmapHost struct {
	StartTime string `xml:"starttime,attr"`
	EndTime   string `xml:"endtime,attr"`
	Status    struct {
		State string `xml:"state,attr"`
	} `xml:"status"`
	Addresses []struct {
		Addr     string `xml:"addr,attr"`
		AddrType string `xml:"addrtype,attr"`
		Vendor   string `xml:"vendor,attr"`
	} `xml:"address"`
	Hostnames []struct {
		Name string `xml:"name,attr"`
		Type string `xml:"type,attr"`
	} `xml:"hostnames>hostname"`
	Ports []nmapPort `xml:"ports>port"`
	OS    []struct {
		Name     string `xml:"name,attr"`
		Accuracy string `xml:"accuracy,attr"`
	} `xml:"os>osmatch"`
}

type nmapPort struct {
	Protocol string `xml:"protocol,attr"`
	PortID   string `xml:"portid,attr"`
	State    struct {
		State string `xml:"state,attr"`
	} `xml:"state"`
	Service *struct {
		Name      string   `xml:"name,attr"`
		Product   string   `xml:"product,attr"`
		Version   string   `xml:"version,attr"`
		ExtraInfo string   `xml:"extrainfo,attr"`
		Tunnel    string   `xml:"tunnel,attr"`
		Method    string   `xml:"method,attr"`
		Conf      string   `xml:"conf,attr"`
		CPEs      []string `xml:"cpe"`
	} `xml:"service"`
}

func parseNmap(b *Builder, r io.Reader) error {
	xr := newXMLReader(r, FormatNmap, b.lim, nil, b.obs)
	dec := xml.NewTokenDecoder(xr)
	sawRoot := false
	for {
		if err := b.tick(); err != nil {
			return err
		}
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return asParseError(err, FormatNmap)
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch se.Name.Local {
		case "nmaprun":
			if sawRoot {
				continue
			}
			sawRoot = true
			b.nmapRun(se)
		case "host":
			if !sawRoot {
				return &ParseError{Format: FormatNmap, Msg: "not an nmaprun document", Err: ErrMalformed}
			}
			lineNo, _ := xr.d.InputPos()
			var h nmapHost
			if err := dec.DecodeElement(&h, &se); err != nil {
				return asParseError(err, FormatNmap)
			}
			b.res.Stats.Records++
			if err := b.nmapHost(&h, lineNo); err != nil {
				return err
			}
		case "scaninfo", "verbose", "debugging", "runstats", "taskbegin", "taskend", "taskprogress", "output", "hosthint", "prescript", "postscript", "target":
			if !sawRoot {
				return &ParseError{Format: FormatNmap, Msg: "not an nmaprun document", Err: ErrMalformed}
			}
			if err := dec.Skip(); err != nil {
				return asParseError(err, FormatNmap)
			}
		default:
			if !sawRoot {
				return &ParseError{Format: FormatNmap, Msg: fmt.Sprintf("root element is <%s>, want <nmaprun>", se.Name.Local), Err: ErrMalformed}
			}
		}
	}
	if !sawRoot {
		return &ParseError{Format: FormatNmap, Msg: "no nmaprun element", Err: ErrMalformed}
	}
	b.stampImportScope()
	return nil
}

// nmapRun keeps the scanner's name and version. The command line is not
// kept: it can hold script arguments with credentials.
func (b *Builder) nmapRun(se xml.StartElement) {
	t := b.res.Report.Tool
	if t == nil {
		return
	}
	if s := tokenOf(attrValue(se, "scanner")); s != "" && b.opts.ToolName == "" {
		t.Name = s
	}
	if v := line(attrValue(se, "version"), 64); v != "" {
		t.Version = v
	}
}

func (b *Builder) nmapHost(h *nmapHost, lineNo int) error {
	if st := h.Status.State; st != "" && st != "up" {
		b.res.Stats.Skipped++
		return nil
	}
	var ip, mac, vendor string
	for _, a := range h.Addresses {
		switch a.AddrType {
		case "ipv4", "ipv6":
			if ip == "" {
				if p := net.ParseIP(strings.TrimSpace(a.Addr)); p != nil {
					ip = p.String()
				}
			}
		case "mac":
			if mac == "" {
				if hw, err := net.ParseMAC(strings.TrimSpace(a.Addr)); err == nil {
					mac, vendor = hw.String(), line(a.Vendor, capShort)
				}
			}
		}
	}
	if ip == "" {
		b.issue(Issue{Line: lineNo, Path: "/nmaprun/host", Message: "host without an IPv4 or IPv6 address: skipped"})
		b.res.Stats.Skipped++
		return nil
	}
	a := ctis.Asset{Type: ctis.AssetTypeIPAddress, Value: ip, Name: ip}
	ver := 4
	if strings.Contains(ip, ":") {
		ver = 6
	}
	a.Technical = &ctis.AssetTechnical{IPAddress: &ctis.IPAddressTechnical{Version: ver}}
	if mac != "" {
		a.Identifiers = &ctis.AssetIdentifiers{MACAddresses: []string{mac}}
		if vendor != "" {
			a.Properties = ctis.Properties{"mac_vendor": vendor}
		}
	}
	if os, conf := nmapOS(h); os != "" {
		a.Technologies = []ctis.Technology{{Name: os, Categories: []string{"operating-system"}, Confidence: conf}}
	}
	if t := nmapTime(h.StartTime); t != nil {
		a.FirstSeenAt = t
	}
	if t := nmapTime(h.EndTime); t != nil {
		a.LastSeenAt = t
	}
	if a.FirstSeenAt != nil && a.LastSeenAt != nil && a.LastSeenAt.Before(*a.FirstSeenAt) {
		a.FirstSeenAt = nil
	}
	if b.opts.DefaultConfidence > 0 {
		a.Confidence = b.opts.DefaultConfidence
	}
	var ptr []string
	for _, hn := range h.Hostnames {
		if hn.Type == "PTR" {
			if n, ok := dnsName(strings.TrimSuffix(hn.Name, ".")); ok {
				ptr = appendUnique(ptr, n)
			}
		}
	}
	if len(ptr) > 0 {
		if a.Properties == nil {
			a.Properties = ctis.Properties{}
		}
		if len(ptr) > 8 {
			ptr = ptr[:8]
		}
		a.Properties["ptr_names"] = ptr
	}
	ipID, err := b.asset(a)
	if err != nil || ipID == "" {
		return err
	}
	// A name the user asked nmap to scan resolves to the address. A PTR
	// name is the address owner's choice (often a provider's), so it stays
	// a property and never becomes an asset.
	for _, hn := range h.Hostnames {
		if hn.Type != "user" {
			continue
		}
		n, ok := dnsName(strings.TrimSuffix(hn.Name, "."))
		if !ok {
			continue
		}
		id, err := b.asset(ctis.Asset{Type: ctis.AssetTypeDomainName, Value: n, Name: n, Confidence: a.Confidence})
		if err != nil {
			return err
		}
		b.relate(ctis.RelResolvesTo, id, ipID)
	}
	for i := range h.Ports {
		if err := b.tick(); err != nil {
			return err
		}
		b.nmapPort(ipID, &h.Ports[i])
	}
	return nil
}

func (b *Builder) nmapPort(hostID string, p *nmapPort) {
	if p.State.State != "open" {
		return
	}
	port, err := strconv.Atoi(strings.TrimSpace(p.PortID))
	if err != nil {
		return
	}
	tr := ctis.Transport(strings.ToLower(p.Protocol))
	if !tr.IsValid() {
		return
	}
	name := ""
	if p.Service != nil {
		name = p.Service.Name
	}
	if p.Service != nil && p.Service.Tunnel == "ssl" && name == "http" {
		name = "https"
	}
	id := b.service(hostID, port, tr, name)
	if id == "" || p.Service == nil {
		return
	}
	svc := b.assetByID(id)
	st := svc.Technical.Service
	st.State = ctis.PortOpen
	st.Product = line(p.Service.Product, capShort)
	st.Version = line(p.Service.Version, capShort)
	st.ExtraInfo = line(p.Service.ExtraInfo, capShort)
	st.IsTLS = p.Service.Tunnel == "ssl"
	var cpe string
	for _, c := range p.Service.CPEs {
		if strings.HasPrefix(strings.TrimSpace(c), "cpe:/a:") {
			if v, err := ctis.CanonicalCPE(strings.TrimSpace(c)); err == nil {
				cpe = v
				break
			}
		}
	}
	st.CPE = cpe
	if st.Product != "" {
		t := ctis.Technology{Name: st.Product, Version: st.Version, CPE: cpe}
		// conf is nmap's 0-10 confidence; "probed" means a probe matched.
		if c, err := strconv.Atoi(p.Service.Conf); err == nil && c > 0 && c <= 10 {
			t.Confidence = c * 10
		}
		svc.Technologies = []ctis.Technology{t}
	}
	if m := tokenOf(p.Service.Method); m != "" {
		if st.Details == nil {
			st.Details = map[string]string{}
		}
		st.Details["detection_method"] = m
	}
}

// nmapOS returns the best OS match and its accuracy.
func nmapOS(h *nmapHost) (string, int) {
	best, acc := "", 0
	for _, m := range h.OS {
		a, _ := strconv.Atoi(m.Accuracy)
		if n := line(m.Name, capShort); n != "" && a > acc && a <= 100 {
			best, acc = n, a
		}
	}
	return best, acc
}

// nmapTime reads a Unix time in seconds.
func nmapTime(s string) *time.Time {
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil || n <= 0 {
		return nil
	}
	t := time.Unix(n, 0).UTC()
	return &t
}
