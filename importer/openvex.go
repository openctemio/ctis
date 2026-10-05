package importer

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/openctemio/ctis"
)

// OpenVEX JSON (v0.2.0; the v0.0.1 forms of vulnerability, products and
// subcomponents as plain strings are read too). One VEX statement per
// OpenVEX statement. The mapping is spec_openvex.go.

func init() {
	parsers[FormatOpenVEX] = parseOpenVEX
	tools[FormatOpenVEX] = ctis.Tool{Name: "openvex"}
}

type openvexComponent struct {
	ID          string `json:"@id"`
	Identifiers struct {
		PURL  string `json:"purl"`
		CPE22 string `json:"cpe22"`
		CPE23 string `json:"cpe23"`
	} `json:"identifiers"`
	Subcomponents []json.RawMessage `json:"subcomponents"`
}

type openvexVuln struct {
	ID      string   `json:"@id"`
	Name    string   `json:"name"`
	Aliases []string `json:"aliases"`
}

type openvexStatement struct {
	Vulnerability   json.RawMessage   `json:"vulnerability"`
	Products        []json.RawMessage `json:"products"`
	Subcomponents   []json.RawMessage `json:"subcomponents"` // v0.0.1
	Status          string            `json:"status"`
	StatusNotes     string            `json:"status_notes"`
	Justification   string            `json:"justification"`
	ImpactStatement string            `json:"impact_statement"`
	ActionStatement string            `json:"action_statement"`
	Timestamp       string            `json:"timestamp"`
	LastUpdated     string            `json:"last_updated"`
}

type openvexDoc struct {
	Context     string             `json:"@context"`
	ID          string             `json:"@id"`
	Author      string             `json:"author"`
	Timestamp   string             `json:"timestamp"`
	LastUpdated string             `json:"last_updated"`
	Version     json.Number        `json:"version"`
	Tooling     string             `json:"tooling"`
	Statements  []openvexStatement `json:"statements"`
}

func parseOpenVEX(b *builder, r io.Reader) error {
	data, err := readAll(r, FormatOpenVEX, b.lim)
	if err != nil {
		return err
	}
	doc, err := scanJSON(data, FormatOpenVEX, b.lim, b.obs, "/statements[]")
	if err != nil {
		return err
	}
	var d openvexDoc
	if err := doc.decode(&d); err != nil {
		return err
	}
	if !strings.Contains(d.Context, "openvex.dev/ns") {
		return &ParseError{Format: FormatOpenVEX, Msg: "@context is not an OpenVEX context", Err: ErrMalformed}
	}

	meta := &b.res.Report.Metadata
	meta.SourceRef = line(d.ID, capShort)
	props := ctis.Properties{}
	for k, v := range map[string]string{"author": d.Author, "document_version": d.Version.String(), "tooling": d.Tooling, "openvex_context": d.Context} {
		if v = line(v, capShort); v != "" {
			props[k] = v
		}
	}
	if len(props) > 0 {
		meta.Properties = props
	}
	source := strings.TrimSpace(d.ID)
	if a := strings.TrimSpace(d.Author); a != "" {
		if source != "" {
			source = a + " (" + source + ")"
		} else {
			source = a
		}
	}
	docTime := parseTime(firstNonEmpty(d.LastUpdated, d.Timestamp))

	for si := range d.Statements {
		if err := b.tick(); err != nil {
			return err
		}
		b.res.Stats.Records++
		s := &d.Statements[si]
		ptr := fmt.Sprintf("/statements/%d", si)
		issue := func(msg string) { b.issue(doc.issueAt("/statements[]", si, ptr, msg)) }
		skip := func(msg string) {
			issue(msg)
			b.res.Stats.Skipped++
		}

		ids, ok := openvexIDs(s.Vulnerability)
		if !ok {
			skip("statement without a usable vulnerability name: skipped")
			continue
		}

		var products []Product
		for _, raw := range s.Products {
			p, ok := openvexProduct(raw, true)
			if !ok {
				issue("product without @id or identifiers: left out")
				continue
			}
			products = append(products, p)
		}
		// v0.0.1: statement-level subcomponents narrow every product.
		var subs []Product
		for _, raw := range s.Subcomponents {
			if p, ok := openvexProduct(raw, false); ok {
				subs = append(subs, p)
			}
		}
		if len(subs) > 0 {
			for i := range products {
				products[i].Subcomponents = append(products[i].Subcomponents, subs...)
			}
		}
		if len(products) == 0 {
			skip("statement without products: skipped")
			continue
		}
		if len(products) > b.lim.MaxComponents {
			return b.tooMany("products in one statement", b.lim.MaxComponents)
		}

		var text string
		switch strings.TrimSpace(s.Status) {
		case "not_affected":
			text = s.ImpactStatement
		case "affected":
			text = s.ActionStatement
		}
		if n := strings.TrimSpace(s.StatusNotes); n != "" {
			if strings.TrimSpace(text) != "" {
				text = strings.TrimSpace(text) + "\n\n" + n
			} else {
				text = n
			}
		}
		asOf := parseTime(firstNonEmpty(s.LastUpdated, s.Timestamp))
		if asOf == nil {
			asOf = docTime
		}
		vex, err := vexOf(s.Status, s.Justification, text, source, asOf)
		if err != nil {
			skip(err.Error() + ": skipped")
			continue
		}
		if vex.Justification == "" && strings.TrimSpace(s.Justification) != "" && vex.Status == ctis.VEXStatusNotAffected {
			issue(fmt.Sprintf("justification %q is not an OpenVEX justification; the statement text is kept", line(s.Justification, 64)))
		}
		if err := b.statement(VEXStatement{VulnerabilityIDs: ids, Products: products, VEX: vex}); err != nil {
			return err
		}
	}
	return nil
}

// openvexIDs reads a vulnerability: an object with name and aliases, or (in
// v0.0.1) a string.
func openvexIDs(raw json.RawMessage) ([]ctis.VulnerabilityID, bool) {
	var vd ctis.VulnerabilityDetails
	var name string
	if err := json.Unmarshal(raw, &name); err == nil {
		addVulnID(&vd, name)
		return vd.IDs, len(vd.IDs) > 0
	}
	var v openvexVuln
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, false
	}
	addVulnID(&vd, v.Name)
	for _, a := range v.Aliases {
		addVulnID(&vd, a)
	}
	return vd.IDs, len(vd.IDs) > 0
}

// openvexProduct reads a product or subcomponent: an object, or (in
// v0.0.1) a string identifier. The identifiers win over @id; an @id that is
// a PURL or CPE fills the empty one, any other @id becomes the name.
// Subcomponents of a product are read one level deep.
func openvexProduct(raw json.RawMessage, withSubs bool) (Product, bool) {
	var c openvexComponent
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		c.ID = s
	} else if err := json.Unmarshal(raw, &c); err != nil {
		return Product{}, false
	}
	p := Product{
		PURL: line(c.Identifiers.PURL, capReference),
		CPE:  line(firstNonEmpty(c.Identifiers.CPE23, c.Identifiers.CPE22), capShort),
	}
	id := line(c.ID, capReference)
	switch {
	case strings.HasPrefix(id, "pkg:"):
		if p.PURL == "" {
			p.PURL = id
		}
	case strings.HasPrefix(id, "cpe:"):
		if p.CPE == "" {
			p.CPE = id
		}
	case id != "":
		p.Name = line(id, capShort)
	}
	if withSubs {
		for _, sraw := range c.Subcomponents {
			if sp, ok := openvexProduct(sraw, false); ok {
				p.Subcomponents = append(p.Subcomponents, sp)
			}
		}
	}
	return p, p.PURL != "" || p.CPE != "" || p.Name != ""
}
