package importer

import (
	"fmt"
	"io"
	"strings"

	"github.com/openctemio/ctis"
)

// CSAF 2.0 JSON (the csaf_vex and csaf_security_advisory profiles). A CSAF
// document describes products, not findings: the result is one VEX
// statement per vulnerability, status group and statement text, naming the
// products by PURL, CPE or name. The mapping is spec_csaf.go.

func init() {
	parsers[FormatCSAF] = parseCSAF
	tools[FormatCSAF] = ctis.Tool{Name: "csaf"}
}

type csafHelper struct {
	CPE  string `json:"cpe"`
	PURL string `json:"purl"`
}

type csafFullProductName struct {
	Name      string      `json:"name"`
	ProductID string      `json:"product_id"`
	Helper    *csafHelper `json:"product_identification_helper"`
}

type csafBranch struct {
	Category string               `json:"category"`
	Name     string               `json:"name"`
	Product  *csafFullProductName `json:"product"`
	Branches []csafBranch         `json:"branches"`
}

type csafRelationship struct {
	Category                  string              `json:"category"`
	FullProductName           csafFullProductName `json:"full_product_name"`
	ProductReference          string              `json:"product_reference"`
	RelatesToProductReference string              `json:"relates_to_product_reference"`
}

type csafGroup struct {
	GroupID    string   `json:"group_id"`
	ProductIDs []string `json:"product_ids"`
}

type csafProductTree struct {
	Branches         []csafBranch          `json:"branches"`
	FullProductNames []csafFullProductName `json:"full_product_names"`
	Relationships    []csafRelationship    `json:"relationships"`
	ProductGroups    []csafGroup           `json:"product_groups"`
}

type csafScoped struct {
	Category   string   `json:"category"`
	Label      string   `json:"label"`
	Details    string   `json:"details"`
	URL        string   `json:"url"`
	Date       string   `json:"date"`
	ProductIDs []string `json:"product_ids"`
	GroupIDs   []string `json:"group_ids"`
}

type csafVuln struct {
	CVE string `json:"cve"`
	IDs []struct {
		SystemName string `json:"system_name"`
		Text       string `json:"text"`
	} `json:"ids"`
	ProductStatus map[string][]string `json:"product_status"`
	Flags         []csafScoped        `json:"flags"`
	Threats       []csafScoped        `json:"threats"`
	Remediations  []csafScoped        `json:"remediations"`
}

type csafDoc struct {
	Document struct {
		Category    string `json:"category"`
		CSAFVersion string `json:"csaf_version"`
		Title       string `json:"title"`
		Publisher   struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"publisher"`
		Tracking struct {
			ID                 string `json:"id"`
			Version            string `json:"version"`
			Status             string `json:"status"`
			CurrentReleaseDate string `json:"current_release_date"`
			InitialReleaseDate string `json:"initial_release_date"`
		} `json:"tracking"`
		Distribution struct {
			TLP struct {
				Label string `json:"label"`
			} `json:"tlp"`
		} `json:"distribution"`
		AggregateSeverity struct {
			Text string `json:"text"`
		} `json:"aggregate_severity"`
	} `json:"document"`
	ProductTree     *csafProductTree `json:"product_tree"`
	Vulnerabilities []csafVuln       `json:"vulnerabilities"`
}

// csafStatusGroups maps the product_status groups, in output order, to the
// status word vexOf reads.
var csafStatusGroups = []struct{ group, status string }{
	{"known_not_affected", "not_affected"},
	{"known_affected", "affected"},
	{"first_affected", "affected"},
	{"last_affected", "affected"},
	{"fixed", "fixed"},
	{"first_fixed", "fixed"},
	{"recommended", "fixed"},
	{"under_investigation", "under_investigation"},
}

type csafStatus struct {
	group, status string
	pids          []string
}

// csafMergedStatus merges the product_status groups that stand for the same
// status (first_affected and last_affected are both affected), so a product
// listed in two of them gets one statement.
func csafMergedStatus(ps map[string][]string) []csafStatus {
	var out []csafStatus
	idx := map[string]int{}
	for _, g := range csafStatusGroups {
		pids := ps[g.group]
		if len(pids) == 0 {
			continue
		}
		i, ok := idx[g.status]
		if !ok {
			i = len(out)
			idx[g.status] = i
			out = append(out, csafStatus{group: g.group, status: g.status})
		} else {
			out[i].group += "/" + g.group
		}
		out[i].pids = append(out[i].pids, pids...)
	}
	return out
}

func parseCSAF(b *builder, r io.Reader) error {
	data, err := readAll(r, FormatCSAF, b.lim)
	if err != nil {
		return err
	}
	doc, err := scanJSON(data, FormatCSAF, b.lim, b.obs, "/vulnerabilities[]")
	if err != nil {
		return err
	}
	var d csafDoc
	if err := doc.decode(&d); err != nil {
		return err
	}
	if strings.TrimSpace(d.Document.CSAFVersion) == "" {
		return &ParseError{Format: FormatCSAF, Msg: "document.csaf_version is missing: not a CSAF document", Err: ErrMalformed}
	}

	meta := &b.res.Report.Metadata
	meta.SourceRef = line(d.Document.Tracking.ID, capShort)
	props := ctis.Properties{}
	setProp := func(k, v string) {
		if v = line(v, capShort); v != "" {
			props[k] = v
		}
	}
	setProp("title", d.Document.Title)
	setProp("category", d.Document.Category)
	setProp("csaf_version", d.Document.CSAFVersion)
	setProp("publisher", d.Document.Publisher.Name)
	setProp("publisher_namespace", d.Document.Publisher.Namespace)
	setProp("document_version", d.Document.Tracking.Version)
	setProp("document_status", d.Document.Tracking.Status)
	setProp("initial_release_date", d.Document.Tracking.InitialReleaseDate)
	setProp("current_release_date", d.Document.Tracking.CurrentReleaseDate)
	setProp("tlp", d.Document.Distribution.TLP.Label)
	setProp("aggregate_severity", d.Document.AggregateSeverity.Text)
	if len(props) > 0 {
		meta.Properties = props
	}

	source := strings.TrimRight(strings.TrimSpace(d.Document.Publisher.Namespace), "/")
	if id := strings.TrimSpace(d.Document.Tracking.ID); id != "" {
		if source != "" {
			source += "#" + id
		} else {
			source = id
		}
	}
	asOf := parseTime(d.Document.Tracking.CurrentReleaseDate)

	tree, err := b.csafTree(d.ProductTree)
	if err != nil {
		return err
	}

	for vi := range d.Vulnerabilities {
		if err := b.tick(); err != nil {
			return err
		}
		b.res.Stats.Records++
		v := &d.Vulnerabilities[vi]
		ptr := fmt.Sprintf("/vulnerabilities/%d", vi)
		issue := func(msg string) { b.issue(doc.issueAt("/vulnerabilities[]", vi, ptr, msg)) }

		ids := csafVulnIDs(v)
		if len(ids) == 0 {
			issue("vulnerability without cve or ids: skipped")
			b.res.Stats.Skipped++
			continue
		}

		// Per product: justification label, impact statement, remediation
		// text.
		just := tree.scoped(v.Flags, func(s csafScoped) string { return s.Label })
		impact := tree.scoped(v.Threats, func(s csafScoped) string {
			if strings.EqualFold(s.Category, "impact") {
				return s.Details
			}
			return ""
		})
		remedy := tree.scoped(v.Remediations, func(s csafScoped) string {
			t := strings.TrimSpace(s.Category)
			if d := strings.TrimSpace(s.Details); d != "" {
				t += ": " + d
			}
			if u := strings.TrimSpace(s.URL); u != "" {
				t += " (" + u + ")"
			}
			return t
		})

		kept := 0
		for _, g := range csafMergedStatus(v.ProductStatus) {
			pids := g.pids
			// Group the products by the statement they get.
			type key struct{ just, text string }
			byKey := map[key][]Product{}
			var order []key
			for _, pid := range uniqueStrings(pids) {
				p, ok := tree.products[pid]
				if !ok {
					issue(fmt.Sprintf("product_status.%s names product %q, which the product tree does not define: left out", g.group, line(pid, 128)))
					continue
				}
				k := key{}
				switch g.status {
				case "not_affected":
					k.just = just[pid]
					k.text = impact[pid]
				case "affected", "fixed":
					k.text = remedy[pid]
				}
				if _, seen := byKey[k]; !seen {
					order = append(order, k)
				}
				byKey[k] = append(byKey[k], p)
			}
			for _, k := range order {
				vex, err := vexOf(g.status, k.just, k.text, source, asOf)
				if err != nil {
					issue(fmt.Sprintf("product_status.%s: %v: products left out: %d", g.group, err, len(byKey[k])))
					continue
				}
				if vex.Justification == "" && k.just != "" {
					issue(fmt.Sprintf("flag label %q is not a CSAF justification", line(k.just, 64)))
				}
				if err := b.statement(VEXStatement{VulnerabilityIDs: ids, Products: byKey[k], VEX: vex}); err != nil {
					return err
				}
				kept++
			}
		}
		if kept == 0 {
			b.res.Stats.Skipped++
		}
	}
	return nil
}

// csafVulnIDs returns the typed ids of a vulnerability.
func csafVulnIDs(v *csafVuln) []ctis.VulnerabilityID {
	var vd ctis.VulnerabilityDetails
	addVulnID(&vd, v.CVE)
	for _, id := range v.IDs {
		addVendorID(&vd, id.Text, strings.ToLower(line(id.SystemName, 64)))
	}
	return vd.IDs
}

func uniqueStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// csafProducts is a resolved product tree.
type csafProducts struct {
	products map[string]Product
	groups   map[string][]string
}

// scoped assigns each product of the items (by product_ids and group_ids)
// the value pick returns for the item; the first non-empty value wins.
func (t *csafProducts) scoped(items []csafScoped, pick func(csafScoped) string) map[string]string {
	out := map[string]string{}
	for _, it := range items {
		v := strings.TrimSpace(pick(it))
		if v == "" {
			continue
		}
		ids := append([]string(nil), it.ProductIDs...)
		for _, g := range it.GroupIDs {
			ids = append(ids, t.groups[g]...)
		}
		for _, id := range ids {
			if _, ok := out[id]; !ok {
				out[id] = v
			}
		}
	}
	return out
}

func csafProduct(fpn *csafFullProductName, version string) Product {
	p := Product{Name: line(fpn.Name, capShort), Version: line(version, capShort)}
	if h := fpn.Helper; h != nil {
		p.PURL = line(h.PURL, capReference)
		p.CPE = line(h.CPE, capShort)
	}
	return p
}

// csafTree resolves the product tree into product ids.
func (b *builder) csafTree(pt *csafProductTree) (*csafProducts, error) {
	t := &csafProducts{products: map[string]Product{}, groups: map[string][]string{}}
	if pt == nil {
		return t, nil
	}
	add := func(id string, p Product) error {
		id = strings.TrimSpace(id)
		if id == "" {
			return nil
		}
		if _, ok := t.products[id]; ok {
			return nil
		}
		if len(t.products) >= b.lim.MaxComponents {
			return b.tooMany("products", b.lim.MaxComponents)
		}
		t.products[id] = p
		return nil
	}

	// Branches nest; scanJSON already bounded the depth. Walk with an
	// explicit stack.
	type frame struct {
		br      *csafBranch
		version string
	}
	var stack []frame
	for i := range pt.Branches {
		stack = append(stack, frame{&pt.Branches[i], ""})
	}
	for len(stack) > 0 {
		if err := b.tick(); err != nil {
			return nil, err
		}
		f := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		version := f.version
		if f.br.Category == "product_version" || f.br.Category == "product_version_range" {
			version = f.br.Name
		}
		if f.br.Product != nil {
			if err := add(f.br.Product.ProductID, csafProduct(f.br.Product, version)); err != nil {
				return nil, err
			}
		}
		for i := range f.br.Branches {
			stack = append(stack, frame{&f.br.Branches[i], version})
		}
	}
	for i := range pt.FullProductNames {
		if err := add(pt.FullProductNames[i].ProductID, csafProduct(&pt.FullProductNames[i], "")); err != nil {
			return nil, err
		}
	}

	// A relationship names a component inside a platform. It may refer to
	// another relationship's product, so resolve until nothing changes; a
	// cycle simply never resolves.
	pending := append([]csafRelationship(nil), pt.Relationships...)
	for len(pending) > 0 {
		var next []csafRelationship
		for _, rel := range pending {
			comp, ok1 := t.products[strings.TrimSpace(rel.ProductReference)]
			platform, ok2 := t.products[strings.TrimSpace(rel.RelatesToProductReference)]
			if !ok1 || !ok2 {
				next = append(next, rel)
				continue
			}
			p := csafProduct(&rel.FullProductName, platform.Version)
			if p.PURL == "" && p.CPE == "" {
				p.PURL, p.CPE = platform.PURL, platform.CPE
			}
			p.Subcomponents = []Product{withoutSubcomponents(comp)}
			if err := add(rel.FullProductName.ProductID, p); err != nil {
				return nil, err
			}
		}
		if len(next) == len(pending) {
			for _, rel := range next {
				b.issue(Issue{Path: "/product_tree/relationships", Message: fmt.Sprintf("relationship %q refers to an undefined or circular product: left out", line(rel.FullProductName.ProductID, 128))})
			}
			break
		}
		pending = next
	}

	for _, g := range pt.ProductGroups {
		id := strings.TrimSpace(g.GroupID)
		if id == "" {
			continue
		}
		t.groups[id] = uniqueStrings(g.ProductIDs)
	}
	return t, nil
}

// withoutSubcomponents keeps a nested product one level deep.
func withoutSubcomponents(p Product) Product {
	p.Subcomponents = nil
	return p
}
