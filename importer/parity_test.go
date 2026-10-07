package importer

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/openctemio/ctis"
)

// Parity with the converters these formats replace (the SDK's tool
// adapters): each <stem>.legacy.json is the CTIS the old converter wrote for
// the fixture. The core of every finding and asset must be the same; the
// differences below are deliberate, each with its reason, and any other
// difference fails the test.
var parityAllowed = map[string]string{
	// Every format.
	"*:asset.criticality": "no default criticality on an imported asset: that is the receiver's call (CTIS spec 4.1)",
	// SARIF goes through the module's FromSARIF instead of the SDK's
	// second SARIF converter.
	"sarif:finding.fingerprint": "FromSARIF fingerprints a result by its own fingerprints entry, else leaves it to the receiver's RFC-043 recipe",
	"sarif:finding.type":        "FromSARIF types a result from the rule's tags, the rule id and the tool name",
	"sarif:finding.title":       "FromSARIF titles a finding with the result's message (what this occurrence is), the rule's short description becomes its description",
	// semgrep.
	"semgrep:finding.fingerprint": "semgrep's placeholder \"requires login\" is no fingerprint; one is derived from path, rule and line",
	// betterleaks.
	"betterleaks:finding.secret_type": "secret types are the CTIS schema's (generic_secret, aws_key, ...); the old words were refused by the schema",
	// nuclei.
	"nuclei:finding.path": "a matched URL is no file: it is finding.web.url (CTIS 1.6), redacted, and location.path stays empty",
	// trivy.
	"trivy:finding.secret_type": "secret types are the CTIS schema's; trivy's category is kept in source_extra.category",
}

type parityAsset struct{ Type, Value, Criticality string }

type parityFinding struct {
	Type, Title, Severity, RuleID, Path, CVE, PURL, Fingerprint, SecretType string
	Line                                                                    int
}

func parityOf(r *ctis.Report) ([]parityAsset, []parityFinding) {
	var as []parityAsset
	for _, a := range r.Assets {
		as = append(as, parityAsset{string(a.Type), a.Value, string(a.Criticality)})
	}
	var fs []parityFinding
	for _, f := range r.Findings {
		p := parityFinding{Type: string(f.Type), Title: f.Title, Severity: string(f.Severity), RuleID: f.RuleID, Fingerprint: f.Fingerprint}
		if f.Location != nil {
			p.Path, p.Line = f.Location.Path, f.Location.StartLine
		}
		if v := f.Vulnerability; v != nil {
			p.CVE, p.PURL = v.CVEID, v.PURL
		}
		if s := f.Secret; s != nil {
			p.SecretType = s.SecretType
		}
		fs = append(fs, p)
	}
	return as, fs
}

func TestImporters_ParityWithLegacyConverters(t *testing.T) {
	legacies, _ := filepath.Glob(filepath.Join(fixtureRoot, "*", "*.legacy.json"))
	if len(legacies) == 0 {
		t.Fatal("no legacy references")
	}
	for _, lg := range legacies {
		format := Format(filepath.Base(filepath.Dir(lg)))
		base := strings.TrimSuffix(lg, ".legacy.json")
		var input string
		for _, fx := range fixtures(t) {
			if stem(fx.path) == base {
				input = fx.path
			}
		}
		if input == "" {
			t.Fatalf("%s: no input fixture", lg)
		}
		t.Run(filepath.Base(lg), func(t *testing.T) {
			raw, err := os.ReadFile(lg)
			if err != nil {
				t.Fatal(err)
			}
			var old ctis.Report
			if err := json.Unmarshal(raw, &old); err != nil {
				t.Fatal(err)
			}
			res, _ := runFixture(t, fixture{format: format, path: input})
			oa, of := parityOf(&old)
			na, nf := parityOf(res.Report)
			var diffs []string
			diff := func(field, a, b string) {
				if a == b {
					return
				}
				if _, ok := parityAllowed["*:"+field]; ok {
					return
				}
				if _, ok := parityAllowed[string(format)+":"+field]; ok {
					return
				}
				diffs = append(diffs, fmt.Sprintf("%s: old %q, new %q", field, a, b))
			}
			if len(oa) != len(na) {
				diffs = append(diffs, fmt.Sprintf("assets: old %d, new %d", len(oa), len(na)))
			} else {
				for i := range oa {
					diff("asset.type", oa[i].Type, na[i].Type)
					diff("asset.value", oa[i].Value, na[i].Value)
					diff("asset.criticality", oa[i].Criticality, na[i].Criticality)
				}
			}
			if len(of) != len(nf) {
				diffs = append(diffs, fmt.Sprintf("findings: old %d, new %d", len(of), len(nf)))
			} else {
				for i := range of {
					o, n := of[i], nf[i]
					diff("finding.type", o.Type, n.Type)
					diff("finding.title", o.Title, n.Title)
					diff("finding.severity", o.Severity, n.Severity)
					diff("finding.rule_id", o.RuleID, n.RuleID)
					diff("finding.path", o.Path, n.Path)
					diff("finding.line", fmt.Sprint(o.Line), fmt.Sprint(n.Line))
					diff("finding.cve", o.CVE, n.CVE)
					diff("finding.purl", o.PURL, n.PURL)
					diff("finding.fingerprint", o.Fingerprint, n.Fingerprint)
					diff("finding.secret_type", o.SecretType, n.SecretType)
				}
			}
			sort.Strings(diffs)
			for _, d := range diffs {
				t.Errorf("unexplained difference from the legacy converter: %s", d)
			}
		})
	}
}
