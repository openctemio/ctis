package importkit

import (
	"strings"
	"testing"

	"github.com/openctemio/ctis/v2"
)

func TestVexOf(t *testing.T) {
	v, err := VexOf("known_not_affected", "vulnerable_code_not_in_execute_path", "", "doc-1", nil)
	if err != nil || v.Status != ctis.VEXStatusNotAffected || v.Justification != ctis.VEXJustificationVulnerableCodeNotInExecutePath {
		t.Fatalf("vexOf = %+v, %v", v, err)
	}
	// CycloneDX words keep the source word next to the mapped one.
	v, err = VexOf("not_affected", "code_not_reachable", "", "", nil)
	if err != nil || v.Justification != ctis.VEXJustificationVulnerableCodeNotInExecutePath || v.NativeJustification != "code_not_reachable" {
		t.Fatalf("vexOf = %+v, %v", v, err)
	}
	// A justification only belongs to not_affected.
	v, err = VexOf("affected", "code_not_reachable", "upgrade", "", nil)
	if err != nil || v.Justification != "" {
		t.Fatalf("vexOf = %+v, %v", v, err)
	}
	// A bare not_affected claim is refused.
	if _, err := VexOf("not_affected", "", "", "", nil); err == nil {
		t.Fatal("bare not_affected accepted")
	}
	if _, err := VexOf("not_affected", "no idea", "", "", nil); err == nil {
		t.Fatal("unknown justification without a statement accepted")
	}
	if v, err := VexOf("not_affected", "", "The function is never called.", "", nil); err != nil || v.Statement == "" {
		t.Fatalf("statement-only not_affected refused: %v", err)
	}
	if _, err := VexOf("false_positive", "", "", "", nil); err == nil {
		t.Fatal("unknown status accepted")
	}
}

func TestTextTruncation(t *testing.T) {
	if got := Text(strings.Repeat("é", 20), 15); !strings.HasSuffix(got, TruncMarker) || len([]rune(got)) != 15 {
		t.Fatalf("text cut = %q", got)
	}
}

func TestPurlHelpers(t *testing.T) {
	for _, bad := range []string{"pkg:npm/a@1\n", "pkg:npm/a b@1", "pkg:npm/a\x00@1", "npm/a@1", "pkg:/a", "pkg:n*m/a@1"} {
		if got := CleanPURL(bad); got != "" && bad != "pkg:npm/a@1\n" {
			t.Errorf("CleanPURL(%q) = %q", bad, got)
		}
	}
	if PurlName("pkg:maven/org.example/a%2Fb@1?x=y") != "org.example/a/b" || PurlName("nope") != "" || PurlName("pkg:npm") != "" {
		t.Error("PurlName")
	}
}

func TestSBOMHelpers(t *testing.T) {
	if SeverityFromCVSS(9.1) != ctis.SeverityCritical || SeverityFromCVSS(0) != ctis.SeverityInfo || SeverityFromCVSS(3.9) != ctis.SeverityLow {
		t.Error("SeverityFromCVSS")
	}
	for w, want := range map[string]ctis.Severity{"important": ctis.SeverityHigh, "negligible": ctis.SeverityInfo, "moderate": ctis.SeverityMedium} {
		if got, ok := SeverityWord(w); !ok || got != want {
			t.Errorf("SeverityWord(%s) = %s", w, got)
		}
	}
	if _, ok := SeverityWord("x"); ok {
		t.Error("SeverityWord(x)")
	}
	if typ, v := SubjectAssetOf("container", "", "alpine", "sha256:"+strings.Repeat("a", 64), "x"); typ != ctis.AssetTypeContainerImage || v != "docker.io/library/alpine@sha256:"+strings.Repeat("a", 64) {
		t.Errorf("SubjectAssetOf container = %s %s", typ, v)
	}
	if typ, v := SubjectAssetOf("library", "pkg:npm/Foo@1.0", "foo", "1.0", "x"); typ != ctis.AssetTypePackage || v != "pkg:npm/Foo@1.0" {
		t.Errorf("SubjectAssetOf purl = %s %s", typ, v)
	}
	if typ, v := SubjectAssetOf("operating-system", "", "Ubuntu", "22.04", "x"); typ != ctis.AssetTypeUnclassified || v != "Ubuntu@22.04" {
		t.Errorf("SubjectAssetOf other = %s %s", typ, v)
	}
	if FloatString(7.5) != "7.5" {
		t.Error("FloatString")
	}
	d := ctis.Dependency{}
	for i := 0; i < 40; i++ {
		AddDepProperty(&d, "k"+strings.Repeat("x", i), "v")
	}
	if len(d.Properties) != MaxDepProperties {
		t.Errorf("properties = %d", len(d.Properties))
	}
}
