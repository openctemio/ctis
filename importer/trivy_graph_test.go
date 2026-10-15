package importer

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/openctemio/ctis"
)

func pkg(id, rel string, on ...string) trivyPackage {
	return trivyPackage{ID: id, Name: id, Relationship: rel, DependsOn: on}
}

func TestTrivyGraph_Path(t *testing.T) {
	yes, no := true, false
	cases := map[string]struct {
		pkgs []trivyPackage
		id   string
		want []string
	}{
		"direct without root": {[]trivyPackage{pkg("a@1", "direct", "b@1"), pkg("b@1", "indirect")}, "a@1", []string{"a@1"}},
		"transitive":          {[]trivyPackage{pkg("a@1", "direct", "b@1"), pkg("b@1", "indirect", "c@1"), pkg("c@1", "indirect")}, "c@1", []string{"a@1", "b@1", "c@1"}},
		"root first": {[]trivyPackage{pkg("app@0", "root", "a@1"), pkg("a@1", "direct", "b@1"), pkg("b@1", "indirect")},
			"b@1", []string{"app@0", "a@1", "b@1"}},
		"shortest of two": {[]trivyPackage{pkg("a@1", "direct", "b@1", "d@1"), pkg("b@1", "indirect", "c@1"), pkg("c@1", "indirect", "d@1"), pkg("d@1", "indirect")},
			"d@1", []string{"a@1", "d@1"}},
		"direct also below another": {[]trivyPackage{pkg("a@1", "direct", "b@1"), pkg("b@1", "direct")}, "b@1", []string{"b@1"}},
		"cycle without a top":       {[]trivyPackage{pkg("a@1", "indirect", "b@1"), pkg("b@1", "indirect", "a@1")}, "a@1", nil},
		"older trivy: Indirect only": {[]trivyPackage{{ID: "a@1", Indirect: &no, DependsOn: []string{"b@1"}}, {ID: "b@1", Indirect: &yes}},
			"b@1", []string{"a@1", "b@1"}},
		"unknown reference ignored": {[]trivyPackage{pkg("a@1", "direct", "zz@9", "b@1"), pkg("b@1", "indirect")}, "b@1", []string{"a@1", "b@1"}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := newTrivyGraph(tc.pkgs).path(tc.id); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("path = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestTrivyGraph_PathBounded(t *testing.T) {
	const n = 100
	pkgs := []trivyPackage{pkg("p0@1", "direct", "p1@1")}
	for i := 1; i < n; i++ {
		var on []string
		if i < n-1 {
			on = []string{fmt.Sprintf("p%d@1", i+1)}
		}
		pkgs = append(pkgs, pkg(fmt.Sprintf("p%d@1", i), "indirect", on...))
	}
	got := newTrivyGraph(pkgs).path(fmt.Sprintf("p%d@1", n-1))
	if len(got) != maxDependencyPath || got[0] != "p0@1" || got[len(got)-1] != fmt.Sprintf("p%d@1", n-1) || got[1] != fmt.Sprintf("p%d@1", n-maxDependencyPath+1) {
		t.Fatalf("bounded path = %v", got)
	}
}

func TestTrivyGraph_Place(t *testing.T) {
	g := newTrivyGraph([]trivyPackage{
		{ID: "a@1", Name: "a", Relationship: "direct", DependsOn: []string{"b@2"}},
		{ID: "b@2", Name: "b", Relationship: "indirect", Identifier: &trivyPkgID{PURL: "pkg:npm/b@2"},
			Locations: []trivyLocation{{StartLine: 7, EndLine: 9}}},
	})
	// Found by name and version when the record has no PkgID.
	f := ctis.Finding{Vulnerability: &ctis.VulnerabilityDetails{}}
	g.place(&f, &trivyVuln{PkgName: "b", InstalledVersion: "2"}, "package-lock.json")
	vd := f.Vulnerability
	if vd.IsDirect || !reflect.DeepEqual(vd.DependencyPath, []string{"a@1", "b@2"}) || vd.PURL != "pkg:npm/b@2" {
		t.Fatalf("vulnerability = %+v", vd)
	}
	if f.Location == nil || f.Location.Path != "package-lock.json" || f.Location.StartLine != 7 || f.Location.EndLine != 9 {
		t.Fatalf("location = %+v", f.Location)
	}
	// A package path the record names is kept.
	f = ctis.Finding{Vulnerability: &ctis.VulnerabilityDetails{}, Location: &ctis.FindingLocation{Path: "app.jar"}}
	g.place(&f, &trivyVuln{PkgID: "a@1"}, "package-lock.json")
	if !f.Vulnerability.IsDirect || f.Location.Path != "app.jar" {
		t.Fatalf("direct finding = %+v %+v", f.Vulnerability, f.Location)
	}
	// An unknown package leaves the finding as it was.
	f = ctis.Finding{Vulnerability: &ctis.VulnerabilityDetails{}}
	g.place(&f, &trivyVuln{PkgID: "zz@1"}, "package-lock.json")
	if f.Location != nil || f.Vulnerability.DependencyPath != nil {
		t.Fatalf("unknown package placed: %+v", f)
	}
}
