package importer

import (
	"strings"

	"github.com/openctemio/ctis"
)

// The package graph of one trivy result (--list-all-pkgs): it tells each
// vulnerability whether its package is a direct dependency, the path that
// brings it in, and where the lockfile declares it.

const (
	// maxDependencyPath bounds vulnerability.dependency_path. A longer path
	// keeps its first entry (the direct dependency or the project) and the
	// entries nearest the vulnerable package.
	maxDependencyPath = 32
	// maxGraphVisit bounds the nodes one path search visits.
	maxGraphVisit = 200_000
)

type trivyGraph struct {
	byID    map[string]*trivyPackage
	parents map[string][]string
	paths   map[string][]string
}

func newTrivyGraph(pkgs []trivyPackage) *trivyGraph {
	g := &trivyGraph{byID: make(map[string]*trivyPackage, len(pkgs)), parents: map[string][]string{}, paths: map[string][]string{}}
	for i := range pkgs {
		if id := pkgs[i].ID; id != "" {
			if _, dup := g.byID[id]; !dup {
				g.byID[id] = &pkgs[i]
			}
		}
	}
	for i := range pkgs {
		p := &pkgs[i]
		if p.ID == "" {
			continue
		}
		for _, on := range p.DependsOn {
			if _, ok := g.byID[on]; ok && on != p.ID {
				g.parents[on] = append(g.parents[on], p.ID)
			}
		}
	}
	return g
}

// trivyRelationship is the package's relationship as trivy states it:
// root, workspace, direct or indirect; older trivy only sets Indirect.
func trivyRelationship(p *trivyPackage) string {
	if r := line(strings.ToLower(p.Relationship), 32); r != "" && r != "unknown" {
		return r
	}
	if p.Indirect != nil {
		if *p.Indirect {
			return "indirect"
		}
		return "direct"
	}
	return ""
}

// lookup finds the vulnerability's package by its id, else by name and
// version.
func (g *trivyGraph) lookup(v *trivyVuln) *trivyPackage {
	if p := g.byID[v.PkgID]; p != nil {
		return p
	}
	if v.PkgName != "" && v.InstalledVersion != "" {
		return g.byID[v.PkgName+"@"+v.InstalledVersion]
	}
	return nil
}

// place fills what the package graph knows about a vulnerability's package:
// is_direct, dependency_path, the PURL when the record has none, and the
// lockfile line that declares the package.
func (g *trivyGraph) place(f *ctis.Finding, v *trivyVuln, file string) {
	vd := f.Vulnerability
	if vd == nil || len(g.byID) == 0 {
		return
	}
	p := g.lookup(v)
	if p == nil {
		return
	}
	if vd.PURL == "" && p.Identifier != nil {
		vd.PURL = sanePURL(p.Identifier.PURL)
	}
	if rel := trivyRelationship(p); rel != "" {
		vd.IsDirect = rel == "direct"
		vd.DependencyPath = g.path(p.ID)
	}
	if f.Location == nil && file != "" {
		f.Location = &ctis.FindingLocation{Path: file}
		for _, l := range p.Locations {
			if l.StartLine > 0 {
				f.Location.StartLine, f.Location.EndLine = l.StartLine, nonNeg(l.EndLine)
				break
			}
		}
	}
}

// terminal reports whether a path search stops at a package: the project
// itself, a direct dependency the project does not list as a package, or a
// package nothing depends on.
func (g *trivyGraph) terminal(id string) bool {
	switch trivyRelationship(g.byID[id]) {
	case "root", "workspace":
		return true
	case "direct":
		for _, par := range g.parents[id] {
			if r := trivyRelationship(g.byID[par]); r == "root" || r == "workspace" {
				return false
			}
		}
		return true
	}
	return len(g.parents[id]) == 0
}

// path is the shortest chain of package ids from the project (or the direct
// dependency) to the package, the package last.
func (g *trivyGraph) path(id string) []string {
	if p, ok := g.paths[id]; ok {
		return p
	}
	prev := map[string]string{id: ""}
	queue := []string{id}
	end := ""
	for len(queue) > 0 && len(prev) <= maxGraphVisit {
		cur := queue[0]
		queue = queue[1:]
		if g.terminal(cur) {
			end = cur
			break
		}
		for _, par := range g.parents[cur] {
			if _, seen := prev[par]; !seen {
				prev[par] = cur
				queue = append(queue, par)
			}
		}
	}
	var out []string
	if end != "" {
		for n := end; ; n = prev[n] {
			out = append(out, line(n, capShort))
			if n == id {
				break
			}
		}
		if len(out) > maxDependencyPath {
			out = append(out[:1:1], out[len(out)-maxDependencyPath+1:]...)
		}
	}
	g.paths[id] = out
	return out
}
