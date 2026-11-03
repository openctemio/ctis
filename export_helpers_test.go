package ctis

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// Round-trip test helpers, shared by the exporter tests of this package and
// of package ctis_test (the CycloneDX test reads its output back with the
// importer, which imports this package).

// exportLosses is a fixture's sidecar of documented accepted losses:
// testdata/export/<format>/<fixture>.losses.json. Each member is a path into
// the report JSON ("findings[].references", "dependencies[].properties.uid")
// that the round trip does not preserve; the comparison drops it on both
// sides. docs/exporters.md lists the same losses per format.
type exportLosses struct {
	Fixture string `json:"fixture"`
	Losses  []struct {
		Member string `json:"member"`
		Reason string `json:"reason"`
	} `json:"losses"`
}

// ExportRoundTripDiff compares two reports (or any JSON values) after
// dropping the accepted losses listed in the sidecar file (relative to
// testdata/export; "" for none) and reports the differing paths.
func ExportRoundTripDiff(t *testing.T, want, got any, sidecar string) []string {
	t.Helper()
	var members []string
	if sidecar != "" {
		b, err := os.ReadFile(filepath.Join("testdata", "export", sidecar))
		if err != nil {
			t.Fatal(err)
		}
		var l exportLosses
		if err := json.Unmarshal(b, &l); err != nil {
			t.Fatalf("%s: %v", sidecar, err)
		}
		for _, m := range l.Losses {
			if m.Reason == "" {
				t.Errorf("%s: loss %q has no reason", sidecar, m.Member)
			}
			members = append(members, m.Member)
		}
	}
	a, b := toTree(t, want), toTree(t, got)
	for _, m := range members {
		a = dropMember(a, splitMember(m))
		b = dropMember(b, splitMember(m))
	}
	var diffs []string
	diffTree("", a, b, &diffs)
	return diffs
}

func toTree(t *testing.T, v any) any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// dropMember removes the member at path; "x[]" walks every element of x.
func dropMember(v any, path []string) any {
	if len(path) == 0 {
		return v
	}
	m, ok := v.(map[string]any)
	if !ok {
		return v
	}
	key := path[0]
	if i := strings.IndexByte(key, '['); i > 0 && strings.HasSuffix(key, "]") && strings.Contains(key, "=") {
		// "list[a.b=value]" drops the elements of list whose member a.b
		// is value.
		sel, want, _ := strings.Cut(key[i+1:len(key)-1], "=")
		arr, ok := m[key[:i]].([]any)
		if !ok {
			return m
		}
		kept := []any{}
		for _, el := range arr {
			if fmt.Sprint(memberAt(el, strings.Split(sel, "."))) != want {
				kept = append(kept, el)
			}
		}
		m[key[:i]] = kept
		return m
	}
	each := strings.HasSuffix(key, "[]")
	key = strings.TrimSuffix(key, "[]")
	if len(path) == 1 && !each {
		delete(m, key)
		return m
	}
	child, ok := m[key]
	if !ok {
		return m
	}
	if each {
		arr, ok := child.([]any)
		if !ok {
			return m
		}
		if len(path) == 1 {
			delete(m, key)
			return m
		}
		for i := range arr {
			arr[i] = dropMember(arr[i], path[1:])
		}
		return m
	}
	m[key] = dropMember(child, path[1:])
	return m
}

// splitMember splits a member path on the dots outside brackets.
func splitMember(m string) []string {
	var out []string
	depth, start := 0, 0
	for i, c := range m {
		switch c {
		case '[':
			depth++
		case ']':
			depth--
		case '.':
			if depth == 0 {
				out = append(out, m[start:i])
				start = i + 1
			}
		}
	}
	return append(out, m[start:])
}

// memberAt returns the member at path, or nil.
func memberAt(v any, path []string) any {
	for _, k := range path {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[k]
	}
	return v
}

func diffTree(path string, a, b any, out *[]string) {
	am, aok := a.(map[string]any)
	bm, bok := b.(map[string]any)
	if aok && bok {
		keys := map[string]bool{}
		for k := range am {
			keys[k] = true
		}
		for k := range bm {
			keys[k] = true
		}
		sorted := make([]string, 0, len(keys))
		for k := range keys {
			sorted = append(sorted, k)
		}
		sort.Strings(sorted)
		for _, k := range sorted {
			diffTree(path+"."+k, am[k], bm[k], out)
		}
		return
	}
	aa, aok := a.([]any)
	ba, bok := b.([]any)
	if aok && bok && len(aa) == len(ba) {
		for i := range aa {
			diffTree(fmt.Sprintf("%s[%d]", path, i), aa[i], ba[i], out)
		}
		return
	}
	if !reflect.DeepEqual(a, b) {
		ja, _ := json.Marshal(a)
		jb, _ := json.Marshal(b)
		*out = append(*out, fmt.Sprintf("%s: want %s, got %s", path, ja, jb))
	}
}

// ExportCheckGolden is checkGolden for raw bytes (an exporter's output),
// usable from package ctis_test.
func ExportCheckGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	if len(got) == 0 || got[len(got)-1] != '\n' {
		got = append(append([]byte(nil), got...), '\n')
	}
	path := filepath.Join("testdata", name)
	if *updateGolden {
		if err := os.WriteFile(path, got, 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test -run %s -update to create it)", err, t.Name())
	}
	if string(got) != string(want) {
		t.Errorf("%s differs from the exporter output; rerun with -update after checking the change.\n got:\n%s", path, got)
	}
}

func TestExportDropMember(t *testing.T) {
	v := map[string]any{"a": []any{map[string]any{"b": 1, "c": 2}}, "d": map[string]any{"e": 3}, "f": []any{1}}
	v2 := dropMember(v, []string{"a[]", "b"}).(map[string]any)
	v2 = dropMember(v2, []string{"d", "e"}).(map[string]any)
	v2 = dropMember(v2, []string{"f[]"}).(map[string]any)
	v2 = dropMember(v2, []string{"missing", "x"}).(map[string]any)
	v2 = dropMember(v2, []string{"a", "x"}).(map[string]any)
	v2["g"] = []any{map[string]any{"s": map[string]any{"t": "x"}}, map[string]any{"s": map[string]any{"t": "y"}}}
	v2 = dropMember(v2, []string{"g[s.t=x]"}).(map[string]any)
	v2 = dropMember(v2, []string{"d[s=x]"}).(map[string]any)
	got, _ := json.Marshal(v2)
	if string(got) != `{"a":[{"c":2}],"d":{},"g":[{"s":{"t":"y"}}]}` {
		t.Fatalf("dropMember: %s", got)
	}
	var diffs []string
	diffTree("", map[string]any{"x": []any{1, 2}}, map[string]any{"x": []any{1}}, &diffs)
	if len(diffs) != 1 {
		t.Fatalf("diffTree: %v", diffs)
	}
}
