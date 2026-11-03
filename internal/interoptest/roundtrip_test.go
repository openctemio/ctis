package interoptest

import (
	"encoding/json"
	"testing"
)

func TestDropMember(t *testing.T) {
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
