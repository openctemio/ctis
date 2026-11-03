package ctis

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestCorrelationKeyVectors(t *testing.T) {
	raw, err := os.ReadFile("conformance/v2/correlation/correlation.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Recipe string `json:"recipe"`
		Cases  []struct {
			Name            string          `json:"name"`
			AssetKey        string          `json:"asset_key"`
			Tool            string          `json:"tool"`
			Finding         json.RawMessage `json:"finding"`
			VulnerabilityID string          `json:"vulnerability_id"`
			LocationKey     string          `json:"location_key"`
			Expected        string          `json:"expected"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if f.Recipe != "ctis-ck/1" || len(f.Cases) < 10 {
		t.Fatalf("unexpected vector file: %q, %d cases", f.Recipe, len(f.Cases))
	}
	seen := map[string]string{}
	for _, c := range f.Cases {
		dec := json.NewDecoder(bytes.NewReader(c.Finding))
		dec.DisallowUnknownFields()
		var fi Finding
		if err := dec.Decode(&fi); err != nil {
			t.Errorf("%s: finding: %v", c.Name, err)
			continue
		}
		if got := LocationKey(&fi); got != c.LocationKey {
			t.Errorf("%s: location key %q, want %q", c.Name, got, c.LocationKey)
		}
		got := CorrelationKeyForTool(c.AssetKey, c.Tool, &fi)
		if got != c.Expected {
			t.Errorf("%s: got %s, want %s", c.Name, got, c.Expected)
		}
		id := strings.Join([]string{c.AssetKey, c.VulnerabilityID, c.LocationKey}, "\x1e")
		if prev, ok := seen[got]; ok && prev != id {
			t.Errorf("%s: collides with a case of different parts", c.Name)
		}
		seen[got] = id
	}
}

func TestCorrelationKeyShape(t *testing.T) {
	f := &Finding{RuleID: "r", Location: &FindingLocation{Path: "a/b.go"}}
	k := CorrelationKeyForTool("asset", "tool", f)
	if !strings.HasPrefix(k, CorrelationKeyPrefix) || len(k) != len(CorrelationKeyPrefix)+64 {
		t.Fatalf("shape %q", k)
	}
	if k != CorrelationKeyForTool("asset", "tool", f) {
		t.Error("not deterministic")
	}
	if CorrelationKey("asset", f) == "" || CorrelationKey("asset", nil) != "" || CorrelationKey("", f) != "" {
		t.Error("nil finding or empty asset key must give no key")
	}
	if k == CorrelationKeyForTool("asset", "other", f) {
		t.Error("the tool is part of the key for a finding without a vulnerability id")
	}
	// Parts cannot shift into each other.
	a := CorrelationKeyForTool("a:b", "t", &Finding{RuleID: "r"})
	b := CorrelationKeyForTool("a", "t", &Finding{RuleID: "b:r"})
	if a == b {
		t.Error("asset key and id shifted")
	}
}
