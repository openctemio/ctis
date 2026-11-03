package weburl

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// The language-neutral copy of the corpus (conformance/v2/weburl/urls.json)
// stays equal to testdata/urls.golden.json without its redaction column, so
// a change of Parse updates both.
func TestConformanceCopyOfCorpus(t *testing.T) {
	var golden []goldenCase
	raw, err := os.ReadFile(filepath.Join("testdata", "urls.golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &golden); err != nil {
		t.Fatal(err)
	}
	var conf struct {
		Cases []goldenCase `json:"cases"`
	}
	raw, err = os.ReadFile(filepath.Join("..", "conformance", "v2", "weburl", "urls.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &conf); err != nil {
		t.Fatal(err)
	}
	if len(conf.Cases) != len(golden) {
		t.Fatalf("conformance copy has %d cases, golden %d", len(conf.Cases), len(golden))
	}
	for i := range golden {
		g, c := golden[i], conf.Cases[i]
		g.Redacted = ""
		if len(g.Params) == 0 {
			g.Params = nil
		}
		if len(c.Params) == 0 {
			c.Params = nil
		}
		if !reflect.DeepEqual(g, c) {
			t.Errorf("case %d: golden %+v, conformance %+v", i, g, c)
		}
	}
}
