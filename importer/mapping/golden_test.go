package mapping

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openctemio/ctis"
)

var update = flag.Bool("update", false, "rewrite the golden files")

var fixedNow = func() time.Time { return time.Date(2026, 10, 7, 8, 0, 0, 0, time.UTC) }

func runSample(t *testing.T, dir string) (report, stats []byte) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "mapping.json"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := Load(raw)
	if err != nil {
		t.Fatal(err)
	}
	inputs, _ := filepath.Glob(filepath.Join(dir, "input.*"))
	if len(inputs) != 1 {
		t.Fatalf("%s: want one input file", dir)
	}
	in, err := os.ReadFile(inputs[0])
	if err != nil {
		t.Fatal(err)
	}
	r, st, err := m.Apply(context.Background(), bytes.NewReader(in), Options{Now: fixedNow, Tool: &ctis.Tool{Name: filepath.Base(dir), Version: "1.0.0"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("%s: report does not validate: %v", dir, err)
	}
	report, err = json.MarshalIndent(r, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	stats, err = json.MarshalIndent(st, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(report, '\n'), append(stats, '\n')
}

func TestGoldenSamples(t *testing.T) {
	dirs, _ := filepath.Glob("testdata/*/mapping.json")
	if len(dirs) < 3 {
		t.Fatalf("want 3 samples, have %d", len(dirs))
	}
	for _, d := range dirs {
		dir := filepath.Dir(d)
		t.Run(filepath.Base(dir), func(t *testing.T) {
			report, stats := runSample(t, dir)
			for name, got := range map[string][]byte{"expect.ctis.json": report, "expect.stats.json": stats} {
				golden := filepath.Join(dir, name)
				if *update {
					if err := os.WriteFile(golden, got, 0o644); err != nil {
						t.Fatal(err)
					}
				}
				want, err := os.ReadFile(golden)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got, want) {
					t.Fatalf("output differs from %s; run go test ./importer/mapping -run TestGoldenSamples -update\n%s", golden, got)
				}
			}
			// Determinism: a second run is byte-identical.
			r2, s2 := runSample(t, dir)
			if !bytes.Equal(report, r2) || !bytes.Equal(stats, s2) {
				t.Fatal("two runs differ")
			}
		})
	}
}
