package mapping

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// FuzzApply runs each sample mapping over hostile input: it must not panic,
// must stay deterministic, must stay within the caps, and every record it
// emits must validate.
func FuzzApply(f *testing.F) {
	var maps []*Mapping
	dirs, _ := filepath.Glob("testdata/*/mapping.json")
	for _, d := range dirs {
		raw, err := os.ReadFile(d)
		if err != nil {
			f.Fatal(err)
		}
		m, err := Load(raw)
		if err != nil {
			f.Fatal(err)
		}
		maps = append(maps, m)
		inputs, _ := filepath.Glob(filepath.Join(filepath.Dir(d), "input.*"))
		for _, in := range inputs {
			if b, err := os.ReadFile(in); err == nil {
				f.Add(b)
			}
		}
	}
	f.Add([]byte(`{"port": 1e999, "ip": "\u0000"}`))
	f.Add([]byte(`[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[`))
	opts := Options{Now: fixedNow, MaxRecords: 500, MaxOutputs: 500, MaxRecordBytes: 64 << 10, MaxInputBytes: 1 << 20}
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, m := range maps {
			r1, s1, err1 := m.Apply(context.Background(), bytes.NewReader(data), opts)
			r2, s2, err2 := m.Apply(context.Background(), bytes.NewReader(data), opts)
			if (err1 == nil) != (err2 == nil) {
				t.Fatal("non-deterministic error")
			}
			if err1 != nil {
				continue
			}
			a, _ := json.Marshal(r1)
			b, _ := json.Marshal(r2)
			if !bytes.Equal(a, b) || s1.Records != s2.Records {
				t.Fatal("two runs differ")
			}
			if s1.Records > opts.MaxRecords || len(r1.Assets)+len(r1.Findings)+len(r1.Dependencies) > opts.MaxOutputs {
				t.Fatalf("cap breached: %+v", s1)
			}
			if err := r1.Validate(); err != nil {
				t.Fatalf("emitted an invalid report: %v", err)
			}
		}
	})
}

// FuzzLoad: a hostile mapping file is refused or loads; never a panic.
func FuzzLoad(f *testing.F) {
	dirs, _ := filepath.Glob("testdata/*/mapping.json")
	for _, d := range dirs {
		if b, err := os.ReadFile(d); err == nil {
			f.Add(b)
		}
	}
	f.Add([]byte(`{"apiVersion": "openctem.io/mapping/v1", "source": "json", "each": "/a[0][1]/~1", "records": []}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := Load(data)
		if err != nil {
			return
		}
		if m.Digest() == "" {
			t.Fatal("loaded without a digest")
		}
		_, _, _ = m.Apply(context.Background(), bytes.NewReader(data), Options{Now: fixedNow, MaxRecords: 50})
	})
}
