package importer

import (
	"archive/zip"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// Bundle fixtures: one directory per layout under testdata/importers/reconftw
// (v4, v3). Each is zipped under a leading directory, as a person zips a
// recon run, and read with OpenBundleZip and ParseBundle, so the archive
// guards are part of every case.

const bundleFixtureRoot = fixtureRoot + "/reconftw"

// bundlePrefix is the leading directory the fixtures are zipped under.
const bundlePrefix = "Recon/example.com/"

// zipTree zips the files of a directory under prefix.
func zipTree(t *testing.T, dir, prefix string) []byte {
	t.Helper()
	files := map[string][]byte{}
	err := filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		b, err := os.ReadFile(p)
		files[prefix+filepath.ToSlash(rel)] = b
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return zipFiles(t, files)
}

// zipFiles zips named contents, in name order.
func zipFiles(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, n := range names {
		w, err := zw.Create(n)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(files[n]); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func parseZipBundle(t *testing.T, z []byte, opts Options) (*Result, []string, error) {
	t.Helper()
	files, err := OpenBundleZip(bytes.NewReader(z), int64(len(z)), opts.Bundle)
	if err != nil {
		return nil, nil, err
	}
	return parseBundle(context.Background(), files, opts)
}

func bundleOpts() Options { return Options{Now: fixedNow, ReportID: "import-test"} }

// bundleLayouts are the fixture directories and the spec each is read with.
var bundleLayouts = map[string]Format{"v4": FormatReconFTW, "v3": formatReconFTWv3}

func TestBundle_Golden(t *testing.T) {
	for gen := range bundleLayouts {
		t.Run(gen, func(t *testing.T) {
			z := zipTree(t, filepath.Join(bundleFixtureRoot, gen), bundlePrefix)
			res, _, err := parseZipBundle(t, z, bundleOpts())
			if err != nil {
				t.Fatal(err)
			}
			if err := res.Report.Validate(); err != nil {
				t.Fatalf("report is not valid CTIS: %v", err)
			}
			if res.Layout != gen {
				t.Fatalf("layout %q, want %q", res.Layout, gen)
			}
			if len(res.Unmapped) > 0 {
				t.Errorf("fixture holds unmapped paths: %v", res.Unmapped)
			}
			compareGolden(t, filepath.Join(bundleFixtureRoot, gen+".golden.json"), res.Report)
			compareGolden(t, filepath.Join(bundleFixtureRoot, gen+".result.json"), struct {
				Format   Format        `json:"format"`
				Layout   string        `json:"layout"`
				Stats    Stats         `json:"stats"`
				Issues   []Issue       `json:"issues,omitempty"`
				Skipped  []SkippedPath `json:"skipped,omitempty"`
				Unmapped []string      `json:"unmapped,omitempty"`
			}{res.Format, res.Layout, res.Stats, res.Issues, res.Skipped, res.Unmapped})
		})
	}
}

// bundleObserved returns the paths every bundle fixture holds, by spec.
func bundleObserved(t *testing.T) map[Format]map[string]bool {
	t.Helper()
	out := map[Format]map[string]bool{}
	for gen, spec := range bundleLayouts {
		z := zipTree(t, filepath.Join(bundleFixtureRoot, gen), bundlePrefix)
		_, paths, err := parseZipBundle(t, z, bundleOpts())
		if err != nil {
			t.Fatal(err)
		}
		out[spec] = map[string]bool{}
		for _, p := range paths {
			out[spec][p] = true
		}
	}
	return out
}
