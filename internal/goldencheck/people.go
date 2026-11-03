package goldencheck

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// NoPeopleInGoldens fails when a golden or result file of dir holds a
// person, an e-mail address or a runner path of the SBOM fixtures.
func NoPeopleInGoldens(t *testing.T, dir string) {
	t.Helper()
	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if !strings.HasSuffix(f.Name(), ".golden.json") && !strings.HasSuffix(f.Name(), ".result.json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, f.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range []string{"jane@example.com", "maint@example.com", "researcher@example.com", "Jane Example", "/home/runner", "send [[[["} {
			if bytes.Contains(b, []byte(s)) {
				t.Errorf("%s holds %q", f.Name(), s)
			}
		}
	}
}
