package importer

import "testing"

func TestDetect(t *testing.T) {
	cases := []struct {
		in   string
		want Format
		ok   bool
	}{
		{"\xEF\xBB\xBF<?xml version=\"1.0\"?>\n<!-- c -->\n<NessusClientData_v2>", FormatNessus, true},
		{"<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n<!DOCTYPE HOST_LIST_VM_DETECTION_OUTPUT SYSTEM \"https://qualysapi.qualys.com/api/2.0/fo/asset/host/vm/detection/host_list_vm_detection_output.dtd\">\n<HOST_LIST_VM_DETECTION_OUTPUT>", FormatQualys, true},
		{"<KNOWLEDGE_BASE_VULN_LIST_OUTPUT>", FormatQualysKB, true},
		{"<html>", "", false},
		{`{"bomFormat": "CycloneDX", "specVersion": "1.6"}`, FormatCycloneDX, true},
		{`{"spdxVersion": "SPDX-2.3"}`, FormatSPDX, true},
		{`{"@context": "https://openvex.dev/ns/v0.2.0", "statements": []}`, FormatOpenVEX, true},
		{`{"document": {"category": "csaf_vex", "csaf_version": "2.0"}, "product_tree": {}}`, FormatCSAF, true},
		{`[{"document": {"csaf_version": "2.0"}}]`, FormatCSAF, true},
		{`{"results": [{"source": {"path": "go.mod"}}]}`, FormatOSV, true},
		{`{"findings": [{"title": "x"}]}`, FormatDefectDojo, true},
		// Cut in the middle: what was read decides.
		{`{"findings": [{"title": "x", "descr`, FormatDefectDojo, true},
		// A nested "findings" is not a top-level member.
		{`{"x": {"findings": []}}`, "", false},
		{`{"x": {"csaf_version": "2.0"}}`, "", false},
		{``, "", false},
		{`   `, "", false},
		{`plain text`, "", false},
		{`{"bomFormat": "SPDX"}`, "", false},
	}
	for _, c := range cases {
		got, ok := Detect([]byte(c.in))
		if got != c.want || ok != c.ok {
			t.Errorf("Detect(%.60q) = %q, %v; want %q, %v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestPathMatch(t *testing.T) {
	cases := []struct {
		pattern, path string
		want          bool
	}{
		{"/a/b", "/a/b", true},
		{"/a/*", "/a/b", true},
		{"/a/*", "/a/b/c", false},
		{"/a/**", "/a", true},
		{"/a/**", "/a/b/c", true},
		{"/a/**", "/ab", false},
		{"/a/tag[cpe-*]", "/a/tag[cpe-0]", true},
		{"/a/tag[cpe-*]", "/a/tag[cpe]", false},
		{"/a/x*y*z", "/a/xyz", true},
		{"/a/x*y*z", "/a/xzy", false},
	}
	for _, c := range cases {
		if got := pathMatch(c.pattern, c.path); got != c.want {
			t.Errorf("pathMatch(%q, %q) = %v, want %v", c.pattern, c.path, got, c.want)
		}
	}
}

func TestSpecCheck(t *testing.T) {
	s := Spec{Fields: []Field{{Path: "a", Target: "x"}, {Path: "/b"}, {Path: "/c", Target: "x", Ignored: "y"}, {Path: "/d", Target: "x"}, {Path: "/d", Target: "x"}}}
	if got := len(s.check()); got != 4 {
		t.Errorf("check found %d problems, want 4: %v", got, s.check())
	}
	if (Coverage{}).Percent() != 0 {
		t.Error("empty coverage is not 0%")
	}
}
