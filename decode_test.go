package ctis

import (
	"reflect"
	"strings"
	"testing"
)

const decodeBase = `"metadata":{"id":"` + testReportID + `","generated_at":"2026-11-03T00:00:00Z"}`

func decodeAtString(t *testing.T, doc string, recvMinor int) (Report, Unknown, error) {
	t.Helper()
	return decodeAt([]byte(doc), SchemaMajor, recvMinor)
}

func unknownPaths(u Unknown, kind UnknownKind) []string {
	var out []string
	for _, e := range u.Entries {
		if e.Kind == kind {
			out = append(out, e.Path)
		}
	}
	return out
}

func TestDecodeSameMinorIsStrict(t *testing.T) {
	// A typo in a document of the receiver's own minor is an error.
	doc := `{"version":"2.6",` + decodeBase + `,"findings":[{"type":"secret","title":"t","sevrity":"high","severity":"high"}]}`
	if _, _, err := decodeAtString(t, doc, 6); err == nil {
		t.Fatal("same-minor typo accepted")
	}
	// Older minor: strict too.
	doc = `{"version":"2.2",` + decodeBase + `,"surprise":1}`
	if _, _, err := decodeAtString(t, doc, 6); err == nil {
		t.Fatal("older-minor unknown member accepted")
	}
	// Clean document: no unknowns.
	doc = `{"version":"2.6",` + decodeBase + `}`
	r, u, err := decodeAtString(t, doc, 6)
	if err != nil || !u.Empty() || r.Version != "2.6" {
		t.Fatalf("clean document: %v %+v", err, u)
	}
}

func TestDecodeNewerMinorIgnoresUnknownMembers(t *testing.T) {
	doc := `{"version":"2.9",` + decodeBase + `,"future_member":{"a":1},
		"assets":[{"id":"a","type":"host","value":"h","future_asset_member":true,"properties":{"kept":1}}],
		"findings":[{"type":"secret","title":"t","severity":"high","asset_ref":"a","vulnerability":{"future_vuln":"x"}}]}`
	r, u, err := decodeAtString(t, doc, 6)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/assets/0/future_asset_member", "/findings/0/vulnerability/future_vuln", "/future_member"}
	if got := unknownPaths(u, UnknownMember); !reflect.DeepEqual(got, want) {
		t.Errorf("ignored members = %v, want %v", got, want)
	}
	if r.Assets[0].Properties["kept"] == nil {
		t.Error("free-form properties must pass through untouched")
	}
	if err := r.Validate(); err != nil {
		t.Errorf("leniently decoded report does not validate: %v", err)
	}
}

func TestDecodeNewerMinorMapsUnknownEnums(t *testing.T) {
	doc := `{"version":"2.42",
		"assets":[
			{"id":"a","type":"quantum_widget","value":"q","environment":"preprod","criticality":"extreme","owners":[{"kind":"robot","ref":"r"},{"kind":"team","ref":"t","role":"janitor"}]},
			{"id":"b","type":"host","value":"h","state":"gone","state_reason":"moon_phase"}
		],
		"findings":[
			{"type":"secret","title":"keep","severity":"apocalyptic","status":"pondering","asset_ref":"b","validation":{"status":"half_exploited"}},
			{"type":"telepathy","title":"drop","severity":"high","asset_ref":"b"}
		],
		"relationships":[{"type":"entangled_with","from_ref":"a","to_ref":"b"}],
		"metadata":{"id":"` + testReportID + `","generated_at":"2026-11-03T00:00:00Z","targets":[
			{"target":"x.example","state":"done"},
			{"target":"y.example","state":"failed","class":"cosmic_rays"},
			{"target":"z.example","state":"teleported"}
		]}}`
	r, u, err := decodeAtString(t, doc, 6)
	if err != nil {
		t.Fatal(err)
	}
	a := r.Assets[0]
	if a.Type != AssetTypeUnclassified || a.Environment != EnvironmentUnknown || a.Criticality != "" {
		t.Errorf("asset fallbacks: type %q env %q criticality %q", a.Type, a.Environment, a.Criticality)
	}
	if len(a.Owners) != 1 || a.Owners[0].Role != "" {
		t.Errorf("owners: %+v (unknown kind drops the owner, unknown role removes the role)", a.Owners)
	}
	if r.Assets[1].State != "" || r.Assets[1].StateReason != "" {
		t.Errorf("gone without a known reason must not stay gone: %+v", r.Assets[1])
	}
	if len(r.Findings) != 1 || r.Findings[0].Title != "keep" {
		t.Fatalf("findings: %+v", r.Findings)
	}
	f := r.Findings[0]
	if f.Severity != SeverityUnknown || f.Status != "" || f.Validation != nil {
		t.Errorf("finding fallbacks: severity %q status %q validation %+v", f.Severity, f.Status, f.Validation)
	}
	if len(r.Relationships) != 0 {
		t.Errorf("relationship of an unknown type kept: %+v", r.Relationships)
	}
	if len(r.Metadata.Targets) != 1 || r.Metadata.Targets[0].Target != "x.example" {
		t.Errorf("targets with an unknown class or state must be dropped, never read as done: %+v", r.Metadata.Targets)
	}
	for _, e := range u.Entries {
		if e.Path == "/findings/0/severity" && (e.Kind != UnknownEnumValue || e.Value != "apocalyptic" || e.Fallback != "unknown") {
			t.Errorf("severity entry: %+v", e)
		}
	}
	dropped := unknownPaths(u, UnknownDropped)
	for _, p := range []string{"/findings/1", "/relationships/0", "/assets/0/owners/0", "/metadata/targets/1", "/metadata/targets/2"} {
		if !contains(dropped, p) {
			t.Errorf("%s not listed as dropped: %v", p, dropped)
		}
	}
	if err := r.Validate(); err != nil {
		t.Errorf("leniently decoded report does not validate: %v", err)
	}
}

func TestDecodeRejectsOtherMajors(t *testing.T) {
	for _, v := range []string{"1.6", "0.9", "3.1"} {
		doc := `{"version":"` + v + `",` + decodeBase + `}`
		if _, _, err := decodeAtString(t, doc, 6); err == nil {
			t.Errorf("version %s accepted", v)
		}
	}
	for _, doc := range []string{`{` + decodeBase + `}`, `{"version":"2.x",` + decodeBase + `}`, `{"version":1,` + decodeBase + `}`, `[]`} {
		if _, _, err := decodeAtString(t, doc, 6); err == nil {
			t.Errorf("%s accepted", doc)
		}
	}
	// The real entry point: this module's major is the only one it reads.
	if _, _, err := Decode(strings.NewReader(`{"version":"9.0",` + decodeBase + `}`)); err == nil {
		t.Error("Decode accepted major 9")
	}
}

func TestDecodeRejectsOtherMajorsSynthetic(t *testing.T) {
	// A receiver of major 2 (synthetic) refuses 1.x and 3.x documents: there
	// is no conversion between majors.
	for _, v := range []string{"1.6", "3.0"} {
		if _, _, err := decodeAt([]byte(`{"version":"`+v+`",`+decodeBase+`}`), 2, 0); err == nil {
			t.Errorf("receiver 2.0 accepted %s", v)
		}
	}
	if _, _, err := decodeAt([]byte(`{"version":"2.3",`+decodeBase+`}`), 2, 0); err != nil {
		t.Errorf("receiver 2.0 refused newer minor 2.3: %v", err)
	}
}

func TestDecodeTrailingDataAndBounds(t *testing.T) {
	doc := `{"version":"2.6",` + decodeBase + `} {"version":"2.6"}`
	if _, _, err := decodeAtString(t, doc, 6); err == nil {
		t.Error("trailing document accepted (strict path)")
	}
	doc = `{"version":"2.9",` + decodeBase + `} x`
	if _, _, err := decodeAtString(t, doc, 6); err == nil {
		t.Error("trailing data accepted (lenient path)")
	}
	// Unknown is bounded.
	var b strings.Builder
	b.WriteString(`{"version":"2.9",` + decodeBase)
	for i := 0; i < MaxUnknownEntries+5; i++ {
		b.WriteString(`,"m` + itoa(i) + `":0`)
	}
	b.WriteString(`}`)
	_, u, err := decodeAtString(t, b.String(), 6)
	if err != nil {
		t.Fatal(err)
	}
	if len(u.Entries) != MaxUnknownEntries || u.Omitted != 5 {
		t.Errorf("unknown entries %d omitted %d", len(u.Entries), u.Omitted)
	}
}

// Every enum the schema declares has a decoding policy, and the documented
// fallbacks are values of their enum.
func TestDecodeEnumPoliciesCoverSchemaEnums(t *testing.T) {
	for typ := range goEnums {
		if _, ok := enumPolicies[typ]; !ok {
			t.Errorf("enum %s has no decoding policy", typ)
		}
	}
	for typ, p := range enumPolicies {
		if _, ok := goEnums[typ]; !ok {
			t.Errorf("decoding policy for %s, which is not a schema enum", typ)
		}
		if p.fallback != "" && !contains(p.values(), p.fallback) {
			t.Errorf("%s: fallback %q is not one of its values", typ, p.fallback)
		}
		if p.open != openEnums[typ] {
			t.Errorf("%s: open vocabulary mismatch between decoder and schema", typ)
		}
	}
	if fb, ok := EnumFallback(Severity("")); !ok || fb != "unknown" {
		t.Errorf("EnumFallback(Severity) = %q, %v", fb, ok)
	}
	if _, ok := EnumFallback(FindingType("")); ok {
		t.Error("FindingType has no fallback")
	}
}

func FuzzDecode(f *testing.F) {
	f.Add([]byte(`{"version":"2.9",` + decodeBase + `,"assets":[{"type":"x","value":"v"}]}`))
	f.Add([]byte(`{"version":"2.6",` + decodeBase + `}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 1<<16 {
			return
		}
		_, _, _ = decodeAt(raw, SchemaMajor, 6)
	})
}
