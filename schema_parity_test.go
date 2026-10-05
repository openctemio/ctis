package ctis

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// The JSON Schema in schemas/v1 and the Go types are two descriptions of one
// wire format, and receivers decode strictly into the Go types. These tests
// walk both together, recursively and in both directions, so any difference
// fails the build:
//
//   - every Go field has a schema member and every schema member a Go field;
//   - JSON types agree (string, integer, number, boolean, array, object);
//   - a member the schema requires is never omitempty in Go, and a member Go
//     always emits validates against the schema in its zero value;
//   - every Go enum type matches the schema enum it is used with;
//   - every schema object that describes a struct sets
//     additionalProperties: false, and free-form maps are Go maps.
//
// There is no exception list. Fix the schema or the struct instead.

var timeType = reflect.TypeOf(time.Time{})

// goEnums maps each Go string enum type to its full value set.
var goEnums = map[reflect.Type][]string{
	reflect.TypeOf(Severity("")):             stringsOf(AllSeverities()),
	reflect.TypeOf(FindingType("")):          stringsOf(AllFindingTypes()),
	reflect.TypeOf(FindingStatus("")):        stringsOf(AllFindingStatuses()),
	reflect.TypeOf(AssetType("")):            stringsOf(AllAssetTypes()),
	reflect.TypeOf(Criticality("")):          stringsOf(AllCriticalities()),
	reflect.TypeOf(DataFlowLocationType("")): stringsOf(AllDataFlowLocationTypes()),
	reflect.TypeOf(NativeScheme("")):         stringsOf(AllNativeSchemes()),
	reflect.TypeOf(DetectionType("")):        stringsOf(AllDetectionTypes()),
	reflect.TypeOf(ScoreSystem("")):          stringsOf(AllScoreSystems()),
	reflect.TypeOf(VEXStatus("")):            stringsOf(AllVEXStatuses()),
	reflect.TypeOf(VEXJustification("")):     stringsOf(AllVEXJustifications()),
	reflect.TypeOf(SourceState("")):          stringsOf(AllSourceStates()),
	reflect.TypeOf(VulnerabilityIDType("")):  stringsOf(AllVulnerabilityIDTypes()),
	reflect.TypeOf(SolutionType("")):         stringsOf(AllSolutionTypes()),
}

func stringsOf[T ~string](in []T) []string {
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = string(v)
	}
	return out
}

type parityWalker struct {
	t    *testing.T
	s    *schemaSet
	seen map[string]bool
	// enumsSeen records which Go enum types the walk met, so an enum type
	// that no field uses is noticed.
	enumsSeen map[reflect.Type]bool
}

func TestSchemaGoParity(t *testing.T) {
	w := &parityWalker{t: t, s: loadSchemaSet(t), seen: map[string]bool{}, enumsSeen: map[reflect.Type]bool{}}
	w.compare("report", reflect.TypeOf(Report{}), w.s.docs["report.json"], "report.json")

	for typ := range goEnums {
		if !w.enumsSeen[typ] {
			t.Errorf("Go enum %s is not used by any field reachable from Report", typ)
		}
	}
}

// Web3VulnerabilityClass is carried in a plain string field (for producers
// with classes of their own), so the walk does not reach it; compare it here.
func TestSchemaWeb3VulnerabilityClassEnum(t *testing.T) {
	s := loadSchemaSet(t)
	node, err := s.pointer("web3-finding.json", "/$defs/Web3VulnerabilityClass")
	if err != nil {
		t.Fatal(err)
	}
	if d := enumDiff(enumValues(node), stringsOf(AllWeb3VulnerabilityClasses())); d != "" {
		t.Errorf("Web3VulnerabilityClass: %s", d)
	}
}

func TestSchemaVersionMatchesGo(t *testing.T) {
	s := loadSchemaSet(t)
	v, err := s.pointer("report.json", "/properties/version")
	if err != nil {
		t.Fatal(err)
	}
	if v["default"] != SchemaVersion {
		t.Errorf("report.json version default = %v, Go SchemaVersion = %q: bump them together", v["default"], SchemaVersion)
	}
	for _, ok := range []string{"1.0", "1.1", "1.2", SchemaVersion, "1.10"} {
		if errs := s.validateValue(t, map[string]any{"version": ok, "metadata": map[string]any{"timestamp": "2026-10-02T00:00:00Z"}}, "report.json"); len(errs) > 0 {
			t.Errorf("schema rejects version %q: %v", ok, errs)
		}
		if !IsCompatibleVersion(ok) {
			t.Errorf("IsCompatibleVersion(%q) = false", ok)
		}
	}
	for _, bad := range []string{"", "1", "2.0", "0.9", "v1.3", "1.03", "1.3.0", "1.x", "9.9-garbage"} {
		errs := s.validateValue(t, map[string]any{"version": bad, "metadata": map[string]any{"timestamp": "2026-10-02T00:00:00Z"}}, "report.json")
		if len(errs) == 0 {
			t.Errorf("schema accepts version %q", bad)
		}
		if IsCompatibleVersion(bad) {
			t.Errorf("IsCompatibleVersion(%q) = true", bad)
		}
	}
	if NewReport().Version != SchemaVersion || NewReport().Schema != SchemaURL {
		t.Error("NewReport must stamp SchemaVersion and SchemaURL")
	}
}

func TestSchemaIDsAndDialect(t *testing.T) {
	s := loadSchemaSet(t)
	if len(s.docs) != 6 {
		t.Errorf("expected 6 schema files, found %d", len(s.docs))
	}
	for file, doc := range s.docs {
		if got, want := doc["$id"], SchemaBaseURL+file; got != want {
			t.Errorf("%s: $id = %v, want %s", file, got, want)
		}
		if doc["$schema"] != "http://json-schema.org/draft-07/schema#" {
			t.Errorf("%s: $schema must be draft-07", file)
		}
	}
}

// TestSchemaKeywords keeps the schemas inside what the test validator
// evaluates, and flags $ref siblings, which draft-07 ignores.
func TestSchemaKeywords(t *testing.T) {
	s := loadSchemaSet(t)
	for file, doc := range s.docs {
		checkKeywords(t, file, "", doc)
	}
}

func checkKeywords(t *testing.T, file, path string, node map[string]any) {
	_, hasRef := node["$ref"]
	for k, v := range node {
		if !supportedKeywords[k] {
			t.Errorf("%s#%s: keyword %q is not supported by the test validator", file, path, k)
		}
		if hasRef && k != "$ref" && !annotationKeywords[k] {
			t.Errorf("%s#%s: %q next to $ref is ignored by draft-07", file, path, k)
		}
		switch k {
		case "properties", "$defs":
			for name, child := range v.(map[string]any) {
				checkKeywords(t, file, path+"/"+k+"/"+name, child.(map[string]any))
			}
		case "items":
			checkKeywords(t, file, path+"/items", v.(map[string]any))
		case "additionalProperties":
			if m, ok := v.(map[string]any); ok {
				checkKeywords(t, file, path+"/additionalProperties", m)
			}
		}
	}
}

func (w *parityWalker) compare(path string, gt reflect.Type, node map[string]any, file string) {
	node, file, err := w.s.deref(node, file)
	if err != nil {
		w.t.Errorf("%s: %v", path, err)
		return
	}
	for gt.Kind() == reflect.Pointer {
		gt = gt.Elem()
	}

	switch {
	case gt == timeType:
		if node["type"] != "string" || node["format"] != "date-time" {
			w.t.Errorf("%s: time.Time must be {type: string, format: date-time} in the schema", path)
		}
		return
	case gt.Kind() == reflect.Slice:
		if node["type"] != "array" {
			w.t.Errorf("%s: Go slice, schema type %v", path, node["type"])
			return
		}
		items, ok := node["items"].(map[string]any)
		if !ok {
			w.t.Errorf("%s: array without items schema", path)
			return
		}
		w.compare(path+"[]", gt.Elem(), items, file)
		return
	case gt.Kind() == reflect.Map:
		if node["type"] != "object" || node["properties"] != nil {
			w.t.Errorf("%s: Go map must be a free-form object (no properties) in the schema", path)
			return
		}
		switch ap := node["additionalProperties"].(type) {
		case bool:
			if !ap {
				w.t.Errorf("%s: Go map but additionalProperties is false", path)
			}
			if gt.Elem().Kind() != reflect.Interface {
				w.t.Errorf("%s: typed Go map %s needs a typed additionalProperties schema", path, gt)
			}
		case map[string]any:
			w.compare(path+"{}", gt.Elem(), ap, file)
		default:
			w.t.Errorf("%s: Go map needs additionalProperties", path)
		}
		return
	case gt.Kind() == reflect.Struct:
		w.compareStruct(path, gt, node, file)
		return
	}

	// Scalars.
	if want := jsonKind(gt); node["type"] != want && (want != "integer" || node["type"] != "number") {
		w.t.Errorf("%s: Go %s is JSON %s, schema type is %v", path, gt, want, node["type"])
	}
	if gt.Kind() == reflect.String && gt.PkgPath() != "" {
		values, ok := goEnums[gt]
		if !ok {
			w.t.Errorf("%s: Go string type %s is not registered in goEnums", path, gt)
			return
		}
		w.enumsSeen[gt] = true
		if d := enumDiff(enumValues(node), values); d != "" {
			w.t.Errorf("%s: enum of %s differs: %s", path, gt.Name(), d)
		}
	}
}

func (w *parityWalker) compareStruct(path string, gt reflect.Type, node map[string]any, file string) {
	key := gt.String() + "@" + file + "#" + fmtNode(node)
	if w.seen[key] {
		return
	}
	w.seen[key] = true

	if node["type"] != "object" {
		w.t.Errorf("%s: struct %s, schema type %v", path, gt, node["type"])
		return
	}
	props, ok := node["properties"].(map[string]any)
	if !ok {
		w.t.Errorf("%s: struct %s has no schema properties", path, gt)
		return
	}
	if node["additionalProperties"] != false {
		w.t.Errorf("%s: schema object for %s must set additionalProperties: false (receivers decode strictly)", path, gt.Name())
	}
	required := map[string]bool{}
	if req, ok := node["required"].([]any); ok {
		for _, r := range req {
			required[r.(string)] = true
		}
	}

	fields := map[string]reflect.StructField{}
	for i := 0; i < gt.NumField(); i++ {
		f := gt.Field(i)
		if !f.IsExported() {
			continue
		}
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "-" {
			continue
		}
		if name == "" {
			w.t.Errorf("%s: field %s.%s has no json tag", path, gt.Name(), f.Name)
			continue
		}
		fields[name] = f
	}

	for _, name := range sortedKeys(props) {
		if _, ok := fields[name]; !ok {
			w.t.Errorf("%s.%s: in the schema (%s) but not in Go %s: strict receivers reject it", path, name, file, gt.Name())
		}
	}
	for _, name := range sortedKeys(fields) {
		f := fields[name]
		prop, ok := props[name].(map[string]any)
		if !ok {
			w.t.Errorf("%s.%s: Go field %s.%s is missing from the schema (%s)", path, name, gt.Name(), f.Name, file)
			continue
		}
		omitempty := strings.Contains(f.Tag.Get("json"), ",omitempty")
		if required[name] && omitempty {
			w.t.Errorf("%s.%s: required by the schema but omitempty in Go", path, name)
		}
		if !required[name] && !omitempty && f.Type.Kind() != reflect.Pointer {
			// Go always emits it, so its zero value must be schema-valid.
			var errs []string
			zero, _ := json.Marshal(reflect.Zero(f.Type).Interface())
			var v any
			dec := json.NewDecoder(strings.NewReader(string(zero)))
			dec.UseNumber()
			_ = dec.Decode(&v)
			w.s.validate(v, prop, file, path+"."+name, &errs)
			if len(errs) > 0 {
				w.t.Errorf("%s.%s: Go always emits it, and its zero value is not schema-valid (%v); make it required or omitempty", path, name, errs)
			}
		}
		w.compare(path+"."+name, f.Type, prop, file)
	}
}

func jsonKind(t reflect.Type) string {
	switch t.Kind() {
	case reflect.String:
		return "string"
	case reflect.Bool:
		return "boolean"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return "integer"
	case reflect.Float32, reflect.Float64:
		return "number"
	}
	return t.Kind().String()
}

func enumValues(node map[string]any) []string {
	raw, _ := node["enum"].([]any)
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func enumDiff(schema, goVals []string) string {
	in := func(list []string, v string) bool {
		for _, x := range list {
			if x == v {
				return true
			}
		}
		return false
	}
	var onlySchema, onlyGo []string
	for _, v := range schema {
		if !in(goVals, v) {
			onlySchema = append(onlySchema, v)
		}
	}
	for _, v := range goVals {
		if !in(schema, v) {
			onlyGo = append(onlyGo, v)
		}
	}
	if len(schema) == 0 {
		return "schema has no enum"
	}
	if len(onlySchema) == 0 && len(onlyGo) == 0 {
		return ""
	}
	return "schema only [" + strings.Join(onlySchema, ",") + "], Go only [" + strings.Join(onlyGo, ",") + "]"
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func fmtNode(node map[string]any) string {
	if d, ok := node["description"].(string); ok {
		return d
	}
	return ""
}
