package ctis

import (
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestAssetIdentifiersRoundTrip(t *testing.T) {
	in := Asset{
		Type:  AssetTypeHost,
		Value: "web-01.corp.example",
		Identifiers: &AssetIdentifiers{
			MachineID:       "4c4c4544-0042-3510-8051-b4c04f4e4d32",
			CloudResourceID: "i-0abc1234def567890",
			BIOSUUID:        "4C4C4544-0042-3510-8051-B4C04F4E4D32",
			SerialNumber:    "B5QNM32",
			MACAddresses:    []string{"00:1a:2b:3c:4d:5e"},
		},
	}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out Asset
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(in.Identifiers, out.Identifiers) {
		t.Fatalf("identifiers changed in a round trip:\n in  %+v\n out %+v", in.Identifiers, out.Identifiers)
	}
	if strings.Contains(string(mustJSON(t, Asset{Type: AssetTypeHost, Value: "x"})), "identifiers") {
		t.Fatal("an asset without identifiers must not emit the field")
	}
}

// The published schema and the struct must describe the same members:
// strict receivers refuse fields the struct does not have.
func TestAssetIdentifiersSchemaMatchesStruct(t *testing.T) {
	raw, err := os.ReadFile("schemas/v1/asset.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Properties map[string]any `json:"properties"`
		Defs       map[string]struct {
			Properties map[string]any `json:"properties"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if _, ok := doc.Properties["identifiers"]; !ok {
		t.Fatal("asset.json has no identifiers member")
	}
	var schema []string
	for k := range doc.Defs["AssetIdentifiers"].Properties {
		schema = append(schema, k)
	}
	var fields []string
	typ := reflect.TypeOf(AssetIdentifiers{})
	for i := 0; i < typ.NumField(); i++ {
		name, _, _ := strings.Cut(typ.Field(i).Tag.Get("json"), ",")
		fields = append(fields, name)
	}
	sort.Strings(schema)
	sort.Strings(fields)
	if !reflect.DeepEqual(schema, fields) {
		t.Fatalf("schema members %v, struct fields %v", schema, fields)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
