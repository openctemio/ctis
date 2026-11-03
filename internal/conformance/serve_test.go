package conformance

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

type reply struct {
	ID     json.RawMessage `json:"id"`
	Output json.RawMessage `json:"output"`
	Error  *OpError        `json:"error"`
}

func serve(t *testing.T, in string) []reply {
	t.Helper()
	var out bytes.Buffer
	if err := Serve(strings.NewReader(in), &out, "test", "v0"); err != nil {
		t.Fatal(err)
	}
	var as []reply
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var a reply
		if err := json.Unmarshal([]byte(line), &a); err != nil {
			t.Fatalf("reply %q: %v", line, err)
		}
		as = append(as, a)
	}
	return as
}

func TestServeProtocol(t *testing.T) {
	as := serve(t, strings.Join([]string{
		`{"id":1,"op":"info"}`,
		``, // blank lines are skipped
		`{"id":"two","op":"asset_key","input":{"type":"domain_name","value":"example.com"}}`,
		`{"id":3,"op":"preferred_id","input":{"vulnerability":{}}}`,
		`{"id":4,"op":"nope","input":{}}`,
		`not json`,
		`{"id":6,"op":"canonical"}`,
		`{"id":7,"op":"canonical","input":{"function":"CanonicalDomain","value":"*.example.com"}}`,
		`{"id":8,"op":"canonical","input":{"function":"Bogus","value":"x"}}`,
		`{"id":9,"op":"canonical","input":{"function":"CanonicalDomain","value":"x","extra":1}}`,
		`{"op":"asset_key","input":{"type":"host","value":"h"}}`,
	}, "\n"))
	if len(as) != 10 {
		t.Fatalf("want 10 answers, got %d", len(as))
	}
	var info map[string]any
	if err := json.Unmarshal(as[0].Output, &info); err != nil || info["implementation"] != "test" || info["ctis"] != "2.0" {
		t.Errorf("info: %s", as[0].Output)
	}
	if string(as[1].ID) != `"two"` || string(as[1].Output) != `"ec26bc85-1b25-5494-9b45-31ab67de6b23"` {
		t.Errorf("asset_key: %s %s", as[1].ID, as[1].Output)
	}
	if string(as[2].Output) != "null" || as[2].Error != nil {
		t.Errorf("a null output: %+v", as[2])
	}
	for i, want := range map[int]string{3: CategoryUnsupported, 4: CategoryProtocol, 5: CategoryProtocol, 6: CategoryCanonical, 7: CategoryProtocol, 8: CategoryProtocol} {
		if as[i].Error == nil || as[i].Error.Category != want {
			t.Errorf("reply %d: %+v, want category %s", i, as[i], want)
		}
	}
	if string(as[4].ID) != "null" || string(as[9].ID) != "null" {
		t.Errorf("ids of a malformed request and of a request without id: %s %s", as[4].ID, as[9].ID)
	}
}

func TestServeLineTooLong(t *testing.T) {
	var out bytes.Buffer
	in := `{"id":1,"op":"validate","input":{"text":"` + strings.Repeat("a", MaxRequestBytes) + `"}}`
	if err := Serve(strings.NewReader(in), &out, "test", "v0"); err == nil {
		t.Fatal("an over-long line was accepted")
	}
	if !strings.Contains(out.String(), `"category":"protocol"`) {
		t.Errorf("no protocol error reply: %.200s", out.String())
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("closed") }

func TestServeWriteError(t *testing.T) {
	if err := Serve(strings.NewReader(`{"id":1,"op":"info"}`+"\n"), failWriter{}, "t", "v"); err == nil {
		t.Error("a write error was not returned")
	}
}

// Every operation answers a malformed input with a protocol error rather
// than a panic or a wrong category.
func TestOpsRefuseMalformedInput(t *testing.T) {
	for _, op := range append(append([]string{}, RequiredOps...), OptionalOps...) {
		for _, in := range []string{`[]`, `{"bogus":1}`} {
			if _, e := Do(op, json.RawMessage(in)); e == nil || e.Category != CategoryProtocol {
				t.Errorf("%s %s: %+v", op, in, e)
			}
		}
	}
}

func TestOpErrors(t *testing.T) {
	for _, c := range []struct {
		op, in, category string
	}{
		{"decode", `{"text":"{}","document":{}}`, CategoryProtocol},
		{"decode", `{"text":"[1]"}`, CategoryDecode},
		{"secret_digest", `{"key_hex":"zz","secret":"s"}`, CategoryProtocol},
		{"secret_digest", `{"key_hex":"01","secret":"s"}`, CategoryFingerprint},
		{"fingerprint", `{"input":{"bogus":1}}`, CategoryProtocol},
		{"location_key", `{"finding":{"bogus":1}}`, CategoryProtocol},
		{"correlation_key", `{"asset_key":"k","tool":"t","finding":{"bogus":1}}`, CategoryProtocol},
		{"preferred_id", `{"vulnerability":{"bogus":1}}`, CategoryProtocol},
		{"mapping_apply", `{"mapping":{},"input":""}`, CategoryMapping},
		{"mapping_apply", `{"mapping":{"apiVersion":"openctem.io/mapping/v2","source":"jsonl","records":[{"kind":"asset","set":{"type":{"const":"host"},"value":"/h"}}]},"input":"","options":{"now":"yesterday"}}`, CategoryProtocol},
		{"mapping_apply", `{"mapping":{"apiVersion":"openctem.io/mapping/v2","source":"jsonl","records":[{"kind":"asset","set":{"type":{"const":"host"},"value":"/h"}}]},"input":"","options":{"limits":{"max_nothing":1}}}`, CategoryProtocol},
		{"mapping_apply", `{"mapping":{"apiVersion":"openctem.io/mapping/v2","source":"jsonl","records":[{"kind":"asset","set":{"type":{"const":"host"},"value":"/h"}}]},"input":"{\"h\":\"a\"}","options":{"limits":{"max_input_bytes":2}}}`, CategoryInput},
		{"interop_select", `{"mappings":[{}],"document":{}}`, CategoryMapping},
		{"interop_collect", `{"mapping":{},"document":{},"records":[]}`, CategoryMapping},
	} {
		if _, e := Do(c.op, json.RawMessage(c.in)); e == nil || e.Category != c.category {
			t.Errorf("%s %s: %+v, want %s", c.op, c.in, e, c.category)
		}
	}
}

// All the limits of mapping_apply reach the options.
func TestMappingApplyLimits(t *testing.T) {
	in := `{"mapping":{"apiVersion":"openctem.io/mapping/v2","source":"jsonl","records":[{"kind":"asset","set":{"type":{"const":"host"},"value":"/h"}}]},"input":"{\"h\":\"a\"}\n{\"h\":\"b\"}\n","options":{"limits":{"max_record_bytes":100,"max_records":1,"max_outputs":5,"max_issues":5,"max_cell_bytes":10,"max_xml_elements":10}}}`
	out, e := Do("mapping_apply", json.RawMessage(in))
	if e != nil {
		t.Fatal(e)
	}
	if st := out.(map[string]any)["stats"].(map[string]any); st["records"] != 1 || st["truncated"] != true {
		t.Errorf("stats %v", st)
	}
}
