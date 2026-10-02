package ctis

import (
	"math"
	"strconv"
	"testing"
)

func TestDataFlowHelpers(t *testing.T) {
	src := NewDataFlowLocation("api/handler.go", 10, 5, "id := r.URL.Query().Get(\"id\")").WithLabel("id").WithFunction("Handle").WithOperation("assignment").AsSource()
	sink := NewDataFlowLocation("db/query.go", 42, 2, "db.Exec(q)").WithFunction("Find").AsSink()
	sink.CalledFunction = "db.Exec"

	df := NewDataFlow(src, sink)
	if !df.Tainted || df.Sources[0].Index != 0 || df.Sinks[0].Index != 1 {
		t.Fatalf("NewDataFlow: %+v", df)
	}
	df.TaintType = "user_input"
	df.AddIntermediate(NewDataFlowLocation("api/handler.go", 12, 3, "q := base + id"))
	df.AddIntermediate(NewDataFlowLocation("db/query.go", 40, 3, "Find(q)"))
	if df.Sinks[0].Index != 3 || !df.CrossFile || df.GetPathLength() != 4 || len(df.GetFullPath()) != 4 {
		t.Errorf("intermediates: %+v", df)
	}
	if !df.IsCrossFunction() {
		t.Error("Handle -> Find crosses functions")
	}

	want := "id (user_input) flows from api/handler.go:10 through 2 step(s) to db.Exec() in db/query.go:42"
	if got := df.BuildSummary(); got != want || df.Summary != want {
		t.Errorf("summary\n got %q\nwant %q", got, want)
	}

	df.AddSanitizer(NewDataFlowLocation("api/handler.go", 11, 1, "id = clean(id)").AsSanitizer())
	df.MarkAsSanitized()
	if df.Tainted || df.Sanitizers[0].TaintState != "sanitized" {
		t.Error("sanitizer")
	}

	same := NewDataFlow(NewDataFlowLocation("a.go", 1, 1, ""), NewDataFlowLocation("a.go", 9, 1, ""))
	same.MarkAsSanitized()
	if got := same.BuildSummary(); got != "tainted data flows from a.go:1 to sink at line 9 (sanitized)" {
		t.Errorf("summary %q", got)
	}
	if (&DataFlow{}).BuildSummary() != "" || (&DataFlow{Interprocedural: true}).IsCrossFunction() != true {
		t.Error("empty flow")
	}
}

// Regression for the itoa overflow fixed in 3b9671e.
func TestItoa(t *testing.T) {
	for _, n := range []int{0, 7, -7, 1234567890, math.MaxInt, math.MinInt} {
		if got, want := itoa(n), strconv.Itoa(n); got != want {
			t.Errorf("itoa(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestEnumHelpers(t *testing.T) {
	for _, v := range AllAssetTypes() {
		if !v.IsValid() || v.String() == "" {
			t.Errorf("asset type %q", v)
		}
	}
	for _, v := range AllFindingTypes() {
		if !v.IsValid() || v.String() == "" {
			t.Errorf("finding type %q", v)
		}
	}
	for _, v := range AllSeverities() {
		if !v.IsValid() || v.String() == "" {
			t.Errorf("severity %q", v)
		}
	}
	for _, v := range AllCriticalities() {
		if !v.IsValid() || v.String() == "" {
			t.Errorf("criticality %q", v)
		}
	}
	if !Criticality("").IsValid() || Criticality("x").IsValid() || AssetType("other").IsValid() {
		t.Error("criticality empty is valid, unknown values are not")
	}
	scores := map[Severity]float64{SeverityCritical: 10, SeverityHigh: 7.5, SeverityMedium: 5, SeverityLow: 2.5, SeverityInfo: 0}
	for s, want := range scores {
		if s.Score() != want {
			t.Errorf("%s score %v", s, s.Score())
		}
	}
	if len(AllWeb3VulnerabilityClasses()) == 0 || len(AllDataFlowLocationTypes()) != 5 {
		t.Error("enum lists")
	}
}

func TestParseVersion(t *testing.T) {
	for in, want := range map[string][2]int{"1.0": {1, 0}, "1.3": {1, 3}, "2.10": {2, 10}} {
		maj, mnr, ok := ParseVersion(in)
		if !ok || maj != want[0] || mnr != want[1] {
			t.Errorf("ParseVersion(%q) = %d %d %v", in, maj, mnr, ok)
		}
	}
	for _, in := range []string{"", "1", ".1", "1.", "a.b", "1.3.0", "01.3", "1.03", "12345.1", "+1.2"} {
		if _, _, ok := ParseVersion(in); ok {
			t.Errorf("ParseVersion(%q) must fail", in)
		}
	}
}
