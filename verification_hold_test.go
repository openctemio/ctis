package ctis

import (
	"encoding/json"
	"errors"
	"math"
	"os"
	"slices"
	"testing"
)

func holdF64(v float64) *float64 { return &v }

func TestVerificationHoldValidate(t *testing.T) {
	for _, tc := range []struct {
		name string
		h    VerificationHold
		ok   bool
	}{
		{"one reason", VerificationHold{Reasons: []string{HoldThrottledResponse}, Status: 429}, true},
		{"every input", VerificationHold{Reasons: []string{HoldEdgeBlockPage, HoldSoft404}, Status: 403, Edge: HoldEdgeBlocked, EdgeVendor: "example-edge", Similarity: holdF64(0.97)}, true},
		{"all reasons", VerificationHold{Reasons: slices.Clone(HoldReasons)}, true},
		{"no reason", VerificationHold{}, false},
		{"unknown reason", VerificationHold{Reasons: []string{"blocked"}}, false},
		{"duplicate reason", VerificationHold{Reasons: []string{HoldOOBWeak, HoldOOBWeak}}, false},
		{"status too low", VerificationHold{Reasons: []string{HoldTimingBased}, Status: 99}, false},
		{"status too high", VerificationHold{Reasons: []string{HoldTimingBased}, Status: 600}, false},
		{"unknown edge", VerificationHold{Reasons: []string{HoldEdgeBlockPage}, Edge: "maybe"}, false},
		{"vendor with markup", VerificationHold{Reasons: []string{HoldEdgeBlockPage}, EdgeVendor: "<b>x</b>"}, false},
		{"vendor too long", VerificationHold{Reasons: []string{HoldEdgeBlockPage}, EdgeVendor: string(make([]byte, 65))}, false},
		{"similarity above 1", VerificationHold{Reasons: []string{HoldSoft404}, Similarity: holdF64(1.5)}, false},
		{"similarity NaN", VerificationHold{Reasons: []string{HoldSoft404}, Similarity: holdF64(math.NaN())}, false},
	} {
		err := tc.h.Validate()
		if (err == nil) != tc.ok {
			t.Errorf("%s: err %v", tc.name, err)
		}
		if err != nil && !errors.Is(err, ErrInvalidVerificationHold) {
			t.Errorf("%s: %v is not ErrInvalidVerificationHold", tc.name, err)
		}
	}
}

// A hold set by a producer survives a JSON round trip of the report and
// reads back the same; a finding without one is not held.
func TestVerificationHoldRoundTrip(t *testing.T) {
	var f Finding
	if _, ok, err := f.VerificationHold(); ok || err != nil {
		t.Fatalf("empty finding: %v %v", ok, err)
	}
	in := VerificationHold{Reasons: []string{HoldEdgeBlockPage, HoldThrottledResponse}, Status: 503, Edge: HoldEdgeChallenged, EdgeVendor: "example-edge"}
	if err := f.SetVerificationHold(in); err != nil {
		t.Fatal(err)
	}
	if err := f.SetVerificationHold(VerificationHold{Reasons: []string{"nope"}}); err == nil {
		t.Fatal("an invalid hold was stored")
	}
	raw, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	var back Finding
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	got, ok, err := back.VerificationHold()
	if err != nil || !ok {
		t.Fatalf("read back: %v %v (%s)", ok, err, raw)
	}
	if !slices.Equal(got.Reasons, in.Reasons) || got.Status != in.Status || got.Edge != in.Edge || got.EdgeVendor != in.EdgeVendor || got.Similarity != nil {
		t.Fatalf("read back %+v, want %+v", got, in)
	}
}

// Producer input that is not a valid hold is an error, never "not held".
func TestVerificationHoldFromDocument(t *testing.T) {
	for _, tc := range []struct {
		doc string
		ok  bool
	}{
		{`{"reasons":["soft_404"],"similarity":0.9}`, true},
		{`{"reasons":["soft_404"],"body":"<html>"}`, false},
		{`{"reasons":"soft_404"}`, false},
		{`{"reasons":[]}`, false},
		{`"held"`, false},
	} {
		var v any
		if err := json.Unmarshal([]byte(tc.doc), &v); err != nil {
			t.Fatal(err)
		}
		var f Finding
		f.Extensions.Set(OpenCTEMNamespace, VerificationHoldKey, v)
		_, ok, err := f.VerificationHold()
		if ok != tc.ok || (err == nil) != tc.ok {
			t.Errorf("%s: ok %v err %v", tc.doc, ok, err)
		}
	}
}

// The namespace schema and the Go constants name the same reasons and edges.
func TestVerificationHoldSchemaParity(t *testing.T) {
	raw, err := os.ReadFile("schemas/extensions/io.openctem/2.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Properties map[string]struct {
			AdditionalProperties *bool    `json:"additionalProperties"`
			Required             []string `json:"required"`
			Properties           map[string]struct {
				Enum  []string `json:"enum"`
				Items struct {
					Enum []string `json:"enum"`
				} `json:"items"`
				MaxItems int `json:"maxItems"`
			} `json:"properties"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	h, ok := doc.Properties[VerificationHoldKey]
	if !ok {
		t.Fatalf("io.openctem schema lacks %s", VerificationHoldKey)
	}
	if h.AdditionalProperties == nil || *h.AdditionalProperties || !slices.Equal(h.Required, []string{"reasons"}) {
		t.Errorf("schema shape: additionalProperties %v required %v", h.AdditionalProperties, h.Required)
	}
	if got := h.Properties["reasons"].Items.Enum; !slices.Equal(got, HoldReasons) || h.Properties["reasons"].MaxItems != len(HoldReasons) {
		t.Errorf("schema reasons %v, Go %v", got, HoldReasons)
	}
	if got := h.Properties["edge"].Enum; !slices.Equal(got, []string{HoldEdgeChallenged, HoldEdgeBlocked}) {
		t.Errorf("schema edges %v", got)
	}
}
