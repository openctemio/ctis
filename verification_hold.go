package ctis

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"slices"
)

// VerificationHoldKey is the key under extensions["io.openctem"] of a
// finding whose matched response the producer screened as possibly the
// target's throttling or block answer (schemas/extensions/io.openctem/2.json,
// docs/profiles/openctem.md). The receiver keeps the finding and holds it
// until it is checked; a receiver that does not know the namespace ignores it.
const VerificationHoldKey = "verification_hold"

// Hold reasons of a VerificationHold.
const (
	// HoldEdgeBlockPage: the matched response is a challenge, block or
	// rate-limit page.
	HoldEdgeBlockPage = "edge_block_page"
	// HoldThrottledResponse: the matched response was 429 or 503, or carried
	// a Retry-After.
	HoldThrottledResponse = "throttled_response"
	// HoldSoft404: the matched response resembles the origin's not-found
	// answer.
	HoldSoft404 = "soft_404"
	// HoldTargetThrottled: the target throttled or blocked the scan around
	// the match.
	HoldTargetThrottled = "target_throttled"
	// HoldTimingBased: the check decides on response time.
	HoldTimingBased = "timing_based"
	// HoldOOBWeak: the out-of-band interaction is weak evidence (DNS only,
	// late, or from a resolver).
	HoldOOBWeak = "oob_weak"
)

// HoldReasons are the hold reasons, in order.
var HoldReasons = []string{HoldEdgeBlockPage, HoldThrottledResponse, HoldSoft404, HoldTargetThrottled, HoldTimingBased, HoldOOBWeak}

// Edge answers of a VerificationHold.
const (
	HoldEdgeChallenged = "challenged"
	HoldEdgeBlocked    = "blocked"
)

// maxEdgeVendorLen bounds VerificationHold.EdgeVendor.
const maxEdgeVendorLen = 64

var edgeVendorRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]*$`)

// VerificationHold is the producer's screen of a finding's matched response:
// why the match may be the target's answer, not the application, and the
// screen's inputs. It never carries the response body.
type VerificationHold struct {
	// Reasons are hold reason codes (HoldReasons), at least one.
	Reasons []string `json:"reasons"`
	// Status is the HTTP status of the matched response (0: not known).
	Status int `json:"status,omitempty"`
	// Edge is how an edge protection answered in the origin's place
	// (HoldEdgeChallenged, HoldEdgeBlocked; "": none seen).
	Edge string `json:"edge,omitempty"`
	// EdgeVendor names the edge protection (an open token, text only).
	EdgeVendor string `json:"edge_vendor,omitempty"`
	// Similarity of the matched response to the origin's not-found answer,
	// from 0 to 1 (nil: not measured).
	Similarity *float64 `json:"similarity,omitempty"`
}

// ErrInvalidVerificationHold is returned for a hold outside the schema.
var ErrInvalidVerificationHold = errors.New("ctis: invalid verification hold")

// Validate checks h against the namespace schema.
func (h VerificationHold) Validate() error {
	if len(h.Reasons) == 0 || len(h.Reasons) > len(HoldReasons) {
		return fmt.Errorf("%w: %d reasons, want 1 to %d", ErrInvalidVerificationHold, len(h.Reasons), len(HoldReasons))
	}
	for i, r := range h.Reasons {
		if !slices.Contains(HoldReasons, r) {
			return fmt.Errorf("%w: reason %q is not a hold reason", ErrInvalidVerificationHold, r)
		}
		if slices.Contains(h.Reasons[:i], r) {
			return fmt.Errorf("%w: reason %q twice", ErrInvalidVerificationHold, r)
		}
	}
	if h.Status != 0 && (h.Status < 100 || h.Status > 599) {
		return fmt.Errorf("%w: status %d", ErrInvalidVerificationHold, h.Status)
	}
	if h.Edge != "" && h.Edge != HoldEdgeChallenged && h.Edge != HoldEdgeBlocked {
		return fmt.Errorf("%w: edge %q", ErrInvalidVerificationHold, h.Edge)
	}
	if h.EdgeVendor != "" && (len(h.EdgeVendor) > maxEdgeVendorLen || !edgeVendorRE.MatchString(h.EdgeVendor)) {
		return fmt.Errorf("%w: edge vendor is not an open token", ErrInvalidVerificationHold)
	}
	if s := h.Similarity; s != nil && (math.IsNaN(*s) || *s < 0 || *s > 1) {
		return fmt.Errorf("%w: similarity outside 0..1", ErrInvalidVerificationHold)
	}
	return nil
}

// SetVerificationHold stores h under extensions["io.openctem"] of the
// finding, after checking it.
func (f *Finding) SetVerificationHold(h VerificationHold) error {
	if err := h.Validate(); err != nil {
		return err
	}
	h.Reasons = slices.Clone(h.Reasons)
	f.Extensions.Set(OpenCTEMNamespace, VerificationHoldKey, h)
	return nil
}

// VerificationHold returns the finding's hold: ok is false when it has none.
// A value that is not a valid hold (a decoded document is producer input) is
// an error, never a silent "not held".
func (f *Finding) VerificationHold() (h VerificationHold, ok bool, err error) {
	v, found := f.Extensions.Get(OpenCTEMNamespace, VerificationHoldKey)
	if !found || v == nil {
		return VerificationHold{}, false, nil
	}
	switch t := v.(type) {
	case VerificationHold:
		h = t
	case *VerificationHold:
		h = *t
	default:
		raw, err := json.Marshal(v)
		if err != nil {
			return VerificationHold{}, false, fmt.Errorf("%w: %v", ErrInvalidVerificationHold, err)
		}
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&h); err != nil {
			return VerificationHold{}, false, fmt.Errorf("%w: %v", ErrInvalidVerificationHold, err)
		}
	}
	if err := h.Validate(); err != nil {
		return VerificationHold{}, false, err
	}
	return h, true, nil
}
