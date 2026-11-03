package ctis

import "testing"

func TestFindingStatus_IsValid_IncludesSuppressed(t *testing.T) {
	if !FindingStatusSuppressed.IsValid() {
		t.Error("suppressed must be a valid finding status (schema parity)")
	}
	for _, s := range AllFindingStatuses() {
		if !s.IsValid() {
			t.Errorf("%s in AllFindingStatuses but not IsValid", s)
		}
	}
	if FindingStatus("bogus").IsValid() {
		t.Error("bogus must be invalid")
	}
}
