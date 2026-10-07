package ctis

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRedactSecretFinding_EveryField(t *testing.T) {
	key := "AKIA" + "Q3EGRZ7X2MNVBP4L"
	f := Finding{
		Type:                FindingTypeSecret,
		Title:               "AWS key " + key,
		Description:         "found " + key,
		Message:             key + " in config",
		Evidence:            "line: " + key,
		Location:            &FindingLocation{Path: "config.py", Snippet: `aws_key = "` + key + `"`},
		Remediation:         &Remediation{Recommendation: "rotate " + key},
		Secret:              &SecretDetails{SecretType: "aws_key", MaskedValue: key},
		Tags:                []string{"secret", key},
		Properties:          Properties{"match": key, "deep": map[string]any{"list": []any{"x" + key}}},
		PartialFingerprints: map[string]string{"commitMessage": "add " + key},
	}
	RedactSecretFinding(&f)
	out, _ := json.Marshal(f)
	if strings.Contains(string(out), key) {
		t.Fatalf("raw secret left in the finding:\n%s", out)
	}
	if f.Type != FindingTypeSecret {
		t.Errorf("type = %q; enums are not text", f.Type)
	}
	if f.Title != "AWS key AKIA********" {
		t.Errorf("title = %q", f.Title)
	}
	if f.Secret.MaskedValue != "AKIA********" {
		t.Errorf("masked_value = %q", f.Secret.MaskedValue)
	}
}

// A producer's masking is kept and a second pass changes nothing.
func TestRedactSecretFinding_KeepsMaskedAndIsIdempotent(t *testing.T) {
	f := Finding{
		Type:     FindingTypeSecret,
		Title:    "GitHub token ghp_****abcd in ci.yml",
		Location: &FindingLocation{Path: "ci.yml", Snippet: `token: "ghp_****abcd"`},
		Secret:   &SecretDetails{MaskedValue: "gh****cd"},
	}
	want, _ := json.Marshal(f)
	RedactSecretFinding(&f)
	RedactSecretFinding(&f)
	got, _ := json.Marshal(f)
	if string(got) != string(want) {
		t.Fatalf("masked finding changed:\n got %s\nwant %s", got, want)
	}
}

// Only a secret finding's snippet is taken for a secret; a code finding is
// untouched unless the caller names a raw value.
func TestRedactSecretFinding_NonSecretNeedsKnownValue(t *testing.T) {
	f := Finding{Type: FindingTypeVulnerability, Title: "password = os.Getenv(\"X1234567\")", Location: &FindingLocation{Snippet: "X1234567"}}
	RedactSecretFinding(&f)
	if f.Location.Snippet != "X1234567" || !strings.Contains(f.Title, "X1234567") {
		t.Fatalf("code finding changed: %+v", f)
	}
	pass := "S3cr" + "etPass!"
	f.Description = "default password " + pass
	RedactSecretFinding(&f, pass, "ab")
	if strings.Contains(f.Description, pass) || f.Description != "default password REDACTED" {
		t.Fatalf("description = %q", f.Description)
	}
}

func TestSecretTokens(t *testing.T) {
	got := secretTokens(`{"token":"ghp_abcdef123456","name":"DATABASE_PASSWORD","v":"os.Getenv","m":"****1234abcd"}`)
	if len(got) != 1 || got[0] != "ghp_abcdef123456" {
		t.Fatalf("secretTokens = %q", got)
	}
}

func TestContainsSecret(t *testing.T) {
	if !ContainsSecret("x AKIA1234 y", "AKIA1234") || ContainsSecret("x ab y", "ab") || ContainsSecret("x", "") {
		t.Fatal("ContainsSecret")
	}
}

// A raw value that is also part of the mask word is not masked again
// inside the mask (found by FuzzFromSARIF: "REDAREDACTED").
func TestRedactDoesNotRemaskTheMask(t *testing.T) {
	for _, raw := range []string{"CTED", "REDA", "ACTED", "****"} {
		f := Finding{Type: FindingTypeSecret, Title: "found " + raw,
			Location: &FindingLocation{Snippet: raw}, Secret: &SecretDetails{MaskedValue: raw}}
		RedactSecretFinding(&f)
		if f.Location.Snippet != maskSecret(raw) && !isMasked(f.Location.Snippet) {
			t.Errorf("%q: snippet %q", raw, f.Location.Snippet)
		}
		if strings.Contains(f.Location.Snippet, "REDAREDACTED") || strings.Contains(f.Secret.MaskedValue, "REDAREDACTED") {
			t.Errorf("%q: mask masked again: %q %q", raw, f.Location.Snippet, f.Secret.MaskedValue)
		}
	}
}
