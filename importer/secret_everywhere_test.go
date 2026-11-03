package importer

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/openctemio/ctis/v2"
)

// A secret that a scanner repeats in its message, description, commit
// message or tags must not reach any field of the report unmasked, whatever
// the format. The fake credentials are assembled at run time so that no
// secret scanner flags this repository.
var (
	leakKey   = "AKIA" + "Q3EGRZ7X2MNVBP4L"         // 20 characters
	leakToken = "ghp_" + "9fK2xLq7RzT4mWv8Np3Yb6Hc" // 28 characters
	leakPass  = "S3cr" + "etPass!"                  // 11 characters
)

func requireNoSecret(t *testing.T, res *Result, secrets ...string) {
	t.Helper()
	out, err := json.Marshal(res.Report)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range secrets {
		if strings.Contains(string(out), s) {
			t.Fatalf("raw secret %q is in the report:\n%s", s, out)
		}
	}
	if len(res.Report.Findings) == 0 {
		t.Fatal("no findings")
	}
}

func TestSecretMaskedEverywhere_Leaks(t *testing.T) {
	for _, f := range []Format{FormatGitleaks, FormatBetterleaks} {
		t.Run(string(f), func(t *testing.T) {
			// Record 1: Secret empty, only the match line; the description
			// and commit message repeat the bare secret. Record 2: Secret
			// set; tags and the commit link repeat it.
			in := `[{"Description":"GitHub token ` + leakToken + `","RuleID":"github-pat","File":"ci.yml","StartLine":4,
			  "Match":"token: ` + leakToken + `","Secret":"","Message":"add ` + leakToken + `","Commit":"abc"},
			 {"Description":"password ` + leakPass + ` in env","RuleID":"generic-password","File":".env","StartLine":1,
			  "Match":"PASS=` + leakPass + `","Secret":"` + leakPass + `","Tags":["` + leakPass + `"],"Link":"https://example.test/c?x=` + leakPass + `"}]`
			res, err := parseString(t, in, Options{Format: f, Repository: "github.com/example/shop"})
			if err != nil {
				t.Fatal(err)
			}
			requireNoSecret(t, res, leakToken, leakPass)
			if got := res.Report.Findings[0].Title; !strings.Contains(got, "ghp_********") {
				t.Errorf("title = %q, want the masked token", got)
			}
		})
	}
}

func TestSecretMaskedEverywhere_Trivy(t *testing.T) {
	// A run with masking turned off: the match and the title hold the key.
	in := `{"SchemaVersion":2,"ArtifactName":"repo","ArtifactType":"repository","Results":[{"Target":"config.py","Class":"secret",
	  "Secrets":[{"RuleID":"aws-access-key-id","Category":"AWS","Severity":"CRITICAL","Title":"AWS Access Key ` + leakKey + `","StartLine":2,"EndLine":2,"Match":"key = ` + leakKey + `"}]}]}`
	res, err := parseString(t, in, Options{Format: FormatTrivy})
	if err != nil {
		t.Fatal(err)
	}
	requireNoSecret(t, res, leakKey)
}

func TestSecretMaskedEverywhere_NessusPluginOutput(t *testing.T) {
	// A misconfigured check echoes a password and a community string in its
	// output; a hostile file repeats them in the synopsis and description.
	in := nessusHead + `<NessusClientData_v2><Report><ReportHost name="192.0.2.7">` +
		`<ReportItem port="161" svc_name="snmp" protocol="udp" pluginID="41028" severity="3" pluginName="SNMP default community">` +
		`<synopsis>community ` + leakPass + ` accepted</synopsis><description>Login with password ` + leakToken + ` worked.</description>` +
		`<plugin_output>Community String: ` + leakPass + "\npassword=" + leakToken + `</plugin_output>` +
		`</ReportItem></ReportHost></Report></NessusClientData_v2>`
	res, err := parseString(t, in, Options{Format: FormatNessus})
	if err != nil {
		t.Fatal(err)
	}
	requireNoSecret(t, res, leakPass, leakToken)
}

func TestSecretMaskedEverywhere_QualysResults(t *testing.T) {
	vals := credentialValues("Community String: " + leakPass + "\npassword: '" + leakToken + "'\nUser: admin")
	if len(vals) != 2 || vals[0] != leakToken || vals[1] != leakPass {
		t.Fatalf("credentialValues = %q, want the token and the community string, not the account", vals)
	}
}

// A secret finding of any format that arrives with an unmasked snippet (a
// DefectDojo export of a secret scan, a future format) is masked by the
// builder: snippet, title and every other field.
func TestSecretMaskedEverywhere_Builder(t *testing.T) {
	b := &Builder{res: &Result{Report: ctis.NewReport()}, lim: DefaultLimits()}
	b.res.Stats.BySeverity = map[ctis.Severity]int{}
	f := ctis.Finding{
		Type: ctis.FindingTypeSecret, Title: "found " + leakToken, Severity: ctis.SeverityHigh,
		Location:    &ctis.FindingLocation{Path: "a", Snippet: "tok=" + leakToken},
		Remediation: &ctis.Remediation{Recommendation: "revoke " + leakToken},
		Properties:  ctis.Properties{"nested": map[string]any{"v": []any{"x " + leakToken}}},
	}
	if err := b.finding(f); err != nil {
		t.Fatal(err)
	}
	requireNoSecret(t, b.res, leakToken)
}
