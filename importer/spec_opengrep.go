package importer

var _ = registerSpec(Spec{
	Format:        FormatOpengrep,
	Title:         "opengrep JSON output",
	SourceVersion: "opengrep 1.x scan --json",
	Rules: []string{
		"The opengrep format is the semgrep parser under the opengrep tool name: the output has the same shape, and Detect names it semgrep, so choose opengrep with Options.Format.",
		"One finding per result, filed on Options.Repository, else Options.DefaultAsset, else an unclassified asset named after the tool (with an issue).",
		"Severity: ERROR high, WARNING medium, INFO low, INVENTORY and EXPERIMENT info; native.severity keeps the word. Confidence from metadata.confidence (HIGH 90, MEDIUM 70, LOW 50).",
		"extra.fingerprint is opengrep's match-based id: it becomes the partial fingerprint matchBasedId/v1. The finding's fingerprint is derived from path, rule and line, the key a semgrep run without a login gave, so a finding first reported by semgrep keeps its identity.",
		"A taint trace is read in both forms the engine writes (objects, or the tagged [\"CliLoc\", [location, content]]); call steps are skipped.",
		"An ignored result (nosemgrep) gets an in-source suppression. Errors become issues.",
	},
	Fields: opengrepFields(),
})

// opengrepFields is the semgrep mapping with opengrep's fingerprint.
func opengrepFields() []Field {
	out := make([]Field, len(sgFields))
	copy(out, sgFields)
	for i := range out {
		if out[i].Path == sgEx+"/fingerprint" {
			out[i].Target = "findings[].partial_fingerprints.matchBasedId/v1"
		}
	}
	return out
}
