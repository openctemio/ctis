package importer

const blRec = "/[]"

var _ = registerSpec(Spec{
	Format:        FormatBetterleaks,
	Title:         "betterleaks JSON report",
	SourceVersion: "betterleaks v1 --report-format json (the gitleaks-compatible array of leak records)",
	Rules: []string{
		"The betterleaks format is the gitleaks parser under the betterleaks tool name; Detect names the shared shape gitleaks, so choose betterleaks with Options.Format.",
		"One secret finding per record, filed on Options.Repository, else Options.DefaultAsset, else an unclassified asset named after the tool (with an issue).",
		"The raw secret never reaches the report: secret.masked_value, the snippet, the title and the commit message hold it masked with ctis.MaskSecretMatch (the masking FromSARIF uses), and the fingerprint input is the masked value (CTIS spec 5.2).",
		"Severity is inferred from the rule id (the report has none): cloud credentials, private keys and personal access tokens are critical, anything else high.",
		"The commit author and e-mail are kept: they say who committed the secret, which is who must rotate it.",
	},
	Fields: []Field{
		{Path: blRec, Target: "findings[]"},
		{Path: blRec + "/RuleID", Target: "findings[].rule_id, native.vuln_id, severity, secret.secret_type, secret.service"},
		{Path: blRec + "/Description", Target: "findings[].title, message"},
		{Path: blRec + "/File", Target: "findings[].location.path"},
		{Path: blRec + "/SymlinkFile", Target: "findings[].source_extra.symlink_file"},
		{Path: blRec + "/StartLine", Target: "findings[].location.start_line"},
		{Path: blRec + "/EndLine", Target: "findings[].location.end_line"},
		{Path: blRec + "/StartColumn", Target: "findings[].location.start_column"},
		{Path: blRec + "/EndColumn", Target: "findings[].location.end_column"},
		{Path: blRec + "/Match", Target: "findings[].location.snippet (masked)"},
		{Path: blRec + "/Secret", Target: "findings[].secret.masked_value, secret.length, fingerprint input (masked)"},
		{Path: blRec + "/Line", Ignored: "the whole source line holding the secret; the masked match is kept"},
		{Path: blRec + "/Entropy", Target: "findings[].secret.entropy"},
		{Path: blRec + "/Commit", Target: "findings[].location.commit_sha"},
		{Path: blRec + "/Link", Target: "findings[].source_extra.commit_link"},
		{Path: blRec + "/Author", Target: "findings[].author"},
		{Path: blRec + "/Email", Target: "findings[].author_email"},
		{Path: blRec + "/Date", Target: "findings[].commit_date"},
		{Path: blRec + "/Message", Target: "findings[].source_extra.commit_message (secret masked)"},
		{Path: blRec + "/Tags", Target: Container},
		{Path: blRec + "/Tags[]", Target: "findings[].tags"},
		{Path: blRec + "/Fingerprint", Target: "findings[].fingerprint (when it does not hold the secret)"},
	},
})
