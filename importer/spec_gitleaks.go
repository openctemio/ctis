package importer

const glRec = "/[]"

var _ = registerSpec(Spec{
	Format:        FormatGitleaks,
	Title:         "gitleaks JSON report",
	SourceVersion: "the JSON report of gitleaks 8.x (`--report-format json`), an array of leak records; every gitleaks-compatible scanner writes the same shape",
	Rules: []string{
		"Detection: a top-level array whose first element has RuleID and Secret or Match is named gitleaks. Other gitleaks-compatible scanners (betterleaks) write the same shape; name them with Options.Format, which keeps the same mapping under their tool name.",
		"One secret finding per record, filed on Options.Repository, else Options.DefaultAsset, else an unclassified asset named after the tool (with an issue).",
		"The raw secret never reaches the report: secret.masked_value, the snippet, the title and the commit message hold it masked with ctis.MaskSecretMatch (the masking FromSARIF uses), and the fingerprint input is the masked value (CTIS spec 5.2).",
		"Severity is inferred from the rule id (the report has none): cloud credentials, private keys and personal access tokens are critical, anything else high.",
		"The commit author and e-mail are kept: they say who committed the secret, which is who must rotate it.",
	},
	Fields: []Field{
		{Path: glRec, Target: "findings[]"},
		{Path: glRec + "/RuleID", Target: "findings[].rule_id, native.vuln_id, severity, secret.secret_type, secret.service"},
		{Path: glRec + "/Description", Target: "findings[].title, message"},
		{Path: glRec + "/File", Target: "findings[].location.path"},
		{Path: glRec + "/SymlinkFile", Target: "findings[].source_extra.symlink_file"},
		{Path: glRec + "/StartLine", Target: "findings[].location.start_line"},
		{Path: glRec + "/EndLine", Target: "findings[].location.end_line"},
		{Path: glRec + "/StartColumn", Target: "findings[].location.start_column"},
		{Path: glRec + "/EndColumn", Target: "findings[].location.end_column"},
		{Path: glRec + "/Match", Target: "findings[].location.snippet (masked)"},
		{Path: glRec + "/Secret", Target: "findings[].secret.masked_value, secret.length, fingerprint input (masked)"},
		{Path: glRec + "/Line", Ignored: "the whole source line holding the secret; the masked match is kept"},
		{Path: glRec + "/Entropy", Target: "findings[].secret.entropy"},
		{Path: glRec + "/Commit", Target: "findings[].location.commit_sha"},
		{Path: glRec + "/Link", Target: "findings[].source_extra.commit_link"},
		{Path: glRec + "/Author", Target: "findings[].author"},
		{Path: glRec + "/Email", Target: "findings[].author_email"},
		{Path: glRec + "/Date", Target: "findings[].commit_date"},
		{Path: glRec + "/Message", Target: "findings[].source_extra.commit_message (secret masked)"},
		{Path: glRec + "/Tags", Target: Container},
		{Path: glRec + "/Tags[]", Target: "findings[].tags"},
		{Path: glRec + "/Fingerprint", Target: "findings[].fingerprint (when it does not hold the secret)"},
	},
})
