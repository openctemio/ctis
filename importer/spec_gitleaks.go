package importer

const glL = "/[]"

var _ = registerSpec(Spec{
	Format:        FormatGitleaks,
	Title:         "gitleaks JSON report",
	SourceVersion: "the JSON report of gitleaks 8.x (`--report-format json`), an array of leaks; any gitleaks-compatible scanner that writes the same shape",
	Rules: []string{
		"One secret finding per leak, severity high, on Options.DefaultAsset (the scanned repository), else on an unclassified asset named after the tool.",
		"Detection: a top-level array whose first element has RuleID and Secret or Match. Every gitleaks-compatible scanner writes this shape, so the format cannot tell them apart; Options.ToolName names the tool.",
		"The raw secret never reaches the report: Secret becomes location.snippet masked with the rule of the SARIF converter (first four characters of a value of at least 16 characters followed by asterisks, else REDACTED), and every occurrence of the secret in Description and Fingerprint is replaced by the mask. Match and Line hold the secret with its context and are not read. secret.masked_value is left unset so receiver fingerprints match those of SARIF secret findings.",
		"The commit author, e-mail address and commit message are personal data and are never read.",
	},
	Fields: []Field{
		{Path: glL, Target: "findings[]"},
		{Path: glL + "/RuleID", Target: "findings[].rule_id, native.vuln_id, secret.secret_type (mapped to the CTIS vocabulary by keyword, else generic_secret)"},
		{Path: glL + "/Description", Target: "findings[].title, rule_name, description (secret masked)"},
		{Path: glL + "/Secret", Target: "findings[].location.snippet (masked)"},
		{Path: glL + "/Match", Ignored: "holds the raw secret with its context; the masked secret is kept"},
		{Path: glL + "/Line", Ignored: "the whole source line, which holds the raw secret"},
		{Path: glL + "/File", Target: "findings[].location.path"},
		{Path: glL + "/SymlinkFile", Target: "findings[].source_extra.symlink_file"},
		{Path: glL + "/StartLine", Target: "findings[].location.start_line"},
		{Path: glL + "/EndLine", Target: "findings[].location.end_line"},
		{Path: glL + "/StartColumn", Target: "findings[].location.start_column"},
		{Path: glL + "/EndColumn", Target: "findings[].location.end_column"},
		{Path: glL + "/Commit", Target: "findings[].location.commit_sha (source_extra.commit without a file)"},
		{Path: glL + "/Date", Target: "findings[].commit_date"},
		{Path: glL + "/Entropy", Target: "findings[].secret.entropy"},
		{Path: glL + "/Tags", Target: Container},
		{Path: glL + "/Tags[]", Target: "findings[].tags"},
		{Path: glL + "/Fingerprint", Target: "findings[].native.instance_id (secret masked)"},
		{Path: glL + "/Link", Target: "findings[].references (http(s) only)"},
		{Path: glL + "/Author", Ignored: "the commit author (personal data)"},
		{Path: glL + "/Email", Ignored: "the commit author's e-mail address (personal data)"},
		{Path: glL + "/Message", Ignored: "the commit message (may name people; not a property of the leak)"},
	},
})
