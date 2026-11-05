package importer

// testsslCheckFields are the members of one check, under the array at p.
func testsslCheckFields(p string) []Field {
	return []Field{
		{Path: p, Target: "findings[] (severity LOW and above)"},
		{Path: p + "/id", Target: "findings[].rule_id, native.vuln_id, title"},
		{Path: p + "/severity", Target: "findings[].severity, native.severity"},
		{Path: p + "/finding", Target: "findings[].message, title"},
		{Path: p + "/cve", Target: "findings[].vulnerability.ids (space-separated); a check with a CVE is a vulnerability, else a misconfiguration"},
		{Path: p + "/cwe", Target: "findings[].vulnerability.cwe_ids"},
		{Path: p + "/hint", Target: "findings[].remediation.recommendation"},
	}
}

var _ = registerSpec(Spec{
	Format:        FormatTestssl,
	Title:         "testssl.sh JSON",
	SourceVersion: "testssl.sh 3.x --jsonfile (flat array) and --jsonfile-pretty",
	Rules: []string{
		"Each endpoint is a service asset name:port/tcp (the address when there is no name), with TLS set; its name is a domain_name that resolves_to its address. The endpoint is an asset even when every check passed.",
		"Severity: LOW, MEDIUM, HIGH and CRITICAL become low, medium, high and critical findings. OK, INFO and DEBUG checks passed or only inform: they are counted in one issue, never findings. WARN and FATAL are problems of the scan: one issue each.",
		"Scores, grades and scan statistics (overall_grade, final_score, grade_cap_*, the *_score ids, scanTime, scanProblem) sum up other checks and are not findings.",
		"The same check on the same name and port seen on several addresses is one finding with occurrence_count.",
		"The title is \"TLS check <id>: <finding>\" cut to 120 characters of the finding; the identity of a finding is its check id on its service.",
		"Every host-bearing asset carries extensions[io.openctem].import_scope relative to Options.ScopeDomains; the receiver judges scope.",
	},
	Fields: append(append([]Field{
		{Path: "/[]/ip", Target: "assets[]: name/address of the endpoint"},
		{Path: "/[]/port", Target: "service port, findings[].network.port"},
		{Path: "/Invocation", Ignored: "the command line"},
		{Path: "/at", Ignored: "where testssl.sh ran"},
		{Path: "/version", Target: "tool.version"},
		{Path: "/openssl", Ignored: "the OpenSSL testssl.sh used"},
		{Path: "/startTime", Ignored: "run start"},
		{Path: "/scanTime", Ignored: "run duration"},
		{Path: "/scanResult", Target: Container},
		{Path: "/scanResult[]", Target: "one endpoint"},
		{Path: "/scanResult[]/targetHost", Target: "assets[] (domain_name)"},
		{Path: "/scanResult[]/ip", Target: "assets[] (ip_address)"},
		{Path: "/scanResult[]/port", Target: "service port, findings[].network.port"},
		{Path: "/scanResult[]/rDNS", Ignored: "the reverse name, the address owner's choice"},
		{Path: "/scanResult[]/service", Ignored: "the protocol testssl.sh spoke (HTTP, SMTP, ...)"},
		{Path: "/scanResult[]/*", Target: "a section of checks (pretest, protocols, ciphers, vulnerabilities, rating, ...)"},
	}, testsslCheckFields("/[]")...), testsslCheckFields("/scanResult[]/*[]")...),
})
