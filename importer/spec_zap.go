package importer

// zapAlertFields lists the members of an alert under prefix p and the
// instance list under inst (the JSON and XML forms name them alike).
func zapAlertFields(p, inst, tags string, tagFields []Field) []Field {
	out := []Field{
		{Path: p, Target: "findings[]"},
		{Path: p + "/pluginid", Target: "findings[].rule_id, native.vuln_id"},
		{Path: p + "/alertRef", Target: "findings[].native.instance_id"},
		{Path: p + "/alert", Target: "findings[].title, rule_name"},
		{Path: p + "/name", Target: "findings[].title (when no alert)"},
		{Path: p + "/riskcode", Target: "findings[].severity, native.severity"},
		{Path: p + "/confidence", Target: "findings[].confidence, status (0 is a false positive), native.detection_type (4 confirmed), source_extra.confidence"},
		{Path: p + "/riskdesc", Ignored: "riskcode and confidence as words"},
		{Path: p + "/confidencedesc", Ignored: "confidence as a word"},
		{Path: p + "/desc", Target: "findings[].description (HTML reduced to text)"},
		{Path: p + "/count", Target: "findings[].occurrence_count (an alert without instances)"},
		{Path: p + "/systemic", Target: "findings[].source_extra.systemic"},
		{Path: p + "/solution", Target: "findings[].remediation.recommendation (HTML reduced to text)"},
		{Path: p + "/otherinfo", Target: "findings[].source_extra.otherinfo (HTML reduced to text)"},
		{Path: p + "/reference", Target: "findings[].references (the http(s) URLs)"},
		{Path: p + "/cweid", Target: "findings[].vulnerability.cwe_id, cwe_ids"},
		{Path: p + "/wascid", Target: "findings[].source_extra.wascid"},
		{Path: p + "/sourceid", Target: "findings[].source_extra.sourceid"},
		{Path: p + "/instances", Target: Container},
		{Path: inst, Target: "findings[] (one per method, URL template and parameter), evidence (one line per instance, at most 20, the rest counted)"},
		{Path: inst + "/uri", Target: "findings[].web.url, evidence (no user info, fragment or query values)"},
		{Path: inst + "/method", Target: "findings[].web.method, evidence"},
		{Path: inst + "/param", Target: "findings[].web.parameter.name, evidence"},
		{Path: inst + "/attack", Target: "findings[].evidence (text)"},
		{Path: inst + "/evidence", Target: "findings[].evidence (text)"},
		{Path: inst + "/otherinfo", Target: "findings[].evidence"},
		{Path: inst + "/id", Ignored: "ZAP-internal instance number"},
		{Path: inst + "/nodeName", Ignored: "the site tree node; the URI is kept"},
		{Path: inst + "/request-header", Ignored: "request headers hold cookies and authorization headers"},
		{Path: inst + "/request-body", Ignored: "request bodies hold credentials and personal data"},
		{Path: inst + "/response-header", Ignored: "response headers hold session cookies"},
		{Path: inst + "/response-body", Ignored: "response bodies hold personal data"},
		{Path: inst + "/requestheader", Ignored: "request headers hold cookies and authorization headers"},
		{Path: inst + "/requestbody", Ignored: "request bodies hold credentials and personal data"},
		{Path: inst + "/responseheader", Ignored: "response headers hold session cookies"},
		{Path: inst + "/responsebody", Ignored: "response bodies hold personal data"},
		{Path: tags, Target: Container},
	}
	return append(out, tagFields...)
}

const (
	zjSite  = "/site[]"
	zjAlert = zjSite + "/alerts[]"
	zxSite  = "/OWASPZAPReport/site"
	zxAlert = zxSite + "/alerts/alertitem"
)

var _ = registerSpec(Spec{
	Format:        FormatZAP,
	Title:         "ZAP traditional report (JSON and XML)",
	SourceVersion: "the traditional JSON and XML reports of ZAP 2.12-2.16",
	Rules: []string{
		"The JSON and XML forms are one format; the first character of the file decides which parser reads it. The paths below list both forms.",
		"One website asset per site, named by its origin (scheme, host and port; no path, query or user info). One finding per alert, method, URL template and parameter (at most 100 per alert, the rest counted in an issue), on the site's host and port, with finding.web: the URI without user info, fragment or query values, the method and the parameter (query when the URI names it, form for a request with a body, otherwise left out).",
		"Severity: riskcode 0 info, 1 low, 2 medium, 3 high; native.severity keeps it. Confidence 1, 2, 3, 4 become 30, 60, 90, 100; 0 (marked a false positive in ZAP) sets status false_positive.",
		"Each instance (method, redacted URI, parameter, attack, evidence) becomes a line of the evidence of its finding, at most 20 per finding; the attack string is kept as text, never as markup. occurrence_count is the number of instances of the finding.",
		"Request and response headers and bodies, which hold cookies, authorization headers and session tokens, are never read.",
	},
	Fields: append(append(append([]Field{
		{Path: "/@programName", Ignored: "always ZAP; the tool is named by the format"},
		{Path: "/@version", Target: "tool.version"},
		{Path: "/@generated", Target: "metadata.properties.generated (when no created)"},
		{Path: "/created", Target: "metadata.properties.generated"},
		{Path: "/insights", Ignored: "scan statistics (counts and timings)"},
		{Path: "/insights[]", Ignored: "scan statistics (counts and timings)"},
		{Path: "/insights[]/**", Ignored: "scan statistics (counts and timings)"},
		{Path: "/site", Target: Container},
		{Path: zjSite, Target: "assets[]"},
		{Path: zjSite + "/@name", Target: "assets[].value (the origin)"},
		{Path: zjSite + "/@host", Target: "assets[].properties.host, findings[].network.host"},
		{Path: zjSite + "/@port", Target: "assets[].properties.port, findings[].network.port"},
		{Path: zjSite + "/@ssl", Target: "assets[].properties.scheme"},
		{Path: zjSite + "/alerts", Target: Container},
	}, zapAlertFields(zjAlert, zjAlert+"/instances[]", zjAlert+"/tags", []Field{
		{Path: zjAlert + "/tags/*", Target: "findings[].tags (the name), references (the link)"},
	})...), []Field{
		{Path: "/OWASPZAPReport", Target: Container},
		{Path: "/OWASPZAPReport/@programName", Ignored: "always ZAP; the tool is named by the format"},
		{Path: "/OWASPZAPReport/@version", Target: "tool.version"},
		{Path: "/OWASPZAPReport/@generated", Target: "metadata.properties.generated"},
		{Path: zxSite, Target: "assets[]"},
		{Path: zxSite + "/@name", Target: "assets[].value (the origin)"},
		{Path: zxSite + "/@host", Target: "assets[].properties.host, findings[].network.host"},
		{Path: zxSite + "/@port", Target: "assets[].properties.port, findings[].network.port"},
		{Path: zxSite + "/@ssl", Target: "assets[].properties.scheme"},
		{Path: zxSite + "/alerts", Target: Container},
	}...), zapAlertFields(zxAlert, zxAlert+"/instances/instance", zxAlert+"/tags", []Field{
		{Path: zxAlert + "/tags/tag", Target: Container},
		{Path: zxAlert + "/tags/tag/tag", Target: "findings[].tags"},
		{Path: zxAlert + "/tags/tag/link", Target: "findings[].references"},
	})...),
})
