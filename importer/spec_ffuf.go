package importer

const ffR = "/results[]"

var _ = registerSpec(Spec{
	Format:        FormatFfuf,
	Title:         "ffuf JSON output",
	SourceVersion: "ffuf 2.x -of json",
	Rules: []string{
		"An inventory format: every result is a URL that answered. Its origin is a web_origin asset and the URL an endpoint of it (source import) with the status code and content type; parameter names are kept, values never, and user info is removed. No findings.",
		"The command line and the configuration are never read: they hold the headers, cookies, tokens and proxy the person gave ffuf.",
		"The fuzzed words (input) are not kept: the URL already holds what was found.",
		"A result whose URL is not http(s) is skipped with an issue.",
		"Every web origin carries extensions[io.openctem].import_scope relative to Options.ScopeDomains; the receiver judges scope.",
	},
	Fields: []Field{
		{Path: "/commandline", Ignored: "the command line holds headers, cookies and tokens: never read"},
		{Path: "/config", Ignored: "the configuration holds headers, cookies, tokens and proxies: never read"},
		{Path: "/config/**", Ignored: "the configuration holds headers, cookies, tokens and proxies: never read"},
		{Path: "/time", Ignored: "run time"},
		{Path: "/results", Target: Container},
		{Path: ffR, Target: "assets[] (web_origin), endpoints[]"},
		{Path: ffR + "/url", Target: "assets[].value (origin), endpoints[] (method GET, template, parameter names)"},
		{Path: ffR + "/status", Target: "endpoints[].status_code"},
		{Path: ffR + "/content-type", Target: "endpoints[].content_type"},
		{Path: ffR + "/host", Ignored: "the host of the URL"},
		{Path: ffR + "/input", Ignored: "the fuzzed words; the URL holds what was found"},
		{Path: ffR + "/input/**", Ignored: "the fuzzed words; the URL holds what was found"},
		{Path: ffR + "/position", Ignored: "position in the word list"},
		{Path: ffR + "/length", Ignored: "response size"},
		{Path: ffR + "/words", Ignored: "response word count"},
		{Path: ffR + "/lines", Ignored: "response line count"},
		{Path: ffR + "/redirectlocation", Ignored: "the redirect target: another URL, not probed"},
		{Path: ffR + "/scraper", Ignored: "scraper output (free text)"},
		{Path: ffR + "/scraper/**", Ignored: "scraper output (free text)"},
		{Path: ffR + "/duration", Ignored: "response time"},
		{Path: ffR + "/resultfile", Ignored: "a local file name"},
	},
})
