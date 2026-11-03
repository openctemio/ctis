package cyclonedx

import "github.com/openctemio/ctis/v2/internal/importkit"

// Helpers shared with package importer (internal/importkit).

const (
	capDescription = importkit.CapDescription
	capReference   = importkit.CapReference
	capRemediation = importkit.CapRemediation
	capShort       = importkit.CapShort
	capTitle       = importkit.CapTitle
	maxDependsOn   = importkit.MaxDependsOn
)

var (
	addDepProperty   = importkit.AddDepProperty
	addScore         = importkit.AddScore
	addVendorID      = importkit.AddVendorID
	addVulnID        = importkit.AddVulnID
	addWebRefs       = importkit.AddWebRefs
	appendUnique     = importkit.AppendUnique
	cleanPURL        = importkit.CleanPURL
	cvssOrder        = importkit.CvssOrder
	extra            = importkit.Extra
	firstNonEmpty    = importkit.FirstNonEmpty
	floatString      = importkit.FloatString
	goodPURL         = importkit.GoodPURL
	line             = importkit.Line
	nameVersion      = importkit.NameVersion
	parseTime        = importkit.ParseTime
	refOr            = importkit.RefOr
	severityFromCVSS = importkit.SeverityFromCVSS
	severityWord     = importkit.SeverityWord
	subjectAssetOf   = importkit.SubjectAssetOf
	text             = importkit.Text
	tokenOf          = importkit.TokenOf
	vexOf            = importkit.VexOf
	webURL           = importkit.WebURL
)
