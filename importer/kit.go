package importer

import "github.com/openctemio/ctis/v2/internal/importkit"

// Helpers shared with the interoperability adapters (internal/importkit).

const (
	capCategory    = importkit.CapCategory
	capDescription = importkit.CapDescription
	capEvidence    = importkit.CapEvidence
	capReference   = importkit.CapReference
	capRemediation = importkit.CapRemediation
	capShort       = importkit.CapShort
	capTitle       = importkit.CapTitle
)

var (
	addDepProperty   = importkit.AddDepProperty
	addRefs          = importkit.AddRefs
	addScore         = importkit.AddScore
	addTags          = importkit.AddTags
	addVendorID      = importkit.AddVendorID
	addVulnID        = importkit.AddVulnID
	addWebRefs       = importkit.AddWebRefs
	appendUnique     = importkit.AppendUnique
	cleanPURL        = importkit.CleanPURL
	cvssVectorScore  = importkit.CvssVectorScore
	docRef           = importkit.DocRef
	extra            = importkit.Extra
	extras           = importkit.Extras
	firstNonEmpty    = importkit.FirstNonEmpty
	goodPURL         = importkit.GoodPURL
	line             = importkit.Line
	nameVersion      = importkit.NameVersion
	parseTime        = importkit.ParseTime
	probe            = importkit.Probe
	purlOf           = importkit.PurlOf
	rawTextEvidence  = importkit.RawTextEvidence
	refOr            = importkit.RefOr
	repoAsset        = importkit.RepoAsset
	severityFromCVSS = importkit.SeverityFromCVSS
	severityWord     = importkit.SeverityWord
	stripUserinfo    = importkit.StripUserinfo
	sourceRef        = importkit.SourceRef
	text             = importkit.Text
	tokenOf          = importkit.TokenOf
	webURL           = importkit.WebURL
)
