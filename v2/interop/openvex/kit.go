package openvex

import "github.com/openctemio/ctis/v2/internal/importkit"

// Helpers shared with package importer (internal/importkit).

const (
	capReference = importkit.CapReference
	capShort     = importkit.CapShort
)

var (
	addVulnID     = importkit.AddVulnID
	firstNonEmpty = importkit.FirstNonEmpty
	line          = importkit.Line
	parseTime     = importkit.ParseTime
	vexOf         = importkit.VexOf
)
