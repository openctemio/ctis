package csaf

import "github.com/openctemio/ctis/v2/internal/importkit"

// Helpers shared with package importer (internal/importkit).

const (
	capReference = importkit.CapReference
	capShort     = importkit.CapShort
)

var (
	addVendorID = importkit.AddVendorID
	addVulnID   = importkit.AddVulnID
	line        = importkit.Line
	parseTime   = importkit.ParseTime
	vexOf       = importkit.VexOf
)
