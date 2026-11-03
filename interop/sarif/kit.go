package sarif

import "github.com/openctemio/ctis/v2/internal/importkit"

// Helpers shared with package importer (internal/importkit).

const capShort = importkit.CapShort

var (
	line          = importkit.Line
	repoAsset     = importkit.RepoAsset
	stripUserinfo = importkit.StripUserinfo
)
