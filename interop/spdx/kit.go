package spdx

import "github.com/openctemio/ctis/v2/internal/importkit"

// Helpers shared with package importer (internal/importkit).

const (
	capReference = importkit.CapReference
	capShort     = importkit.CapShort
	maxDependsOn = importkit.MaxDependsOn
)

var (
	addDepProperty = importkit.AddDepProperty
	appendUnique   = importkit.AppendUnique
	goodPURL       = importkit.GoodPURL
	line           = importkit.Line
	parseTime      = importkit.ParseTime
	refOr          = importkit.RefOr
	subjectAssetOf = importkit.SubjectAssetOf
)
