package ctis

import (
	"strings"

	"github.com/openctemio/ctis/fingerprint"
)

// CorrelationKeyPrefix starts every correlation key.
const CorrelationKeyPrefix = "ctis-ck/1:"

// correlationRecipe is the recipe name inside the hashed canonical input.
const correlationRecipe = "ctis-ck"

// CorrelationKey is the normative key that says two findings, possibly from
// different tools, describe the same issue at the same place on the same
// asset. It is "ctis-ck/1:" and the hex SHA-256 of the length-prefixed parts
// (fingerprint.EncodeParts, as recipe v2 uses) in this order:
//
//  1. assetKey: the asset's key, computed by the receiver, never taken from
//     a producer;
//  2. the finding's preferred vulnerability id (PreferredVulnerabilityID), or
//     "rule:" + tool + "/" + rule_id when it has none;
//  3. LocationKey(f).
//
// Receivers compute it; a producer's value is never trusted. The tool is the
// finding's own tool when the finding carries one; CorrelationKeyForTool takes
// it explicitly (the report's tool when the finding has none).
//
// It returns "" when f is nil or assetKey is empty: no asset, no key.
func CorrelationKey(assetKey string, f *Finding) string {
	return CorrelationKeyForTool(assetKey, findingTool(f), f)
}

// CorrelationKeyForTool is CorrelationKey with the tool name given by the
// caller. The tool only matters for a finding that has no vulnerability id.
func CorrelationKeyForTool(assetKey, tool string, f *Finding) string {
	if f == nil || assetKey == "" {
		return ""
	}
	var id string
	if f.Vulnerability != nil {
		if v, ok := PreferredVulnerabilityID(f.Vulnerability); ok {
			id = v.ID
		}
	}
	if id == "" {
		id = "rule:" + strings.TrimSpace(tool) + "/" + strings.TrimSpace(f.RuleID)
	}
	return CorrelationKeyPrefix + fingerprint.Hash(fingerprint.EncodeParts(correlationRecipe, assetKey, id, LocationKey(f)))
}

// findingTool is the tool name recorded on the finding itself. Findings
// carry no tool member in this release, so it is empty and callers that know
// the report's tool use CorrelationKeyForTool.
func findingTool(*Finding) string { return "" }
