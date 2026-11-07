package importer

import (
	"slices"
	"strings"
	"time"
)

// ImportCoverage is what a scan export proves about the findings it does not
// hold: on which hosts, for which checks, an absent finding means the check
// ran and did not find it. A receiver that closes findings missing from an
// import closes only what Covers answers true for. A nil ImportCoverage, or
// one that is not Complete, proves nothing: nothing may close.
//
// Only the Nessus importer fills it today.
type ImportCoverage struct {
	// Complete is false when the file cannot prove an absence (Reasons
	// says why): no plugin selection in the file, plugin results without
	// plugin details. Hosts are still listed.
	Complete bool `json:"complete"`

	// Why the file proves nothing, or narrows what it proves: stable codes
	// (CoverageNoPolicy, CoverageNoPluginDetails, CoverageNoHosts).
	Reasons []string `json:"reasons,omitempty"`

	// Plugin families the scan ran whole.
	Families []string `json:"families,omitempty"`

	// Plugins the scan ran outside those families (the policy's plugin
	// set and the individually enabled plugins of a mixed family).
	Plugins []string `json:"plugins,omitempty"`

	// The hosts the file holds, in file order.
	Hosts []HostCoverage `json:"hosts"`
}

// HostCoverage is one scanned host of an import.
type HostCoverage struct {
	// The asset of the report the host is.
	AssetRef string `json:"asset_ref"`

	// When the host's scan ended (HOST_END), else when it started. Nil
	// when the file gives neither: such a host proves nothing (Finished
	// false).
	ObservedAt *time.Time `json:"observed_at,omitempty"`

	// Finished is true when the file records the end of the host's scan.
	// An unfinished host (a stopped scan) proves nothing.
	Finished bool `json:"finished"`

	// Credentialed is true when the scan logged in to the host.
	Credentialed bool `json:"credentialed"`

	// LocalChecks is true when the local checks (credentialed patch and
	// configuration checks) ran on the host: credentialed and no
	// authentication failure or "local checks not available" result. When
	// false, only network-level findings of the host may close.
	LocalChecks bool `json:"local_checks"`

	// The plugin id that showed the authentication failure or the missing
	// local checks, when there was one.
	AuthIssue string `json:"auth_issue,omitempty"`
}

// Coverage reason codes.
const (
	// The file holds no plugin selection (no Policy element, as in some
	// exports): which checks ran is unknown.
	CoverageNoPolicy = "no_policy"
	// The plugin results carry no plugin details.
	CoverageNoPluginDetails = "no_plugin_details"
	// The file holds no host.
	CoverageNoHosts = "no_hosts"
)

// Host returns the coverage of the host whose asset is assetRef.
func (c *ImportCoverage) Host(assetRef string) (HostCoverage, bool) {
	if c == nil {
		return HostCoverage{}, false
	}
	for _, h := range c.Hosts {
		if h.AssetRef == assetRef {
			return h, true
		}
	}
	return HostCoverage{}, false
}

// Covers reports whether a finding absent from the import may be closed: the
// file is complete, the host is in it and finished, the plugin ran (its
// family whole, or the plugin itself), and a local check is closed only on
// a host where local checks ran. Compliance results are never closed by
// absence (only a PASSED result of the same check resolves a FAILED one).
// observedLater is the receiver's last sighting of the finding: a finding
// seen after the host's scan is never closed by it.
func (c *ImportCoverage) Covers(assetRef, pluginID, family string, local, compliance bool, observedLater *time.Time) bool {
	if c == nil || !c.Complete || compliance {
		return false
	}
	h, ok := c.Host(assetRef)
	if !ok || !h.Finished || h.ObservedAt == nil {
		return false
	}
	if observedLater != nil && observedLater.After(*h.ObservedAt) {
		return false
	}
	if local && !h.LocalChecks {
		return false
	}
	pluginID, family = strings.TrimSpace(pluginID), strings.TrimSpace(family)
	if pluginID == "" {
		return false
	}
	return slices.Contains(c.Plugins, pluginID) || (family != "" && slices.Contains(c.Families, family))
}

// IsLocalFamily reports whether a Nessus plugin family holds local
// (credentialed) checks: the "<OS> Local Security Checks" families and the
// families of checks that read the host from inside.
func IsLocalFamily(family string) bool {
	f := strings.ToLower(strings.TrimSpace(family))
	return strings.HasSuffix(f, "local security checks") || f == "policy compliance" || f == "windows : microsoft bulletins"
}
