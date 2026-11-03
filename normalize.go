package ctis

import (
	"net"
	"strings"
)

// NormalizeAssetName normalizes an asset name for the given type.
// This is a lightweight implementation for defense-in-depth.
// The API server re-normalizes authoritatively before storage.
//
// Part of RFC-001: Asset Identity Resolution.
func NormalizeAssetName(assetType AssetType, name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}

	switch assetType {
	case AssetTypeDomain, AssetTypeSubdomain:
		name = strings.ToLower(name)
		name = strings.TrimRight(name, ".")
		return name

	case AssetTypeIPAddress:
		if ip := net.ParseIP(name); ip != nil {
			if v4 := ip.To4(); v4 != nil {
				return v4.String()
			}
			return ip.String()
		}
		return name

	case AssetTypeHost:
		// If IP, normalize as IP
		if ip := net.ParseIP(name); ip != nil {
			if v4 := ip.To4(); v4 != nil {
				return v4.String()
			}
			return ip.String()
		}
		// Otherwise lowercase hostname
		name = strings.ToLower(name)
		name = strings.TrimRight(name, ".")
		return name

	case AssetTypeRepository:
		name = strings.TrimPrefix(name, "https://")
		name = strings.TrimPrefix(name, "http://")
		if strings.HasPrefix(name, "git@") {
			name = strings.TrimPrefix(name, "git@")
			if idx := strings.Index(name, ":"); idx > 0 {
				name = name[:idx] + "/" + name[idx+1:]
			}
		}
		name = strings.TrimSuffix(name, ".git")
		name = strings.ToLower(name)
		name = strings.TrimRight(name, "/")
		return name

	case AssetTypeHTTPService, AssetTypeDiscoveredURL:
		// Scheme and host are case-insensitive; the path and query are not
		// (/Admin and /admin can be different resources), so keep their case.
		return normalizeURLName(name)

	default:
		return name
	}
}

// normalizeURLName lower-cases the scheme and the host of a URL-like value
// and keeps everything after the authority (path, query, fragment) as given.
// User info keeps its case. A value without a scheme is read as host[/path].
// A trailing slash is dropped.
func normalizeURLName(name string) string {
	scheme, rest := "", name
	if i := strings.Index(name, "://"); i > 0 {
		scheme, rest = strings.ToLower(name[:i])+"://", name[i+3:]
	}
	authority, tail := rest, ""
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		authority, tail = rest[:i], rest[i:]
	}
	userinfo := ""
	if i := strings.LastIndex(authority, "@"); i >= 0 {
		userinfo, authority = authority[:i+1], authority[i+1:]
	}
	return strings.TrimRight(scheme+userinfo+strings.ToLower(authority)+tail, "/")
}
