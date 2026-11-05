package importer

import (
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/openctemio/ctis/v2"
)

// S3Scanner JSON lines (-json): one log line per bucket checked, the bucket
// under "bucket". A bucket that exists is a storage asset named by its
// provider's virtual-host name; each class of permission granted to
// everyone or to every authenticated user of the provider is a
// misconfiguration finding on it. Log lines without a bucket are ignored.
// Object keys and the owner's identity are never kept. The mapping is
// spec_s3scanner.go.

func init() {
	parsers[FormatS3Scanner] = parseS3Scanner
	tools[FormatS3Scanner] = ctis.Tool{Name: "s3scanner", InfoURL: "https://github.com/sa7mon/S3Scanner", Techniques: []ctis.Technique{ctis.TechniqueCSPM}}
}

type s3Bucket struct {
	Name     string `json:"name"`
	Region   string `json:"region"`
	Exists   int    `json:"exists"`
	Provider string `json:"provider"`

	AuthRead        int `json:"perm_auth_users_read"`
	AuthWrite       int `json:"perm_auth_users_write"`
	AuthReadACL     int `json:"perm_auth_users_read_acl"`
	AuthWriteACL    int `json:"perm_auth_users_write_acl"`
	AuthFullControl int `json:"perm_auth_users_full_control"`
	AllRead         int `json:"perm_all_users_read"`
	AllWrite        int `json:"perm_all_users_write"`
	AllReadACL      int `json:"perm_all_users_read_acl"`
	AllWriteACL     int `json:"perm_all_users_write_acl"`
	AllFullControl  int `json:"perm_all_users_full_control"`
}

// s3Allowed is S3Scanner's value of a granted permission (0 denied, 2
// unknown).
const s3Allowed = 1

// s3Class is one class of exposure and its finding.
type s3Class struct {
	rule, title string
	severity    ctis.Severity
	granted     func(*s3Bucket) bool
}

var s3Classes = []s3Class{
	{"s3scanner:public-write", "Storage bucket writable by anyone", ctis.SeverityCritical,
		func(k *s3Bucket) bool {
			return k.AllWrite == s3Allowed || k.AllWriteACL == s3Allowed || k.AllFullControl == s3Allowed
		}},
	{"s3scanner:public-read", "Storage bucket readable by anyone", ctis.SeverityHigh,
		func(k *s3Bucket) bool { return k.AllRead == s3Allowed || k.AllReadACL == s3Allowed }},
	{"s3scanner:authenticated-write", "Storage bucket writable by every authenticated user of the provider", ctis.SeverityHigh,
		func(k *s3Bucket) bool {
			return k.AuthWrite == s3Allowed || k.AuthWriteACL == s3Allowed || k.AuthFullControl == s3Allowed
		}},
	{"s3scanner:authenticated-read", "Storage bucket readable by every authenticated user of the provider", ctis.SeverityMedium,
		func(k *s3Bucket) bool { return k.AuthRead == s3Allowed || k.AuthReadACL == s3Allowed }},
}

var (
	s3NameRE   = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,221}[a-z0-9]$`)
	s3RegionRE = regexp.MustCompile(`^[a-z0-9-]{2,32}$`)
)

// s3Host is the bucket's virtual-host name at its provider.
func s3Host(provider, name, region string) string {
	region = strings.ToLower(strings.TrimSpace(region))
	if !s3RegionRE.MatchString(region) {
		region = ""
	}
	switch provider {
	case "aws":
		return name + ".s3.amazonaws.com"
	case "gcp":
		return name + ".storage.googleapis.com"
	case "digitalocean":
		if region != "" {
			return name + "." + region + ".digitaloceanspaces.com"
		}
	case "linode":
		if region != "" {
			return name + "." + region + ".linodeobjects.com"
		}
	case "scaleway":
		if region != "" {
			return name + ".s3." + region + ".scw.cloud"
		}
	case "dreamhost":
		return name + ".objects-us-east-1.dream.io"
	}
	return name
}

func parseS3Scanner(b *Builder, r io.Reader) error {
	bl := DefaultBundleLimits()
	ln := 0
	var fatal error
	err := eachTextLine(b, "/line", newCapReader(r, b.lim.MaxInputBytes), bl.MaxLineBytes, bl.MaxLines, func(l string) bool {
		ln++
		doc, err := scanJSON([]byte(l), FormatS3Scanner, b.lim, b.obs)
		if err != nil {
			return false
		}
		var rec struct {
			Bucket *s3Bucket `json:"bucket"`
		}
		if err := doc.decode(&rec); err != nil {
			return false
		}
		if rec.Bucket == nil {
			return true // a log line
		}
		if fatal = b.s3Bucket(rec.Bucket, ln); fatal != nil {
			return false
		}
		return true
	})
	if fatal != nil {
		return fatal
	}
	if err != nil {
		return lineReadError(err)
	}
	b.stampImportScope()
	return nil
}

func (b *Builder) s3Bucket(k *s3Bucket, ln int) error {
	name := strings.ToLower(strings.TrimSpace(k.Name))
	if !s3NameRE.MatchString(name) || strings.Contains(name, "..") {
		b.issue(Issue{Line: ln, Message: fmt.Sprintf("bucket name %q is not a storage bucket name: skipped", line(k.Name, 80))})
		return nil
	}
	if k.Exists != 1 {
		return nil // not found, or unknown: nothing was seen
	}
	provider := tokenOf(k.Provider)
	if provider == "" {
		provider = "aws"
	}
	host := s3Host(provider, name, k.Region)
	a := ctis.Asset{Type: ctis.AssetTypeStorage, Value: host, Name: host, Properties: ctis.Properties{"storage_provider": provider}}
	if reg := strings.ToLower(strings.TrimSpace(k.Region)); s3RegionRE.MatchString(reg) {
		a.Properties["region"] = reg
	}
	if b.opts.DefaultConfidence > 0 {
		a.Confidence = b.opts.DefaultConfidence
	}
	id, err := b.asset(a)
	if err != nil || id == "" {
		return err
	}
	for _, c := range s3Classes {
		if !c.granted(k) {
			continue
		}
		f := ctis.Finding{
			Type:     ctis.FindingTypeMisconfiguration,
			Title:    c.title,
			Severity: c.severity,
			Category: "storage",
			RuleID:   c.rule,
			AssetRef: id,
			Native: &ctis.NativeIdentity{
				Scheme: ctis.NativeSchemeOther,
				VulnID: c.rule,
				RawRef: line(fmt.Sprintf("line %d", ln), ctis.MaxRawRefLen),
			},
			Remediation: &ctis.Remediation{Recommendation: "Remove the grant to everyone or to all authenticated users from the bucket policy and ACL, and turn on the provider's public access block."},
		}
		if b.opts.DefaultConfidence > 0 {
			f.Confidence = b.opts.DefaultConfidence
		}
		if err := b.finding(f); err != nil {
			return err
		}
	}
	return nil
}
