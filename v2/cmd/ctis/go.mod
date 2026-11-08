module github.com/openctemio/ctis/v2/cmd/ctis

go 1.22

require (
	github.com/openctemio/ctis/v2 v2.0.3
	github.com/openctemio/ctis/v2/interop/csaf v0.1.0
	github.com/openctemio/ctis/v2/interop/cyclonedx v0.1.0
	github.com/openctemio/ctis/v2/interop/ocsf v0.1.0
	github.com/openctemio/ctis/v2/interop/openvex v0.1.0
	github.com/openctemio/ctis/v2/interop/sarif v0.1.0
	github.com/openctemio/ctis/v2/interop/spdx v0.1.0
)

// No replace directives: "go install github.com/openctemio/ctis/v2/cmd/ctis@<version>"
// refuses them. To build against unreleased core or adapter changes, use a
// local go.work (not committed).
