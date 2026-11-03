module github.com/openctemio/ctis/v2/cmd/ctis

go 1.22

require (
	github.com/openctemio/ctis/v2 v2.0.0
	github.com/openctemio/ctis/v2/interop/csaf v0.1.0
	github.com/openctemio/ctis/v2/interop/cyclonedx v0.1.0
	github.com/openctemio/ctis/v2/interop/ocsf v0.1.0
	github.com/openctemio/ctis/v2/interop/openvex v0.1.0
	github.com/openctemio/ctis/v2/interop/sarif v0.1.0
	github.com/openctemio/ctis/v2/interop/spdx v0.1.0
)

// The command builds against the modules of this repository. These lines
// go once the core and the adapters are tagged, so that
// "go install github.com/openctemio/ctis/v2/cmd/ctis@<tag>" works (it
// refuses a module with replace directives).
replace (
	github.com/openctemio/ctis/v2 => ../..
	github.com/openctemio/ctis/v2/interop/csaf => ../../interop/csaf
	github.com/openctemio/ctis/v2/interop/cyclonedx => ../../interop/cyclonedx
	github.com/openctemio/ctis/v2/interop/ocsf => ../../interop/ocsf
	github.com/openctemio/ctis/v2/interop/openvex => ../../interop/openvex
	github.com/openctemio/ctis/v2/interop/sarif => ../../interop/sarif
	github.com/openctemio/ctis/v2/interop/spdx => ../../interop/spdx
)
