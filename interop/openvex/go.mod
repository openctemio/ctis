module github.com/openctemio/ctis/v2/interop/openvex

go 1.22

require github.com/openctemio/ctis/v2 v2.0.0

// Builds against the core module of this repository until v2.0.0 is
// tagged; a consumer's build ignores it.
replace github.com/openctemio/ctis/v2 => ../..
