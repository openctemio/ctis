# Contributing

Thank you for helping. Open an issue to discuss a larger change first, keep each pull
request to one concern, and include tests where the change is code. Security issues go
to the address in [SECURITY.md](SECURITY.md), not to a public issue.

A change to the format itself (a new member, a new enum value, a new rule, anything
that changes what a valid document is or what it means) starts as a proposal; see
[proposals/README.md](proposals/README.md). How decisions are made is in
[GOVERNANCE.md](GOVERNANCE.md).

## Developer Certificate of Origin

Contributions to this repository are made under the
[Developer Certificate of Origin 1.1](https://developercertificate.org/) (DCO). There
is no contributor license agreement to sign. By adding a `Signed-off-by` line to a
commit you certify the following:

```text
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

### How to sign off

Add the trailer with `git commit -s`. It uses the name and e-mail address of your git
configuration:

```text
Signed-off-by: Jane Doe <jane@example.org>
```

The address must be the commit's author address. The `dco` check fails on a commit
without a matching sign-off and lists it. To fix the commits of a branch, run
`git rebase --signoff <base>` and push again. Merge commits and commits made by
dependency bots are not checked.

## Licences of contributions

Your contribution is licensed under the licence of the files it changes (see
[README.md, License](README.md#license)):

- the specification text and other prose under `docs/` and `proposals/`: Creative
  Commons Attribution 4.0 International ([LICENSE-docs](LICENSE-docs));
- schemas, examples, conformance vectors and code: Apache License 2.0
  ([LICENSE](LICENSE)), whose section 5 applies to contributions.

Contributing also makes the patent commitment in [PATENTS.md](PATENTS.md) for your
contribution to the specification.

## Changes to the format

Every change to the format updates the schema, the Go types, the examples, the
conformance vectors and the CHANGELOG together. `go test ./...` fails when the schema
and the Go types disagree, when an example does not validate, or when the generated
field reference in `docs/spec.md` is stale (refresh it with
`go test -run TestSpecFieldReference -update`).

## Go version

Each module's `go` directive is the minimum its code and dependencies need,
never newer than the oldest Go the consumers build with (the sensor SDK, the
platform API and the sensor). CI enforces the ceiling with
`.github/scripts/check-go-directive.sh`; raise its floor only after every
consumer builds with that Go.

## Modules and the interoperability adapters

The repository holds several Go modules: the core (`.`), one module per
standard-format adapter (`v2/interop/<format>`) and the command (`v2/cmd/ctis`).
CI builds, tests and lints every one of them
(`.github/scripts/modules.sh`); each depends on the standard library and the
core module only. A change to a standard format's mapping changes that
adapter only: its mapping files (`v2/interop/<format>/<version>/`), its vectors
(`conformance/interop/<format>/<version>/`) and its `CHANGELOG.md`, released
with a tag `v2/interop/<format>/vX.Y.Z`. How to add an upstream version is in
[docs/interop.md](docs/interop.md).
