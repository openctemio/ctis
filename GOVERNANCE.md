# Governance

This document says what CTIS is, who decides changes to it, and how. It applies to this
repository. CTIS stands for **CTEM Interchange Schema**: a document format for the
assets, findings and coverage that continuous threat exposure management tools exchange.

## 1. Scope

The standard consists of:

- the specification text (`docs/spec.md`) and the design records (`docs/proposals-*.md`,
  `proposals/`);
- the JSON Schemas (`schemas/`);
- the conformance vectors (`conformance/`) and the validator CLI (`cmd/ctis`).

The Go module in this repository is the reference implementation: types, validation,
canonical forms, fingerprints, importers and exporters. It is held to the specification
and the conformance vectors like any other implementation.

Receiver-specific behaviour (limits, what a platform stores, how it binds a report to a
job) is not part of the standard. It is described in informative receiver profiles
(`docs/profiles/`). Platform-to-sensor orchestration contracts that live in this
repository today move to their own module; they are not part of the format.

## 2. Roles

- **Contributors**: anyone who opens an issue, a proposal or a pull request. Contributions
  are made under the Developer Certificate of Origin ([CONTRIBUTING.md](CONTRIBUTING.md)).
- **Maintainers**: review and merge changes, cut releases and run the proposal process.
  They are listed in [MAINTAINERS.md](MAINTAINERS.md).
- **Steering group**: the maintainers acting together on the decisions of section 3.
  The group has three to five seats. While one organisation is the only implementer, its
  maintainers hold the seats. From the second independent implementer on, no single
  organisation holds more than half of the seats; the group invites maintainers from
  implementers to reach that balance.

A contributor becomes a maintainer by a steering-group decision after sustained, quality
contributions. A maintainer who is inactive for six months may be moved to emeritus.

## 3. Decisions

- Day-to-day changes (fixes, tests, documentation, reference implementation) need one
  maintainer's approval and green checks.
- A change to the format follows the proposal process ([proposals/README.md](proposals/README.md)):
  a public comment period of at least 14 days, then a decision by consensus of the
  steering group. When consensus fails, a two-thirds majority of the seats decides.
- Changes to this document, to the licences or to the patent commitment need a
  two-thirds majority of the seats and a 30-day public comment period.
- Decisions and their reasons are recorded in the pull request or proposal they concern.
  Steering-group meetings, when held, publish minutes in the repository.

## 4. Versioning and compatibility

- The specification uses semantic versions. A minor version is additive: a document valid
  under 1.N stays valid and means the same under 1.N+1. Renames and removals happen only
  in a new major version, which is one planned release with a published upgrade path.
- A breaking proposal waits for the next major. A member is marked deprecated, with its
  replacement, for at least one minor version before a major removes it.
- The previous major version is supported (security fixes, clarifications) for 12 months
  after the next major is released.
- Each release has a changelog entry, a git tag and immutable tagged schema files.
- New features may ship first as an experimental extension namespace and move into the
  core when two independent implementations exist.

## 5. Licences and patents

- Specification text and other prose: [CC BY 4.0](LICENSE-docs).
- Schemas, examples, conformance vectors and code: [Apache-2.0](LICENSE).
- Patents: [PATENTS.md](PATENTS.md).

The specification text was published under Apache-2.0 until 2026-11-03, when the project
moved its prose to CC BY 4.0 so that the specification can be quoted and adapted with
attribution, as is usual for open standards. Copies obtained before that date remain
available under Apache-2.0.

## 6. Security

Security issues in the specification or the reference implementation are reported
privately as described in [SECURITY.md](SECURITY.md). A fix that changes the format
follows the proposal process after disclosure, with a shortened comment period when the
steering group agrees it is urgent.

## 7. Neutral home and name

The project intends to move to a vendor-neutral foundation once at least three
independent organisations implement CTIS, and keeps its licences, process and records
in a form that allows that move. The final name and mark are decided at that step, after
a trademark search.

## 8. Conformance claims

An implementation may state "CTIS 1.N compatible" (with the profiles it covers) when it
passes the public conformance vectors with the validator CLI. Claims are
self-certified; the maintainers may keep a public list of implementations.
