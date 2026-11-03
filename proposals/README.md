# CTIS proposals

A proposal is how the format changes: a new member, object, enum value or asset type, a
change to a rule, or the removal of anything. Fixes to the reference implementation,
tests and wording that does not change meaning are ordinary pull requests.

## Process

1. **Discuss.** Optional but recommended: open an issue to describe the problem and test
   the interest.
2. **Write.** Copy [0000-template.md](0000-template.md) to `proposals/NNNN-short-title.md`
   (take the next free number) and open a pull request with it. The proposal states the
   problem, the design, its compatibility class, security and privacy considerations and
   the conformance vectors it adds.
3. **Comment.** The pull request stays open for public comment for at least 14 days
   after it is announced in the repository's discussions or issues.
4. **Decide.** The steering group decides by consensus ([GOVERNANCE.md](../GOVERNANCE.md)
   section 3) and records the decision and its reasons in the proposal's status line:
   `accepted`, `rejected`, `deferred` or `withdrawn`. An accepted proposal is merged as a
   record.
5. **Implement.** The schema, the Go types, the specification text, the examples, the
   conformance vectors and the changelog change together in one or more pull requests
   that link the proposal. The proposal's status becomes `implemented in <version>`.

## Compatibility classes

- **Additive**: valid documents stay valid and keep their meaning (new optional member,
  new enum value with a documented fallback, a loosened constraint). Ships in the next
  minor version.
- **Breaking**: anything else (rename, removal, tightened constraint, changed meaning).
  Waits for the next major version and needs an entry in that version's upgrade path.

## Experimental features

A proposal may first ship as an extension namespace (`extensions`), outside the core.
It moves into the core when two independent implementations use it.

## Earlier design records

Proposals made before this process are in [docs/proposals-1.4.md](../docs/proposals-1.4.md)
and [docs/proposals-2.0.md](../docs/proposals-2.0.md).
