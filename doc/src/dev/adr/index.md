# Architecture Decision Records

An architecture decision record (ADR) holds the *why* behind a design: the
problem it answers, the choice made, and what that choice rules out. The rest of
the documentation says what the server does. The module docs (`//!`) say what
each piece of code guarantees. The ADRs are where the argument lives, so that
the argument is not restated wherever the decision is mentioned.

Read the relevant ADR before changing something it covers. If a change reverses
a decision, write a new ADR that supersedes the old one and change the old one's
status. Do not rewrite its argument after the fact.

| ADR | Decision | Status |
|---|---|---|
| [0001](0001-pre-1-0-compatibility.md) | Before 1.0.0, only the database schema is a compatibility promise | Accepted |
| [0002](0002-workspace-layering.md) | One binary over a layered workspace of lockstep crates | Accepted |
| [0003](0003-migrations-frozen-and-explicit.md) | Migrations are append-only and applied only by the schema owners | Accepted |
| [0004](0004-uuid-v7-blob-ids.md) | Row ids are UUID v7 stored as BLOBs, and their type says where they came from | Accepted |
| [0005](0005-rust-enums-own-the-vocabularies.md) | A Rust enum owns each vocabulary, and SQL checks only the closed ones | Accepted |

### Decisions argued on other pages

Some decisions are explained where their subject is documented, and have no
record here, because a second copy would drift from the first:

- [Secrets are stored three different ways, on
  purpose](../database.md#secrets-are-stored-three-different-ways-on-purpose)
- [Columns nothing ever compares
  against](../database.md#columns-nothing-ever-compares-against): no identity is
  pinned to an address or a User-Agent.
- [Evidence has no foreign
  keys](../database.md#the-audit-trail-has-no-foreign-keys-deliberately): the
  audit trail and the revocation ledger outlive what they describe.

## Writing an ADR

Name the file `NNNN-kebab-title.md`, taking the next free number, and list it
both in the table above and in `SUMMARY.md` under this page. `doc/lint.py`
refuses an ADR that is missing from either list, or that lacks one of the five
sections below.

The title is `# ADR NNNN: <decision>`, and the sections come in this order:

- **`## Status`**: `Accepted`, or `Superseded by ADR NNNN`. Name a
  proposal to replace it if one is on record.
- **`## Context`**: the problem, and the history that makes the rule
  necessary. History with no rule behind it does not belong here — git and
  `CHANGELOG.md` already keep it.
- **`## Decision`**: what was chosen, stated as rules.
- **`## Consequences`**: what the decision costs and what it rules out.
- **`## Enforced by`**: the tests, startup refusals and type-level constructs
  that hold the decision in place, named so that a grep finds them. Write
  "Review only" when nothing does.

Link to the page that owns a configuration key rather than restating its
default, since the book documents each key in exactly one file.
