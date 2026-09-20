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
| [0006](0006-no-slow-or-privileged-work-in-a-request.md) | A request does no slow or privileged work; it queues it | Accepted |
| [0007](0007-role-processes.md) | One binary runs as role processes, and only the worker holds the CA key | Accepted |
| [0008](0008-shared-state-in-the-database.md) | State that more than one process can see lives in the database | Accepted. One exception stands, the web admin's login limiter, for as long as |
| [0009](0009-dependency-policy.md) | Dependencies are pure Rust on `ring`, add no global state, and earn their place | Accepted; metrics clause superseded by [0011](0011-metrics-on-prometheus-client.md), crypto clause narrowed by [0014](0014-postgresql-beside-sqlite.md) |
| [0010](0010-error-types.md) | Errors derive `thiserror`, carry their whole message, and panic only at startup | Accepted. This was re-argued more than once before it was written down, which |
| [0011](0011-metrics-on-prometheus-client.md) | Metrics are built on `prometheus-client`, one registry per scrape | Accepted |
| [0012](0012-container-images-are-built-natively-per-architecture.md) | Images are built natively per architecture, uncached, and published only past a guard | Accepted |
| [0013](0013-trunk-and-release-branches.md) | `main` is the trunk, and a patch line is a release branch cut when a fix needs one | Accepted |
| [0014](0014-postgresql-beside-sqlite.md) | PostgreSQL is chosen by the URL's scheme, over one set of queries | Accepted |

### Decisions argued elsewhere

Some decisions are explained where their subject lives, and have no record
here, because a second copy would drift from the first.

In the book:

- [Hoisting the JWS checks into an
  extractor](../architecture.md#request-flow-and-extractors), and the two
  security properties it must keep.
- [Pluggable signing keys](../architecture.md#pluggable-signing-keys): `rcgen`'s
  own `SigningKey` as the seam, and signing on the blocking pool.
- [Secrets are stored three different ways, on
  purpose](../database.md#secrets-are-stored-three-different-ways-on-purpose)
- [Columns nothing ever compares
  against](../database.md#columns-nothing-ever-compares-against): no identity is
  pinned to an address or a User-Agent.
- [Evidence has no foreign
  keys](../database.md#the-audit-trail-has-no-foreign-keys-deliberately): the
  audit trail and the revocation ledger outlive what they describe.
- [Profiles](../../core/profiles.md): an endpoint is a profile, its path is
  derived from its name, and it is a database boundary.
- [Bypass is not a
  shortcut](../../challenges/index.md#bypass-is-not-a-shortcut): why validation
  is on by default.
- [When a check cannot
  decide](../../filters/policy.md#when-a-check-cannot-decide): the filter's
  three-valued answers.
- [Reloading the configuration](../../operations/reload.md): a reload is a
  rebuild and a swap, all or nothing.
- [Why a second listener](../../operations/webadmin.md#why-a-second-listener),
  and the web admin's [CSRF](../../operations/webadmin.md#csrf),
  [roles](../../operations/webadmin.md#roles) and [read-only audit
  view](../../operations/webadmin.md#the-audit-trail-is-read-only-here).
- [Why the audit trail survives
  deletion](../../operations/audit.md#why-it-survives-deletion).
- [Delivery semantics](../../notifications/index.md#delivery-semantics) of
  notifications.
- [Paging](../../operations/cli.md#paging): every listing is paged and says so.

In a module's own documentation (`//!`), where the decision concerns that
module alone:

- `crates/jobs/src/jobs/mod.rs`: why background work is a durable queue and not
  a `tokio::spawn`, and the `Retry`/`Failed` split every handler must honour.
- `crates/signer/src/local_ca/crl.rs`: how the CRL number stays monotonic across
  processes.
- `crates/policy/src/filter/policy.rs`: Kleene logic, and why a rule's stages
  are an intersection.
- `crates/policy/src/ipam/mod.rs`: why an inventory never denies, so an outage
  cannot fail open.
- `crates/core/src/script_hook.rs`: the one contract every `custom` script runs
  under.
- `crates/core/src/templating.rs`: `.html` escapes and `.j2` does not, decided
  by the name.
- `crates/jobs/src/metrics.rs`: bounded cardinality, families declared even
  when empty, and counters that survive a reload.
- `crates/jobs/src/notify/expiry.rs`: why the expiry notice is a digest.
- `crates/server/src/reload.rs`: the swap's mechanics and what stays frozen.

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
