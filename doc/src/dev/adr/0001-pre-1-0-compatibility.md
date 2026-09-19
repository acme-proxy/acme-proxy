# ADR 0001: Before 1.0.0, only the database schema is a compatibility promise

## Status

Accepted.

## Context

A project that promises stability on every surface from its first release ends
up carrying a compatibility layer for every shape it has ever had: aliases for
renamed keys, dual syntaxes, lowering passes that translate an old section into
a new one. Each of these is code that must be tested, documented and reasoned
about for as long as the promise lasts, and each makes the next redesign harder.

acme-proxy is still finding its design. Several subsystems were replaced
wholesale rather than extended: the filter chain became a policy engine
([Policy](../../filters/policy.md)), the Mattermost notifier became a generic
webhook ([Webhook](../../notifications/webhook.md)), the `acme_proxy` signer
became `relay`, and `filter.netbox` became `[ipam]`. None of these would have
been worth doing if each had to keep reading the old shape.

One surface cannot be treated this way. The database holds accounts, orders and
issued certificates that clients and relying parties depend on, and `sqlx`
checksums every applied migration. An upgrade that cannot open the existing
database is not an upgrade.

## Decision

Before 1.0.0 the **database schema is the only compatibility guarantee**:
`crates/store/migrations/` is append-only ([ADR
0003](0003-migrations-frozen-and-explicit.md)), so an upgrade is starting the
new binary against the existing database.

Everything else may be renamed or removed in any release: configuration keys,
profile names and the ACME URLs derived from them, the admin JSON API, log event
names and the CLI. Such a change owes exactly three things:

- An entry under the release's `### Breaking` heading in `CHANGELOG.md`, naming
  the old spelling and the new one. The changelog's
  [Compatibility](https://github.com/acme-proxy/acme-proxy/blob/main/CHANGELOG.md#compatibility)
  section is the canonical statement of this policy; the README, `SECURITY.md`
  and the book each carry one sentence linking to it.
- A **startup refusal naming the removed key** wherever practical, so an
  unmigrated configuration stops the server instead of coming up looking
  configured. This is a one-line error message, not a compatibility path.
- **Never an alias, a dual syntax or a legacy lowering.** The old shape is
  deleted; the new code does not learn to read it.

The refusals themselves are removed at 1.0.0.

## Consequences

- A redesign costs one changelog entry and one diagnostic, which is what makes
  replacing a subsystem cheaper than accreting around it.
- A key must still *parse* to be refused by name. The removed `[filter]` fields
  therefore survive in `crates/core/src/config/types/filter.rs`; a field that
  is gone would fail as an opaque serde error instead of a named one.
- Operators must read the Breaking section before an upgrade. `acme-proxy filter
  show` builds a policy exactly as startup does, so it checks a migrated
  configuration before a restart.
- Frozen means frozen: the comments inside committed migrations still say
  `acme_proxy` where the code says `relay`, because editing them would change
  their checksum ([ADR 0003](0003-migrations-frozen-and-explicit.md)).

The how-to for a rename is in
[Contributing](../contributing.md#changing-a-configuration-key).

## Enforced by

- `refuse_removed_keys` in `crates/policy/src/filter/build.rs`, guarded by
  `every_removed_key_is_refused_by_name`.
- `the_old_acme_proxy_backend_name_is_refused_by_its_new_one`
  (`crates/signer/src/lib.rs`) and
  `the_removed_mattermost_backend_is_refused_by_name`
  (`crates/jobs/src/notify/mod.rs`).
- `the_netbox_type_is_refused_by_name` (`crates/policy/src/filter/build.rs`).
- The Breaking entry and the "no alias" rule are review only.
