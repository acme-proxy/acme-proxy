# ADR 0004: Row ids are UUID v7 stored as BLOBs, and their type says where they came from

## Status

Accepted.

## Context

Row ids started as UUID v4 strings. Two costs followed:

- A random id is written into an index at a random leaf on every insert. SQLite
  feels that mildly, and PostgreSQL would pay a page split and a full-page WAL
  write per row. That backend is
  [issue #4](https://github.com/acme-proxy/acme-proxy/issues/4).
- The paged listings break ties on a whole-second `created_at` with
  `ORDER BY created_at, id`. With v4 ids, rows created in the same second come
  back in a different random order for each pair.

Converting ids from text to BLOBs added a third problem. SQLite never compares a
bound `String` equal to a BLOB, so an internal lookup that kept a `&str`
parameter would match nothing, silently, for ever. The case that exposed this
was a job-retention test. It inserted a job with a hand-written id and asserted
it was gone afterwards. Had `Job::find_by_id` taken a `&str` and parsed it
internally, that assertion would have passed whether or not the sweep had run.

## Decision

- **Every id is minted in one place** (`mint()` in `crates/store/src/id.rs`), as
  a UUID version 7. The leading 48-bit millisecond timestamp makes ids created
  close together share a prefix, and makes them sort by creation.
- **Ids are stored as the 16 bytes themselves.** `sqlx`'s `uuid` feature encodes
  a `Uuid` as a SQLite BLOB, and maps the same type to PostgreSQL's native
  `uuid`.
- **Existing rows keep their v4 ids.** An id is a foreign key, a `kid` is a
  credential a client stored, and an order id is part of a URL a client polls.
  A table can therefore hold both versions, and only the v7 ids sort by
  creation.
- **The parameter type records provenance.** In `crates/store/src/`:
  - an id typed `&str` may be junk from outside the process, so it is parsed
    and an unparseable value answers "absent";
  - an id typed `Uuid` was read out of a row.

  There is no third case, and no parallel `_uuid` variant of any function.
- **`parse()` is deliberately narrower than `Uuid::try_parse`.** It accepts only
  the 36-character hyphenated form that `Uuid::to_string()` produces, so an id
  written in another spelling answers "not found" rather than resolving.
- Columns that look like ids but do not point at a row stay text. The list,
  and how to query a BLOB id by hand, are in
  [Database Schema](../database.md#ids-are-uuid-v7-stored-as-bytes).

## Consequences

- An internal lookup handed a stale string fixture is a compile error rather
  than a silently empty result.
- Only a few functions keep `&str`, where the value genuinely arrives from
  outside the process (the request path and job payloads). They are listed in
  `crates/store/src/id.rs`.
- The conversion migration (`20260827120000_uuid_ids_as_blobs.sql`) is the
  worked example of the DROP-cascade hazard in [ADR
  0003](0003-migrations-frozen-and-explicit.md).
- Some fresh values are deliberately not row ids and do not go through `mint()`:
  the `x-request-id` fallback, the job lease owner and a notification's
  `delivery_id`.

## Enforced by

- The type system, for `&str` versus `Uuid`.
- `every_id_column_is_declared_a_blob` and
  `the_blob_migration_preserves_every_row` (`crates/store/src/db.rs`).
- The unit tests of `parse` in `crates/store/src/id.rs`.
