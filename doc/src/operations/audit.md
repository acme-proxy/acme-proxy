# Audit Trail

A certificate authority's most important record is not what it holds but what it
did: who asked it to sign something, from where, and what it answered.
`acme-proxy` writes that down in one append-only table and surfaces it in three
places — the CLI, the JSON API and the panel.

There is deliberately **no `audit.enabled`**. Recording who asked the CA to sign
something is not a feature of this server, it is what a CA does. The only thing
an operator can switch off is the reverse-DNS lookup, because that one costs a
network round trip and there are estates where it can never succeed.

## What gets recorded

Two different things, in two different places.

**Traceability columns**, on the rows themselves:

| Table | Columns |
|---|---|
| `accounts` | `created_ip` / `created_ptr` — where `newAccount` was called from, frozen at creation; `last_seen_at` / `last_seen_ip` / `last_seen_ptr` — where the key last authenticated a request |
| `orders` | `created_ip` / `created_ptr` — where the order was opened from |

**The audit log**, one row per CA action *and per refusal*:

| Event | Written when |
|---|---|
| `certificate_issued` | the signer returned a certificate |
| `certificate_issue_failed` | finalize was refused after the order was ready — a bad CSR, a CSR/order mismatch, a filter denial, or the backend's own failure |
| `certificate_revoked` | a revocation succeeded, whether through ACME, the CLI or the panel |
| `certificate_revoke_failed` | a revocation was refused — including `alreadyRevoked`, an unauthorized caller, and an unknown certificate |

The refusals are the point. A stream of `certificate_revoke_failed` rows naming
certificates that do not exist is somebody enumerating serials, which is exactly
the question a trail exists to answer.

Two boundaries worth knowing:

- **Nothing is ever compared against any of this.** Pinning an identity to an
  address breaks CGNAT and mobile clients, so these columns answer "who asked
  for this certificate, and from where", never "may this request proceed".
- **None of it reaches an ACME object.** The wire format is RFC 8555's and stays
  that way. The trail is visible through the admin surfaces only.

### What is *not* recorded

Refusals that never reached a CA action. A request rejected for a bad signature,
a replayed nonce or an unready order is protocol bookkeeping — nothing was
signed, nothing was withdrawn, and recording it would bury the rows that matter.
For the same reason, a `revokeCert` payload that cannot be parsed at all writes
nothing: a row naming no subject is noise.

## Reading it from the CLI

```bash
acme-proxy audit list
acme-proxy audit show 4213
```

| Command | Flags |
| --- | --- |
| `audit list` | `--profile`, `--account-id`, `--order-id`, `--cert-serial`, `--event`, `--outcome`, `--since-days <n>`, `--limit <n>`, `--offset <n>`, `--json` |
| `audit show <id>` | `--json` |
| `audit cleanup` | `--older-than <days>` *(prompts)* |

`audit list` is **paged**, defaulting to 50 rows, as `account list` and `order
list` are. This table grows a row per issuance for the life of the deployment,
so it always prints `N of M row(s)` — a page must never be mistaken for the
whole trail. There is no "everything" spelling on purpose; on a year-old CA that
is a terminal full of scrollback and a table loaded into memory. Page with
`--offset`, and see [Paging](cli.md#paging) for the window every listing shares
and the `--json` envelope it answers with.

```console
$ acme-proxy audit list --outcome failure --since-days 7
4213      2026-08-09T18:22:04Z  certificate_issue_failed    prod          acme:acct-9f2c              10.4.1.19 (web7.corp.example)              api.corp.example  reason=badCSR
1 of 1 row(s).
```

**An unknown `--event` or `--outcome` is refused by name**, listing the values
this build knows. Passed through to SQL it would answer "no rows", which looks
exactly like "nothing happened" — the single most misleading answer an audit
tool can give.

`audit show` prints one field per line, omitting every field that was not
recorded rather than showing it as empty:

```console
$ acme-proxy audit show 4213
id           4213
created      2026-08-09T18:22:04Z
event        certificate_issue_failed
outcome      failure
profile      prod
actor        acme:acct-9f2c
account      acct-9f2c
order        ord-71ab
client_ip    10.4.1.19
client_ptr   web7.corp.example
user_agent   certbot/2.9.0
request_id   01J9F2K7Q4
reason       badCSR
identifiers  api.corp.example
```

### The actor

Every row names who acted, as a kind plus an optional id:

| Kind | Meaning |
|---|---|
| `acme` | an ACME client, identified by its account id |
| `admin` | a web admin operator, identified by username |
| `cli` | someone on the host — there is no request and no address, and the row says so |
| `system` | the server itself, e.g. a relayed order settling in the background |

An administrative revocation is attributed to **the operator, not the
certificate's owner**. Recording the client there would say the opposite of what
happened.

## Retention

`audit.retention_days = 0` — the default — keeps everything for ever, which is
the right default for a trail whose value is that it is complete. Setting it
non-zero spawns a daily sweep running the identical `DELETE` as:

```bash
acme-proxy audit cleanup --older-than 365
```

This is **the only command in the binary that destroys audit history**, so it is
confirm-gated and its prompt names the number of rows it is about to remove. Use
`-y` to skip the prompt in a cron job.

> **The web admin cannot prune the trail.** `/api/audit` and `/ui/audit` are
> read-only, and there is no route to list, because the first thing a stolen
> session would do is erase what it had done — and a trail that can be erased by
> the thing it is watching proves nothing. Pruning happens on the host, or on a
> schedule set in configuration.

## Reading it from the web admin

| Surface | |
|---|---|
| `GET /api/audit?profile=&accountId=&orderId=&certSerial=&event=&outcome=&limit=&offset=` | the paged envelope every list endpoint returns |
| `GET /api/audit/{id}` | one row |
| `/ui/audit` | the list, filterable, with a detail page per row |

The API omits absent fields rather than sending them as `null`, so a client can
test for presence directly. There is no `since` filter on this surface: a
browser filters by picking a page, and a date parser here would be a second
definition of "how far back" that the CLI already has.

> **Rows carry remote text.** A `User-Agent` and a reverse DNS name are both
> written by whoever is on the other end — the PTR for a client's address is
> controlled by whoever runs that address's reverse zone. The panel escapes them
> like any other untrusted value, and `tests/admin_pages.rs` pins it.

## Why it survives deletion

`audit_log` is the one table in the schema with **no foreign keys**, and that is
the design rather than an oversight. An audit row has to outlive `account
delete` and `order delete`; a `CASCADE` would destroy the evidence along with
its subject. So `account_id` and `order_id` are plain columns naming a row that
may be gone, and the identifiers are frozen into the row rather than joined back
to an order that no longer exists.

The rest follows from the same rule: rows are only ever inserted — there is no
setter and no `UPDATE` anywhere in the crate — and the primary key is
`AUTOINCREMENT`, so SQLite cannot reuse the rowid of a purged row.

## Configuration

See [`[audit]`](../configuration/reference.md#audit) for the three keys. The
section is process-wide rather than per-profile: the trail describes the CA, not
one of its endpoints.
