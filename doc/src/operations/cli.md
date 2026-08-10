# Admin CLI

`acme-proxy` embeds an administrative command-line interface in the same binary,
so a full deployment never needs a separate tool to manage its state (accounts,
orders, the audit trail, nonces, the upstream account, and EAB credentials).

## Invoking it

`serve` is the **default** subcommand, so a bare `acme-proxy` starts the server.
You reach the admin CLI by *naming* a subcommand:

```bash
acme-proxy account list
```

Every command reads the same configuration as the server — `config.toml` in the
working directory, or `ACME_PROXY_CONFIG`, plus `ACME_PROXY_*` environment
overrides — so it must be run where the configuration points at the same
database. There is no `--config` flag.

Commands operate directly on SQLite. Running them against a live server is safe
(the database is in WAL mode), but they act immediately and are not
transactional across the server's own in-flight requests.

### Global flags

**`-y`, `--yes`** — skip the interactive "Are you sure?" prompt on destructive
commands. It is a global flag, so it may be given anywhere on the line. `account
delete`, `order delete`, `audit cleanup`, `admin user delete` and `admin user
totp reset` prompt; nothing else is gated by it.

**`--json`** — where supported, emit JSON instead of the human-readable line
format. List commands print a **single JSON array**; single-item commands print
one JSON object. (It is not newline-delimited JSON.)

## Account management

| Command | Flags |
| --- | --- |
| `account list` | `--profile <name>`, `--json` |
| `account show <id>` | `--json` |
| `account update-contact <id>` | `--contact <uri>` (repeatable) |
| `account deactivate <id>` | — |
| `account delete <id>` | *(prompts)* |

- `account list --profile` restricts the listing to one ACME endpoint. Without
  it, accounts from every profile are listed — the admin CLI is deliberately
  unscoped by default, unlike the request path, which always scopes by profile.
- `account list` shows, per account, the address its key was last seen from and
  that address's reverse name (`ip (ptr)`, the address alone when no name
  resolved, `-` when neither was recorded). `account show` prints one field per
  line and adds where the account was *registered* from. Nothing in the server
  ever compares against these — pinning an identity to an address breaks CGNAT
  and mobile — and none of them reaches an ACME object.
- `account deactivate` prevents the account from making any further requests. It
  is the operator-side equivalent of a client deactivating itself.
- `account delete` cascades: every order, authorization and challenge belonging
  to the account is destroyed with it. The prompt names what will go.

## Order management

| Command | Flags |
| --- | --- |
| `order list` | `--profile <name>`, `--account-id <id>`, `--status <status>`, `--json` |
| `order show <id>` | `--json` |
| `order delete <id>` | *(prompts)* |
| `order revoke <id>` | `--reason <n>` |

- `order show` surfaces `revokedAt` and `revocationReason`, which are
  deliberately absent from the ACME JSON a client sees — revocation state is
  admin-visible only.
- `order revoke` is the operator-side equivalent of `POST /revokeCert`, for an
  out-of-band compromise report a client cannot or will not act on. It calls the
  signer's own `revoke` hook, so a local CA's CRL genuinely reflects it. It is
  **not** confirm-gated, because revocation only ever tightens trust. See
  [Revocation & CRL](revocation.md).

## Audit trail

| Command | Flags |
| --- | --- |
| `audit list` | `--profile <name>`, `--account-id <id>`, `--order-id <id>`, `--cert-serial <hex>`, `--event <e>`, `--outcome success\|failure`, `--since-days <n>`, `--limit <n>`, `--offset <n>`, `--json` |
| `audit show <id>` | `--json` |
| `audit cleanup` | `--older-than <days>` *(prompts)* |

- `audit list` is **paged**, defaulting to 50 rows, unlike `account list` and
  `order list`. This table grows a row per issuance for the life of the
  deployment, so it always prints `N of M row(s)` — a page must never be
  mistaken for the whole trail. Page with `--offset`.
- **An unknown `--event` or `--outcome` is refused by name**, listing the values
  this build knows. Passed through to SQL it would answer "no rows", which reads
  exactly like "nothing happened".
- `audit show` prints one field per line, omitting every field that was not
  recorded rather than rendering it empty.
- `audit cleanup` is the **only command in this binary that destroys audit
  history**, so it is confirm-gated and its prompt names the row count.
  `audit.retention_days` runs the same sweep daily.

The web admin can read this trail but not prune it — see
[Audit Trail](audit.md).

## Nonce housekeeping

| Command | Flags |
| --- | --- |
| `nonce cleanup` | `--ttl-seconds <n>` |

Deletes expired nonces. The server already sweeps them on an interval for the
life of the process, so this is mainly a debugging tool. `--ttl-seconds`
defaults to the configured `nonce.ttl_seconds`.

## Upstream account management

Only relevant with `signer.backend = "relay"`.

| Command | Flags |
| --- | --- |
| `upstream show` | `--profile <name>`, `--json` |
| `upstream register` | `--profile <name>`, `--eab-kid <kid>`, `--eab-hmac-key-file <path>` |

**`--profile` is required whenever the configuration defines more than one
profile.** `[signer]` is a per-profile section, so acting on "the upstream"
without saying which one would be acting on nothing. It may be omitted only when
exactly one profile exists.

`upstream register` performs this proxy's own `newAccount` at the upstream CA
and stores the resulting account URL beside `account_key_path` with a `.kid`
extension. Only that first startup ever contacts the upstream.

> **Security note**: the EAB HMAC secret is read from `--eab-hmac-key-file`, or
> prompted on **stdin**. It is deliberately not accepted as a command-line
> argument, because argv is visible to every user on the host via `ps`. Omit
> `--eab-kid` entirely when the upstream requires no External Account Binding.

## External Account Binding (EAB)

| Command | Flags |
| --- | --- |
| `eab create` | `--label <text>`, `--profile <name>`, `--json` |
| `eab list` | `--json` |
| `eab show <kid>` | `--json` |
| `eab revoke <kid>` | — |

- `eab create` prints the generated HMAC secret **once**. It is stored but never
  shown again, so a lost secret is replaced, not recovered.
- `--profile` binds the credential to one endpoint. Omitted, the credential is
  accepted at *every* profile — which is what an unscoped credential means, and
  is usually not what you want in a multi-tenant deployment.
- `eab revoke` takes effect immediately, with no restart: credentials are read
  from the live database on every `newAccount`.

See [External Account Binding](../features/eab.md) for the protocol side.

## Web admin operators and sessions

The web admin has no sign-up page: the first operator is created here. These
commands work whether or not `[admin]` is enabled, and whether or not the server
is running.

| Command | Flags |
| --- | --- |
| `admin user create <username>` | `--password-file <path>` |
| `admin user list` | `--json` |
| `admin user passwd <username>` | `--password-file <path>` |
| `admin user delete <username>` | confirm-gated; `-y` skips |
| `admin user disable\|enable <username>` | — |
| `admin user totp status <username>` | `--json` |
| `admin user totp reset <username>` | confirm-gated; `-y` skips |
| `admin user totp recovery-codes <username>` | prints them once |
| `admin session list` | `--username <u>`, `--json` |
| `admin session revoke` | `--user <u>` **or** `--all` |

```console
$ printf '%s' "$PASSWORD" | acme-proxy admin user create alice
Created admin user alice (bac6a47e-711b-4e8e-858e-417da905dab9).
```

- **The password never goes in argv.** There is no `--password` flag and `clap`
  rejects one: argv is visible via `ps` and lands in shell history. Supply it on
  stdin or with `--password-file` (which strips one trailing newline). Typing it
  interactively works but echoes, and the command says so.
- Minimum 12 characters. Stored as PBKDF2-HMAC-SHA256 at 600 000 iterations, and
  **not recoverable** — a lost password is replaced with `admin user passwd`.
- `admin user passwd` and `admin user disable` both **revoke every session that
  user holds**. A password changed because it may have leaked, that left the
  leaked session alive, would be a change in name only.
- Usernames are stored lowercased, so `Alice` and `alice` cannot become two
  logins that read as one in a log line.
- There is deliberately **no `admin user totp enrol`**. Enrolling happens in the
  panel, which shows the setup key once behind `Cache-Control: no-store`; there
  is no way to do it from a terminal that does not put that key into scrollback
  and shell history — the same reasoning that keeps a password out of `argv`.
  What the shell is for is the case the panel cannot serve: `totp reset` is how
  an operator who has lost their authenticator gets back in. It asks first,
  because it removes a security control rather than tightening one, and it takes
  the recovery codes and every live session with it.
- `admin session list` shows a fingerprint of the stored token hash, never the
  hash itself.

See [Web Admin — Users & Sessions](webadmin_users.md) for the full treatment.
