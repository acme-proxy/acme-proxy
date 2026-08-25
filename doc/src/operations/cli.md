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
format. Single-item commands print one JSON object. A **paged** list command
(`account list`, `order list`, `audit list`) prints the same envelope the admin
JSON API returns, so a script does not learn one shape for the shell and another
for the API:

```json
{ "items": [ … ], "total": 137, "limit": 50, "offset": 0 }
```

`total` is what the same filters match *unpaged*, which is the difference
between having read the table and having read a page of it. The unpaged
listings — `eab list`, `admin user list`, `admin session list` — print a bare
JSON array: those are tables an operator mints by hand, so there is no page and
no total to report. (Neither shape is newline-delimited JSON.)

**`--color <auto|always|never>`** — when to colour the human-readable output.
Also global. The default is `auto`: colour when the stream is a terminal and
`NO_COLOR` is unset or empty, which means a piped or redirected run is plain
without your having to say so.

- `always` colours regardless of the stream **and regardless of `NO_COLOR`** —
  it was typed on this command line, so it outranks both. That is what makes
  `acme-proxy audit list --color always | less -R` work.
- `never` never colours, whatever the terminal is.
- An unrecognised value is refused rather than treated as `auto`.

Colour is decided separately for stdout (the output) and stderr (error
messages), since the two are redirected independently. It is **semantic, never
decorative**: statuses (`valid`, `pending`, `revoked`…), audit events that name
a refusal, `filter explain`'s per-check verdicts, and the standing warnings such
as `eab create`'s "shown only this once". Labels, timestamps and identifiers are
never coloured.

**`--json` output never carries colour**, at any setting — it is the same bytes
a script parses today. So is every human-readable line under `--color never`.

Note this is not the same switch as `logging.ansi`, which colours the *server's*
log stream and is a configuration key rather than a flag; the CLI's colour is
not configurable, on purpose, since the right answer depends on the terminal in
front of you rather than on the deployment.

**`--version`** — print the build's own version and exit. It is the first thing
a bug report asks for, and the answer a checkout cannot give on a host where the
binary was copied in. `--help` is its counterpart and works at every level:
`acme-proxy audit --help` lists that group's subcommands.

## Shell completions

`acme-proxy completions <shell>` prints a completion script on stdout, for
`bash`, `elvish`, `fish`, `powershell` or `zsh`. It is generated from the same
command tree `clap` parses, so it covers every subcommand and flag, four levels
deep — `acme-proxy admin user totp ` completes to `status`, `reset` and
`recovery-codes`. Flag *values* complete only where the flag has a fixed set
`clap` knows about, which today is `--color`; `--status` and `--outcome` take a
string the command refuses by name, so a shell has nothing to offer for them.

The command reads neither the configuration nor the database, so it works
anywhere, including in a shell startup file and before a deployment exists.

```bash
# bash — system-wide, or ~/.local/share/bash-completion/completions/acme-proxy
acme-proxy completions bash | sudo tee /etc/bash_completion.d/acme-proxy

# zsh — any directory on $fpath; the file must be named _acme-proxy
acme-proxy completions zsh > ~/.zfunc/_acme-proxy

# fish
acme-proxy completions fish > ~/.config/fish/completions/acme-proxy.fish
```

Regenerate after upgrading: before 1.0.0 the CLI is not frozen, so a script kept
from an older binary can go on offering a subcommand that no longer exists. The
policy is stated in the
[changelog](https://github.com/acme-proxy/acme-proxy/blob/main/CHANGELOG.md#compatibility).

One limitation is the generator's rather than this CLI's: the `fish` script
stops completing at three levels, so `acme-proxy admin user totp ` offers
nothing past `totp`. The other four shells complete the whole tree.

## Man page

`acme-proxy man` prints the roff source of `acme-proxy.1` on stdout. Like
`completions`, it reads nothing and is generated from the command tree:

```bash
acme-proxy man | sudo tee /usr/share/man/man1/acme-proxy.1 > /dev/null
man acme-proxy
```

It is one page for the top-level command — the options, every subcommand with
its one-line purpose, the environment variables, the configuration file, and a
pointer back to this book. The per-flag detail of each subcommand lives in the
tables below rather than in the page, which is why `SEE ALSO` names the book.
Read it without installing anything with `acme-proxy man | man -l -`.

## Account management

| Command | Flags |
| --- | --- |
| `account list` | `--profile <name>`, `--limit <n>`, `--offset <n>`, `--json` |
| `account show <id>` | `--json` |
| `account update-contact <id>` | `--contact <uri>` (repeatable) |
| `account deactivate <id>` | — |
| `account delete <id>` | *(prompts)* |

- `account list --profile` restricts the listing to one ACME endpoint. Without
  it, accounts from every profile are listed — the admin CLI is deliberately
  unscoped by default, unlike the request path, which always scopes by profile.
  The listing is **newest first** and paged; see [Paging](#paging) below.
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
| `order list` | `--profile <name>`, `--account-id <id>`, `--status <status>`, `--expiring-in <days>`, `--hide-superseded`, `--limit <n>`, `--offset <n>`, `--json` |
| `order show <id>` | `--json` |
| `order delete <id>` | *(prompts)* |
| `order revoke <id>` | `--reason <n>` |

- `order list --expiring-in <days>` asks a different question over a different
  query: the certificates this CA issued that reach their notAfter inside the
  window, **soonest first**, each annotated with whatever has already replaced
  it. It is the same listing the `[notify.expiry]` digest mails and the panel
  shows at `/ui/expiring`, so the three cannot come to disagree about what
  "expiring" or "already replaced" means. Add `--hide-superseded` to drop the
  rows that have a successor and leave only the ones to act on.
- **`--status` and `--account-id` are refused with `--expiring-in`**, by name.
  The expiry listing is issued, unrevoked certificates by definition and has no
  account predicate, so either flag would silently mean something other than it
  does elsewhere — the rule `--status` and `audit list --event` already follow.
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

- `audit list` is paged like the other two listings; see [Paging](#paging).
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

## Paging

`account list`, `order list` (both of its queries) and `audit list` take
`--limit <n>` and `--offset <n>`, defaulting to **50 rows**. `orders` and
`audit_log` each grow a row per issuance for the life of the deployment, so
there is deliberately no "everything" spelling and `--limit 0` is not a way
around it: on a year-old CA that is a terminal full of scrollback and a table
loaded into memory. A nonsense window is corrected rather than refused — a
`--limit 0` becomes one row, a negative `--offset` becomes zero.

Every paged listing ends with a count, always and not only when the page is
short:

```console
$ acme-proxy order list --limit 2
...
2 of 1877 row(s).
```

"42 of 1877" is the difference between having read the table and having read a
page of it. Page with `--offset`; the listings are ordered newest first,
tie-broken on the row id, so a row cannot swap between pages and go unseen.

`order list --expiring-in` adds a third number when `--hide-superseded` drops
rows, because supersession is decided per row and cannot become part of the
query — so the total counts the *window*, not the rows printed under it:

```console
$ acme-proxy order list --expiring-in 30 --hide-superseded --limit 20
...
6 of 8 row(s), 2 superseded hidden.
```

The window is not clamped to `admin.page_size_max`. That key is a ceiling on
what an HTTP caller may ask the server for; this front end already answers to a
shell on the host.

## Access policy

| Command | Flags |
| --- | --- |
| `filter show` | `--profile <name>` |
| `filter explain` | `--profile <name>`, `--client-ip <ip>`, `--identifier <name>`, `--path <p>`, `--account-id <id>`, `--json` |

`--profile` may be omitted only when exactly one profile exists, the same rule
`upstream show` follows: `[filter]` is per-profile, so acting on "the policy"
without saying which one would be acting on nothing.

`filter show` prints the resolved policy — every check with its type and the
stages it decides at, then every rule in evaluation order with its condition
**re-parenthesized**. That last part is the point: an operator who wrote
`a or b and c` sees `a or (b and c)` printed back and has their answer about
precedence without reading the grammar.

Both commands *build* the policy rather than reading the file back, so every
startup refusal reaches you here too. `filter show` is therefore the cheapest
way to check a policy before restarting the server:

```console
$ acme-proxy filter show
profile: default
default: deny (when a rule was applicable and none matched)

checks
  inventory            ipam         identifiers only
  mgmt-net             allowed_ip   connection and identifiers

rules (first match wins)
  mgmt-bypass          mgmt-net -> allow
                         evaluated at: connection and identifiers
  inventory-owned      inventory or mgmt-net -> allow
                         evaluated at: identifiers only
```

`filter explain` evaluates it against a hypothetical request and reports all
three stages — connection, `newOrder` and CSR — because **every stage must
allow**, and that is the thing most easily misread. For each it prints every
check's verdict with its reason, which rule matched, and the HTTP answer that
stage would produce.

```console
$ acme-proxy filter explain --client-ip 10.0.0.5 --identifier web.corp.example.com
```

Checks the evaluation never reached are listed as **skipped**: a
short-circuited operand and a passing one look identical in the outcome, so
this is the only way the output can answer "why did my inventory check not
run".

> **This really runs the policy.** `filter explain` executes your `custom`
> scripts and issues real IPAM and DNS requests, exactly as a request would,
> because a stubbed answer would be worse than nothing the first time it
> disagreed with production. It touches no database and creates nothing, and it
> names the checks that reached outside the process at the end of its output
> (`sideEffects` under `--json`).
>
> That is also why it is a host-only command with no web-admin equivalent: the
> address and names are chosen by the caller, so behind a session it would be
> script execution and outbound requests driven from one stolen cookie.

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
