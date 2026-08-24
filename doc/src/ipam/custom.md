# Custom Script

Runs an operator-supplied script to answer the one question the whole
subsystem asks: *which names does this address own?*

Use it when the inventory of record is something this server carries no client
for — a CMDB, a `hosts` file, an LDAP tree, a spreadsheet exported nightly, a
vendor API behind a Python wrapper. It is the same escape hatch the
[custom filter](../filters/custom.md) and the
[custom signer](../signers/custom.md) are for their subsystems, and it runs
under the same hardening.

It is also the backend with the least in it. There is no URL, no credential,
no TLS setting and no [`sources`](index.md#sources) list: the script *is* the
inventory, and where it looks is its own business.

## The contract

The script is told the client address twice — once in the environment, once in
a JSON object on stdin — so neither a four-line shell script nor a Python one
has to reach for the channel it finds awkward.

| Variable | Value |
| --- | --- |
| `ACME_IPAM_HOOK` | Always `names_for`. There is one hook. |
| `ACME_IPAM_CLIENT_IP` | The resolved client address, canonicalized (an IPv4-mapped IPv6 address is flattened to IPv4). |

The same on stdin:

```json
{"hook": "names_for", "client_ip": "203.0.113.5"}
```

A script that exits without reading stdin is fine and is not an error.

### The answer

**stdout plus an exit code.**

| Exit | stdout | Means |
| --- | --- | --- |
| `0` | one name per line | The inventory holds this address, and these are its names |
| `0` | empty | Held, and entitled to nothing |
| `3` | ignored | **No record of this address at all** |
| anything else | the reason | The script failed — a retryable `500`, never a denial |

Names are compared [exactly](index.md#matching-is-exact), but the script need
not tidy them: each line is lowercased and stripped of a trailing dot, and a
blank line is ignored. So `WWW.Example.COM.` and `www.example.com` are the
same answer, and printing whatever form the inventory happens to hold is
correct.

One name per line rather than a separated list because a newline is the shell
idiom, and plain text rather than JSON because there is nothing here a
structure would carry that a list of lines does not — a contract needing `jq`
for what `echo` already does would be paid for by every script ever written
against it. The custom signer hands back its certificate chain the same way.

### Why `3` is reserved

"Held, and entitled to nothing" and "no record of this address" are different
answers — the `ipam` check words a different refusal for each, so an operator
reading a `403` can tell them apart — and once stdout means *the names*, an
exit status is the only channel left to say the second one in. So it gets a
code of its own, exactly as the custom signer's `badCSR` does.

Every *other* non-zero exit stays a failure, and that direction is the one that
matters. A script that breaks, is missing, or runs past `ipam.timeout_ms`
produces a **server error the client can retry**, never a refusal — see
[Denied versus Internal](index.md#denied-versus-internal). It is the same
guarantee an unreachable NetBox gets, and it is enforced by the types rather
than by care here: the error an IPAM backend can return has no denied variant
to reach for, so a broken script cannot fail open *or* look permanent.

## An example

```sh
#!/bin/sh
case "$ACME_IPAM_CLIENT_IP" in
  203.0.113.5)
    echo www.example.com
    echo api.example.com
    exit 0
    ;;
  203.0.113.6)
    exit 0          # held, entitled to nothing
    ;;
esac
exit 3              # no record of this address
```

A fuller one, reading a real source, is in
[Custom Plugins Examples](../dev/custom_plugins.md).

## No sources

[`sources`](index.md#sources) exists because NetBox and phpIPAM each read
several places and an operator has to say which are trusted. A script reads
whatever it reads, so there is nothing here to list and no key to set. The
vocabulary is closed and validated per backend, so a `sources` line under
`[ipam.custom]` is not a source this backend "does not support" — it is a
setting that does not exist.

## What it costs

One forked process per lookup, inside `newOrder` and again at `finalize`.
`ipam.timeout_ms` is the budget, and it is also what kills the child at the
deadline; there is deliberately no second timeout here.

Note that `acme-proxy filter explain` really runs the policy, so it **executes
this script** — as it does the custom filter's. That is the point of the
command, and it is reported in its side-effects list.

## Security and process isolation

1. **Environment clearing**: `env_clear()` is called. The script inherits a
   minimal `PATH` plus the two `ACME_IPAM_*` variables above — nothing else.
   The server's own environment may hold the NetBox token, the SMTP password or
   the RFC 2136 TSIG key, and an inventory script has no business reading them.
2. **Zombie protection**: the child runs with `kill_on_drop(true)` under a
   `tokio::time::timeout`. A timeout alone only drops the future, so without
   this a hung script would outlive its deadline and leak a process per
   request.
3. **Failure reporting**: on a non-zero exit other than `3`, the first
   non-empty line of stdout (falling back to stderr) becomes the error detail.
   It is logged, not sent to the client: an internal error tells the client
   nothing about why.

## Configuration

```toml
[ipam]
backend = "custom"
timeout_ms = 5000

[ipam.custom]
script_path = "/etc/acme-proxy/ipam/lookup.sh"
args = []
```

### Reference

**`script_path`** (`String`) — *Default: `""` | Env: `ACME_PROXY_IPAM__CUSTOM__SCRIPT_PATH`*

Path to the executable answering the lookup. Empty while `ipam.backend` is
`custom` is a startup error, the same as
[`signer.custom.script_path`](../signers/custom.md#reference).

**`args`** (`Array`) — *Default: `[]` | Env: `ACME_PROXY_IPAM__CUSTOM__ARGS`*

Fixed arguments passed before the script is told anything about the request.
One script can serve several deployments by branching on them.

There is deliberately **no `timeout_ms`** here.
[`ipam.timeout_ms`](index.md#reference) is the budget the whole lookup runs
under, and a second one would contradict the rule the other backends follow.
