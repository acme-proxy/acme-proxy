# Vendored corpus

`common-passwords.txt` is compiled into the binary by `include_str!` in
`src/admin/password.rs` and read by `check_password_policy`. It is the ASVS 5.0
**V6.2.4** ("check against the top 3000 passwords") and **V6.2.12** ("check
against breached passwords") control.

## `common-passwords.txt`

| | |
|---|---|
| Upstream | `xato-net-10-million-passwords-1000000.txt`, SecLists **2026.1** |
| Source | `https://raw.githubusercontent.com/danielmiessler/SecLists/2026.1/Passwords/Common-Credentials/xato-net-10-million-passwords-1000000.txt` |
| Upstream SHA-256 | `424a3e03a17df0a2bc2b3ca749d81b04e79d59cb7aeec8876a5a3f308d0caf51` |
| Upstream size | 1 000 000 entries, 8 557 632 bytes |
| Licence | MIT, verbatim in `SecLists.LICENSE` (© 2018 Daniel Miessler) |
| Rank cut | top **700 000** |
| Derived size | **13 918 entries, 195 336 bytes** |

**This README is the only provenance record.** `cargo deny` audits the crate
graph and cannot see a text file committed into `src/`, so nothing automated
will tell you this one is outdated or tampered with — the same reason
`src/webadmin/static/README.md` exists for the vendored htmx.

MIT is already in `deny.toml`'s `licenses.allow` list, but that entry is about
crates and grants this file nothing. It is noted only so a future reader does
not go looking for a licence exception that was never required. The licence text
is vendored beside the corpus because MIT requires the notice to travel with a
substantial portion of the work, and a filtered list of 13 918 entries is one --
the same reason `htmx.LICENSE` sits next to `htmx.min.js`. **Refresh it whenever
the corpus is refreshed**: it is not guaranteed to stay MIT across a release.

### Why the file is 195 KB and not 8.5 MB

**Every entry shorter than `MIN_PASSWORD_LEN` is dropped, because
`check_password_policy` has already refused it on length.** That is the whole
reason a compiled-in corpus is affordable here: `password`, `qwerty`,
`123456` and `iloveyou` never reach the corpus check, so carrying them would
add bytes to every deployment — including the ones with `admin.enabled =
false` — in exchange for nothing. Filtering the upstream million at twelve
characters leaves 46 146 entries; the top-700 000 cut leaves 13 918.

The cut is **derived from a ~200 KB budget, not chosen for its own sake**. The
curve is steep near the tail, so re-derive it rather than assuming it:

| Rank cut | Entries ≥ 12 chars | Bytes |
|---|---|---|
| top 100 000 | 483 | 6 716 |
| top 300 000 | 2 788 | 38 682 |
| top 500 000 | 7 192 | 100 712 |
| **top 700 000** | **13 918** | **195 336** |
| top 1 000 000 | 46 146 | 674 833 |

Any of these strictly contains the top 3000, so V6.2.4 is met whichever is
picked; the budget is what decides how much of V6.2.12 comes with it.

### Refreshing it

```console
$ cd src/admin/corpus
$ URL=https://raw.githubusercontent.com/danielmiessler/SecLists/<TAG>/Passwords/Common-Credentials/xato-net-10-million-passwords-1000000.txt
$ curl -fsSL "$URL" | tee /tmp/upstream.txt | head -n 700000 \
    | awk 'length($0) >= 12' | tr 'A-Z' 'a-z' | LC_ALL=C sort -u \
    > common-passwords.txt
$ curl -fsSL https://raw.githubusercontent.com/danielmiessler/SecLists/<TAG>/LICENSE \
    -o SecLists.LICENSE
$ sha256sum /tmp/upstream.txt && wc -lc common-passwords.txt
```

Then update the table above. Three details in that pipeline are load-bearing:

- **`LC_ALL=C`** — `sort` under a UTF-8 locale collates differently, and
  `corpus_is_sorted_and_unique` compares with Rust's byte ordering. Without it
  the test fails on a file that looks sorted.
- **`awk`'s `length()` counts bytes**, where the policy counts *characters*.
  They agree only because this corpus is pure ASCII, which
  `corpus_entries_are_ascii_lowercase_and_long_enough` asserts rather than
  assumes. A corpus with non-ASCII entries needs a different filter.
- **`tr` before `sort -u`** — lowercasing after deduplication leaves
  `Password12345` and `password12345` as two entries for one lookup.
