# Vendored assets

Everything in this directory is served by `src/webadmin/pages/assets.rs`, from
`include_str!`/`include_bytes!` — the files are compiled into the binary, so a
deployment is still one executable and `tower-http`'s `fs` feature stays off.

## `htmx.min.js`

| | |
|---|---|
| Version | **2.0.10** (also readable in-file: `grep -o 'version:"[^"]*"' htmx.min.js`) |
| Source | `https://raw.githubusercontent.com/bigskysoftware/htmx/v2.0.10/dist/htmx.min.js` |
| SHA-256 | `71ea67185bfa8c98c39d31717c6fce5d852370fcdfd129db4543774d3145c0de` |
| Licence | Zero-Clause BSD (`0BSD`), verbatim in `htmx.LICENSE` |
| Size | 51 238 bytes |

**This file is the reason this README exists.** `cargo deny` audits the crate
graph; it cannot see a JavaScript blob committed into `src/`, so nothing
automated will ever tell you this file is outdated, tampered with, or carrying
an advisory. The version, the URL and the checksum above are the only record.

`0BSD` is coincidentally already in `deny.toml`'s `licenses.allow` list (it
arrives transitively through `lettre`), so no policy decision was needed here —
but that entry is about crates and grants this file nothing. It is noted only so
a future reader does not go looking for a licence exception that was never
required.

The 2.x line is deliberate. htmx 4.x exists but was still `-beta` when this
landed, and a certificate authority's management panel is not where a
pre-release front-end framework belongs.

### Refreshing it

```console
$ cd src/webadmin/static
$ curl -fsSL https://raw.githubusercontent.com/bigskysoftware/htmx/v<TAG>/dist/htmx.min.js -o htmx.min.js
$ curl -fsSL https://raw.githubusercontent.com/bigskysoftware/htmx/v<TAG>/LICENSE       -o htmx.LICENSE
$ sha256sum htmx.min.js
```

Then update the table above — version, URL, checksum and size — and re-read
`htmx.LICENSE`, which is *not* guaranteed to stay `0BSD` across a major
version. Two behaviours the admin templates depend on and an upgrade must be
re-checked against, both set through the `htmx-config` meta tag in
`templates/layout.html`:

- **`includeIndicatorStyles: false`** — htmx otherwise injects an inline
  `<style>` element at load, which the admin listener's
  `Content-Security-Policy` (`style-src 'self'`) blocks. The `.htmx-indicator`
  rules it would have injected live in `admin.css` instead.
- **`responseHandling`** — htmx does not swap non-2xx responses by default, so
  without this a `409 already_revoked` would fail silently instead of showing
  the operator an error banner.

## `admin.css`

Ours, hand-written, no framework and no build step. Includes the
`.htmx-indicator` rules described above.
