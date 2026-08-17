# Customizing the Panel

The pages at `/ui` are [minijinja] templates compiled into the binary. Any one
of them can be replaced on disk without rebuilding, the same way [notification
templates](../notifications/templates.md) work — an operator who has already
overridden a notification should not have to learn a second scheme.

```toml
[admin]
template_dir = "/etc/acme-proxy/admin-templates"
```

Each name is looked for in that directory first and falls back to the
compiled-in default. **The override is per file**, not per directory: a
directory holding only `layout.html` restyles the chrome of every page and
leaves the other twenty exactly as shipped.

Every template is compiled at startup. A broken override **refuses to start**,
naming the file and the parse error, rather than serving a `500` the first time
somebody opens that page.

## The files

Paths are relative to `template_dir`, and are also how the templates refer to
each other in `{% extends %}` and `{% include %}`.

| File | What it is |
|---|---|
| `layout.html` | The chrome every full page extends: `<head>`, navigation, `<body>` |
| `login.html` | Sign-in. Standalone — extends nothing, and uses no JavaScript |
| `mfa/challenge.html` | The second sign-in step. Standalone and JavaScript-free for the same reason; branches on `step` between proving a code and setting one up |
| `mfa/_setup.html` | The setup key and the `otpauth://` URI. Included by both the sign-in flow and the account page, so it renders no `<form>` of its own |
| `mfa/_codes.html` | A fresh recovery set, the one time it exists in the clear |
| `mfa/enrolled.html` | Where a forced enrolment lands: the codes, then a link into the panel |
| `account/index.html`, `account/_mfa.html` | The operator's own page, and the fragment every mutation on it swaps |
| `account/_card.html` | The second-factor card itself, with no `id` — so `_codes.html` can wrap it without nesting two elements carrying one |
| `account/_enrol.html`, `account/_codes.html` | The enrolment step, and the codes plus the refreshed card |
| `index.html` | The overview: four counts and the endpoint list |
| `partials/_flash.html` | The inline banner every mutation's answer renders |
| `partials/_pager.html` | The previous/next controls under a list |
| `accounts/list.html`, `accounts/_table.html` | The account list, and the table htmx swaps |
| `accounts/detail.html`, `accounts/_card.html` | One account, and the card every account mutation returns |
| `orders/list.html`, `orders/_table.html` | The order list |
| `orders/detail.html`, `orders/_card.html` | One order with its authorizations and challenges |
| `eab/list.html`, `eab/_table.html` | The credential list and the create form |
| `eab/detail.html`, `eab/_card.html` | One credential |
| `eab/_created.html` | The one-time HMAC secret |
| `nonces/index.html`, `nonces/_panel.html` | The nonce count and the sweep control |
| `profiles/list.html`, `profiles/_table.html` | The mounted endpoints |

A file whose name starts with `_` is a **fragment**: htmx swaps it on its own,
so it must not contain `<html>` or `<body>`, and it must keep the `id` on its
root element — that id is what the page's `hx-target` points at.

## Two things not to break

### The extension is a security control

Every page template is named `.html`, and that is deliberate. minijinja decides
auto-escaping from the template *name*, and the notify templates are named `.j2`
precisely so that escaping is **off** for them (an email body is not markup).
Renaming a page template to `.j2` — or adding a new one under a name minijinja
does not recognise as HTML — turns an account contact or an EAB label into
stored XSS.

### The CSRF token has to stay on `<body>`

`layout.html` carries:

```html
<body hx-headers='{"X-CSRF-Token": "{{ csrf_token }}"}'>
```

That attribute is the only route by which the token reaches a mutating request.
A layout that drops it loses **every** write at once — which is the intended
failure mode; a partial loss would be far harder to notice.

The same file sets two htmx options that the
[Content-Security-Policy](webadmin.md#security-notes) depends on:

```html
<meta name="htmx-config"
      content='{"includeIndicatorStyles":false,"responseHandling":[...]}'>
```

`includeIndicatorStyles: false` stops htmx injecting an inline `<style>` element
that `style-src 'self'` would block — the rules it would have injected live in
`admin.css` instead. `responseHandling` makes htmx swap non-2xx responses,
without which a `409` conflict would fail silently instead of showing the
operator a banner.

## Context

Every full page gets `csrf_token`, `user`, `nav` (the active navigation item)
and `title`, plus its own data. That data is the **same JSON the API returns** —
`render_account_json`, `render_order_detail_json`, `render_eab_json` — so `GET
/api/accounts/{id}` is an accurate description of what `account` holds in
`accounts/_card.html`. Lists additionally get `page` (`{items, total}`),
`pager`, `filters` and `profiles`.

A quick way to see a context in full is to render it:

```jinja
<pre>{{ account | tojson(indent=2) }}</pre>
```

## Starting from the shipped version

The defaults are in the source tree under `src/webadmin/templates/`. Copy the
one you want to change:

```console
$ mkdir -p /etc/acme-proxy/admin-templates
$ cp src/webadmin/templates/layout.html /etc/acme-proxy/admin-templates/
```

Then send `SIGHUP` — see [Reloading the Configuration](reload.md). Templates
are compiled up front, so a mistake fails the reload and the panel goes on
serving the last set that worked; it never reaches a browser. The same compile
happens at startup, where a mistake stops the process instead.

## Stylesheet and scripts

`admin.css` and `htmx.min.js` are served from `/ui/static/` and are **not**
covered by `template_dir` — they are embedded assets, not templates. To restyle
beyond what CSS variables allow, override `layout.html` and point its `<link>`
at your own file. Note that the Content-Security-Policy is `default-src 'none'`
with `style-src 'self'`: a stylesheet must be served from this origin, and an
inline `<style>` block or `style=` attribute will be blocked.

[minijinja]: https://docs.rs/minijinja
