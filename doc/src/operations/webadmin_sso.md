# Single Sign-On (OIDC, LDAP)

The web admin can let people sign in through the identity provider your
organisation already runs, instead of (or as well as) the operators created
with `acme-proxy admin user create`:

- **OpenID Connect** — Keycloak, Microsoft Entra ID, Okta, Google, Authentik,
  Dex, … Each provider is a **Sign in with …** button on the sign-in page.
- **LDAP**, Active Directory included. Each directory is a **realm** on the
  password form: the person picks it, types their directory password, and the
  directory checks it.

Nobody has to be created in advance. **An operator is created at their first
sign-in**, and **their role follows their groups at every sign-in**: put them
in the group that maps to `operator` and they are an operator the next time
they sign in; take them out of every mapped group and they cannot sign in at
all.

The reasoning behind the design is
[ADR 0015](../dev/adr/0015-external-identity-providers.md).

## How a sign-in becomes an operator

The provider answers *who is this* (a stable id, a username) and *which groups
are they in*. Then, in order:

- **No mapped group, no sign-in.** The groups are compared, case-insensitively,
  with the provider's `roles` table; the highest role any of them grants wins.
  A person in none is refused, not made a viewer.
- **The stable id is the identity, never the name.** An operator is the pair
  *(provider, the provider's id for the person)*: the OpenID Connect `iss` and
  `sub`, or a directory's `entryUUID` / `objectGUID`. A person renamed at the
  provider is renamed here at their next sign-in.
- **A name already taken refuses the sign-in.** If the provider's username is
  already an operator here — a local one, or another provider's — the sign-in
  is refused (`username_taken`). It is never linked to the existing operator:
  otherwise whoever administers the provider could create a user called `admin`
  and become your break-glass account.
- **`disable` wins.** An operator disabled from the panel or the CLI stays
  disabled whatever their groups say.
- **The last admin is protected.** A sign-in whose groups would demote the only
  `admin` is refused (`last_admin`) rather than letting them in with a role the
  provider no longer grants. Promote somebody else first.

A role change and a creation are recorded in the [audit trail](audit.md) as
`operator_role_changed` / `operator_created`, with `actor_kind = system` and
`actor_id` naming the provider (`oidc:corp`), since nobody signed in made the
change.

## What an external operator can and cannot do here

They sign in only through their provider. Everything else works as for a local
operator, with these differences:

- **No password here.** The password form's local realm refuses them, and
  there is no password to change, from the panel or with `admin user passwd`
  (`managed_externally`).
- **Their role is the provider's.** The role form is not shown for them, and
  `admin user role` / `POST /api/operators/{username}/role` refuse
  (`managed_externally`): a change would revert at their next sign-in.
- **The second factor.** A directory password is a password, so an LDAP
  operator enrols and uses a local TOTP factor exactly as a local operator does,
  and `admin.require_mfa` applies to them. An OpenID Connect operator's second
  factor is the provider's: they cannot enrol a local one, and you insist on one
  with [`required_amr`](#reference-openid-connect).
- **Re-proving themselves** for a sensitive change (managing a colleague,
  changing their notification address, their second factor):
  - an LDAP operator types their **directory** password, which is checked by a
    bind as them;
  - an OpenID Connect operator has nothing to type: a sign-in **less than five
    minutes old** stands in. Past that, the change is refused with
    `reauthentication_required`; sign out and back in through the provider.

Disabling, deleting, setting the contact address and revoking sessions work as
usual. The **Operators** page and `admin user list` show where each operator
signs in through (`source=oidc:corp`, `ldap:ad`, or `local`).

## Keeping a local way in

Local operators keep working beside the providers, and should: if the provider
is down, or a mapping is wrong, a local `admin` created on the host is how you
get back in. `admin.auth.local = false` closes the local realm once you are sure
you do not want one; it deletes nobody, and turning it back on restores them.

A provider that cannot be reached answers `503 provider_unavailable` — never
`invalid_credentials`, which would send the person to reset a password that
works — and never stops the panel from starting: nothing contacts a provider
until somebody signs in through it.

## OpenID Connect

The sign-in is the authorization code flow with PKCE (`S256`). Register a
**confidential** client with your provider, with:

- **redirect URI** `<admin.base_url>/ui/login/oidc/<name>/callback`, for
  example `https://ca-admin.example.com/ui/login/oidc/corp/callback`;
- client authentication by **client secret, HTTP Basic**
  (`client_secret_basic`);
- a claim carrying the person's groups in the **ID token** (or set
  `userinfo_groups`).

The ID token must be signed `RS256` or `ES256`, which every mainstream provider
does by default. Its issuer, audience, authorized party, expiry and `nonce` are
all checked; the provider's discovery document must name exactly the configured
`issuer`; and every endpoint it names must be `https`.

```toml
[admin.auth.oidc.corp]
display_name = "Corporate SSO"
issuer = "https://sso.example.com/realms/acme"
client_id = "acme-proxy"
client_secret_file = "/run/secrets/acme-proxy-oidc"

[admin.auth.oidc.corp.roles]
admin = ["acme-admins"]
operator = ["acme-operators"]
viewer = ["staff"]
```

### Keycloak

`issuer` is the realm URL, `https://<host>/realms/<realm>`. Keycloak does not
put groups in the token by default: add a **Group Membership** mapper to the
client's dedicated scope, with *Token Claim Name* `groups`, *Add to ID token*
on, and *Full group path* off (or map the paths, `/acme-admins`).

### Microsoft Entra ID

`issuer` is `https://login.microsoftonline.com/<tenant-id>/v2.0`. Group claims
arrive as object ids and are left out entirely past 200 groups, so prefer **app
roles**: define `acme-admin`, `acme-operator` and `acme-viewer` on the app
registration, assign them, and set `groups_claim = "roles"`.
`preferred_username` is the user's UPN, `alice@example.com` — operator names may
contain `@`.

### Requiring the provider's second factor

`required_amr = ["mfa"]` refuses a token whose `amr` does not say the provider
asked for a second factor; `required_acr` does the same for an `acr` value
(Keycloak's step-up levels, for instance). What your provider puts in either is
its own vocabulary: check one of its tokens before relying on a value.

## LDAP and Active Directory

The directory is asked in this order:

- **An empty password is refused before anything is sent.** A bind with a name
  and no password is an *unauthenticated* bind, which many directories answer
  with success.
- The **service account** (`bind_dn`) binds and searches `user_base_dn` with
  `user_filter`, the typed name escaped. Exactly one entry must match.
- The **groups** are the person's `group_attribute` (`memberOf`), or — with
  `group_search_base` — a search for the groups that list them.
- Last, a **bind as the person** with the typed password. Only this step proves
  anything.

The connection must be encrypted: `ldaps://`, or `ldap://` with `start_tls`.
Plain `ldap://` is refused at startup unless the host is the loopback address,
because every operator's password would cross the network in the clear. A
directory's certificate is usually from an internal CA: name it in
`ca_cert_path`.

Group names in `roles` are compared with the groups' **DNs**,
case-insensitively. A DN holds commas, and a list read from an environment
variable is split on them, so set an LDAP realm's `roles` in the configuration
file, not through `ACME_PROXY_ADMIN__AUTH__LDAP__…__ROLES__…`.

### OpenLDAP

The defaults fit an OpenLDAP with the `memberof` overlay:

```toml
[admin.auth.ldap.corp]
display_name = "Corporate directory"
url = "ldaps://ldap.example.com"
ca_cert_path = "/etc/acme-proxy/ldap-ca.pem"
bind_dn = "cn=acme-proxy,ou=services,dc=example,dc=com"
bind_password_file = "/run/secrets/acme-proxy-ldap"
user_base_dn = "ou=people,dc=example,dc=com"

[admin.auth.ldap.corp.roles]
admin = ["cn=acme-admins,ou=groups,dc=example,dc=com"]
viewer = ["cn=staff,ou=groups,dc=example,dc=com"]
```

Without the overlay, read groups with a search instead:
`group_search_base = "ou=groups,dc=example,dc=com"`, which looks for
`groupOfNames` entries whose `member` is the person's DN (`group_filter`).
A `posixGroup` keyed on `memberUid` is not supported: the filter is given the
person's DN, not their name.

### Active Directory

```toml
[admin.auth.ldap.ad]
display_name = "Active Directory"
url = "ldaps://dc1.example.com"
ca_cert_path = "/etc/acme-proxy/ad-ca.pem"
bind_dn = "CN=svc-acme-proxy,OU=Service Accounts,DC=example,DC=com"
bind_password_file = "/run/secrets/acme-proxy-ad"
user_base_dn = "OU=Staff,DC=example,DC=com"
user_filter = "(&(objectClass=user)(sAMAccountName={username}))"
username_attribute = "sAMAccountName"
id_attribute = "objectGUID"

[admin.auth.ldap.ad.roles]
admin = ["CN=ACME Admins,OU=Groups,DC=example,DC=com"]
```

`memberOf` lists only **direct** membership. For groups inside groups, set
`group_search_base` and `nested_groups = true`, which asks the domain controller
to resolve the chain (`LDAP_MATCHING_RULE_IN_CHAIN`).

This has been tested against OpenLDAP; the Active Directory specifics —
`objectGUID`, the in-chain rule — are covered by unit tests and should be tried
against your own domain before you rely on them.

## What the log says

Every sign-in through a provider is an `admin_login_succeeded` or
`admin_login_failed` line like a local one, with a **`realm`** field: `local`,
`oidc:<name>` or `ldap:<name>`. The extra `reason` values are listed in
[Monitoring](monitoring.md#structured-events). `admin_user_provisioned` and
`admin_role_synced` record a creation and a role change, and
`admin_login_provider_failed` carries the detail of a provider that could not be
asked.

## Reference

Every key below is reloadable: a reload rebuilds the providers, and their
cached discovery documents and key sets with them. A provider's name is a
lowercase slug (`^[a-z0-9-]+$`), since it is also a URL segment and an
environment-variable segment.

### `[admin.auth]`

**`local`** (`Boolean`) — *Default: `true` | Env: `ACME_PROXY_ADMIN__AUTH__LOCAL`*

Whether the password form's local realm — operators created with `admin user
create` — accepts a sign-in. Startup refuses `false` with no provider
configured, since nobody could sign in.

### Reference: OpenID Connect

`[admin.auth.oidc.<name>]`, under `ACME_PROXY_ADMIN__AUTH__OIDC__<NAME>__…`.

**`display_name`** (`String`) — *Default: the name | Env: `ACME_PROXY_ADMIN__AUTH__OIDC__<NAME>__DISPLAY_NAME`*

The button's label: **Sign in with** *display_name*.

**`issuer`** (`String`) — *Default: none, required | Env: `ACME_PROXY_ADMIN__AUTH__OIDC__<NAME>__ISSUER`*

The provider's issuer identifier, exactly as its discovery document and tokens
spell it — the comparison is byte for byte, trailing slash included. Must be
`https://` (startup refuses anything else but a loopback `http://`). Discovery
is fetched from `<issuer>/.well-known/openid-configuration`.

**`client_id`** (`String`) — *Default: none, required | Env: `ACME_PROXY_ADMIN__AUTH__OIDC__<NAME>__CLIENT_ID`*

The client registered with the provider.

**`client_secret`** (`String`) — *Default: `""` | Env: `ACME_PROXY_ADMIN__AUTH__OIDC__<NAME>__CLIENT_SECRET`*

The client secret. A secret: prefer `client_secret_file`, or the environment
variable, to writing it in the file.

**`client_secret_file`** (`String`) — *Default: `""` | Env: `ACME_PROXY_ADMIN__AUTH__OIDC__<NAME>__CLIENT_SECRET_FILE`*

A file holding the client secret, trailing whitespace trimmed. Wins over
`client_secret`. Read at startup and on reload.

**`scopes`** (`List`) — *Default: `["openid", "profile", "email"]` | Env: `ACME_PROXY_ADMIN__AUTH__OIDC__<NAME>__SCOPES`*

Scopes requested. `openid` is added if missing. Some providers release groups
only for an extra scope (`groups`).

**`username_claim`** (`String`) — *Default: `"preferred_username"` | Env: `ACME_PROXY_ADMIN__AUTH__OIDC__<NAME>__USERNAME_CLAIM`*

The ID-token claim the operator's name comes from. Lowercased; it may hold
letters, digits, `-`, `_`, `.` and `@`. A token without it is refused.

**`groups_claim`** (`String`) — *Default: `"groups"` | Env: `ACME_PROXY_ADMIN__AUTH__OIDC__<NAME>__GROUPS_CLAIM`*

The claim holding the groups `roles` maps: an array of strings, or one string.
`roles` for Entra ID app roles.

**`userinfo_groups`** (`Boolean`) — *Default: `false` | Env: `ACME_PROXY_ADMIN__AUTH__OIDC__<NAME>__USERINFO_GROUPS`*

Read `groups_claim` from the userinfo endpoint instead of the ID token, for a
provider that keeps tokens small. The userinfo `sub` must be the token's.

**`required_acr`** (`List`) — *Default: `[]` | Env: `ACME_PROXY_ADMIN__AUTH__OIDC__<NAME>__REQUIRED_ACR`*

Refuse a token whose `acr` is none of these. Empty accepts any.

**`required_amr`** (`List`) — *Default: `[]` | Env: `ACME_PROXY_ADMIN__AUTH__OIDC__<NAME>__REQUIRED_AMR`*

Refuse a token whose `amr` lacks any of these — `["mfa"]` to insist the
provider asked for a second factor. Empty accepts any.

**`ca_cert_path`** (`String`) — *Default: `""` | Env: `ACME_PROXY_ADMIN__AUTH__OIDC__<NAME>__CA_CERT_PATH`*

Extra CA certificates (PEM) trusted on top of the public roots, for a provider
behind an internal PKI.

**`timeout_ms`** (`Integer`) — *Default: `10000` | Env: `ACME_PROXY_ADMIN__AUTH__OIDC__<NAME>__TIMEOUT_MS`*

Bound on each call to the provider (discovery, key set, token, userinfo).

**`roles.admin`** / **`roles.operator`** / **`roles.viewer`** (`List`) — *Default: `[]` | Env: `ACME_PROXY_ADMIN__AUTH__OIDC__<NAME>__ROLES__ADMIN`, `…__ROLES__OPERATOR`, `…__ROLES__VIEWER`*

The groups granting each [role](webadmin_users.md#roles), compared
case-insensitively. Startup refuses a provider whose three lists are all empty.

### Reference: LDAP

`[admin.auth.ldap.<name>]`, under `ACME_PROXY_ADMIN__AUTH__LDAP__<NAME>__…`.

**`display_name`** (`String`) — *Default: the name | Env: `ACME_PROXY_ADMIN__AUTH__LDAP__<NAME>__DISPLAY_NAME`*

The realm's label on the password form.

**`url`** (`String`) — *Default: none, required | Env: `ACME_PROXY_ADMIN__AUTH__LDAP__<NAME>__URL`*

`ldaps://host[:port]`, or `ldap://host[:port]` with `start_tls`. Plain
`ldap://` is refused at startup unless the host is loopback.

**`start_tls`** (`Boolean`) — *Default: `false` | Env: `ACME_PROXY_ADMIN__AUTH__LDAP__<NAME>__START_TLS`*

Upgrade an `ldap://` connection with StartTLS before anything is sent. Refused
with an `ldaps://` URL, which is already TLS.

**`ca_cert_path`** (`String`) — *Default: `""` | Env: `ACME_PROXY_ADMIN__AUTH__LDAP__<NAME>__CA_CERT_PATH`*

Extra CA certificates (PEM) trusted on top of the public roots.

**`bind_dn`** (`String`) — *Default: `""` | Env: `ACME_PROXY_ADMIN__AUTH__LDAP__<NAME>__BIND_DN`*

The service account that searches for people. Empty binds anonymously, which
most directories refuse.

**`bind_password`** (`String`) — *Default: `""` | Env: `ACME_PROXY_ADMIN__AUTH__LDAP__<NAME>__BIND_PASSWORD`*

The service account's password. A secret: prefer `bind_password_file`.

**`bind_password_file`** (`String`) — *Default: `""` | Env: `ACME_PROXY_ADMIN__AUTH__LDAP__<NAME>__BIND_PASSWORD_FILE`*

A file holding it, trailing whitespace trimmed. Wins over `bind_password`.

**`user_base_dn`** (`String`) — *Default: none, required | Env: `ACME_PROXY_ADMIN__AUTH__LDAP__<NAME>__USER_BASE_DN`*

Where people are searched for (the whole subtree).

**`user_filter`** (`String`) — *Default: `"(uid={username})"` | Env: `ACME_PROXY_ADMIN__AUTH__LDAP__<NAME>__USER_FILTER`*

The search, with `{username}` replaced by the typed name, escaped (RFC 4515).
Must mention `{username}`.

**`username_attribute`** (`String`) — *Default: `"uid"` | Env: `ACME_PROXY_ADMIN__AUTH__LDAP__<NAME>__USERNAME_ATTRIBUTE`*

The attribute the operator's name comes from (`sAMAccountName` on AD).

**`id_attribute`** (`String`) — *Default: `"entryUUID"` | Env: `ACME_PROXY_ADMIN__AUTH__LDAP__<NAME>__ID_ATTRIBUTE`*

The attribute naming the person stably across renames (`objectGUID` on AD). A
binary value is hex-encoded. Empty, or absent on the entry, uses the DN — which
changes when the person is moved or renamed.

**`group_attribute`** (`String`) — *Default: `"memberOf"` | Env: `ACME_PROXY_ADMIN__AUTH__LDAP__<NAME>__GROUP_ATTRIBUTE`*

The attribute on the person's entry listing their groups' DNs. Ignored when
`group_search_base` is set.

**`group_search_base`** (`String`) — *Default: `""` | Env: `ACME_PROXY_ADMIN__AUTH__LDAP__<NAME>__GROUP_SEARCH_BASE`*

Search for groups under this DN instead of reading `group_attribute`. The
service account searches, so the person needs no read access to groups.

**`group_filter`** (`String`) — *Default: `"(member={dn})"` | Env: `ACME_PROXY_ADMIN__AUTH__LDAP__<NAME>__GROUP_FILTER`*

The group search, with `{dn}` replaced by the person's escaped DN.

**`nested_groups`** (`Boolean`) — *Default: `false` | Env: `ACME_PROXY_ADMIN__AUTH__LDAP__<NAME>__NESTED_GROUPS`*

Active Directory: count membership through other groups too, with the
in-chain matching rule in place of `group_filter`. Needs `group_search_base`.

**`timeout_ms`** (`Integer`) — *Default: `5000` | Env: `ACME_PROXY_ADMIN__AUTH__LDAP__<NAME>__TIMEOUT_MS`*

Bound on the whole exchange with the directory, connection included.

**`roles.admin`** / **`roles.operator`** / **`roles.viewer`** (`List`) — *Default: `[]` | Env: `ACME_PROXY_ADMIN__AUTH__LDAP__<NAME>__ROLES__ADMIN`, `…__ROLES__OPERATOR`, `…__ROLES__VIEWER`*

The group DNs granting each role, compared case-insensitively. Startup refuses
a directory whose three lists are all empty.
