# Signers

The `signer` subsystem determines how `acme-proxy` fulfills a certificate issuance request once all challenges and filters have been verified. 

`acme-proxy` supports three backends:
1. **[Local CA](local_ca.md):** The server acts as a self-contained CA, signing certificates itself.
2. **[ACME Proxy](acme_proxy.md):** The server acts as a relay, forwarding the signing request to an upstream CA.
3. **[Custom Script](custom.md):** The server shells out to an external script or tool to obtain the certificate.

You can configure the active backend in the TOML configuration:

```toml
[signer]
backend = "local_ca" # Options: "local_ca", "acme_proxy", "custom"
```

**`backend`** (`String`)  
*Default: `"local_ca"` | Env: `ACME_PROXY_SIGNER__BACKEND`*  
Which backend issues certificates. One of `local_ca`, `acme_proxy`, `custom`.

`[signer]` is a **per-profile** section, so each profile can use a different
backend — a `local_ca` at `/profile/dev` beside a relay at `/profile/prod`.
Backends are shared by *configuration*: two profiles with identical `[signer]`
sections share one backend instance rather than constructing two. See
[Profiles & Routing](../core/profiles.md).
