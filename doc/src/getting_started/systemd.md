# systemd

Below is an example `systemd` service file that runs `acme-proxy` securely.

1. **Create a dedicated user:**
   ```bash
   sudo useradd -r -s /bin/false acme-proxy
   ```

2. **Prepare directories:**
   ```bash
   sudo mkdir -p /etc/acme-proxy
   sudo mkdir -p /var/lib/acme-proxy
   sudo chown acme-proxy:acme-proxy /var/lib/acme-proxy
   ```

3. **Create the service file:** Create `/etc/systemd/system/acme-proxy.service`:

   ```ini
   [Unit]
   Description=ACME Proxy Server
   After=network.target

   [Service]
   Type=simple
   User=acme-proxy
   Group=acme-proxy
   ExecStart=/usr/local/bin/acme-proxy serve
   ExecReload=/bin/kill -HUP $MAINPID
   WorkingDirectory=/var/lib/acme-proxy

   # Configuration. The extension may be omitted, in which case the format
   # is inferred.
   Environment="ACME_PROXY_CONFIG=/etc/acme-proxy/config.toml"
   Environment="ACME_PROXY_DATABASE__URL=sqlite:///var/lib/acme-proxy/acme.db"

   # Security / Sandboxing
   ProtectSystem=strict
   ReadWritePaths=/var/lib/acme-proxy
   ProtectHome=true
   PrivateTmp=true
   NoNewPrivileges=true

   Restart=on-failure
   RestartSec=5

   [Install]
   WantedBy=multi-user.target
   ```

`ProtectSystem=strict` makes the whole filesystem read-only except
`ReadWritePaths`, so everything the server writes must land in
`/var/lib/acme-proxy`. With `WorkingDirectory` set there, the defaults already
do: `signer.local_ca.cert_path` (`ca.pem`), `key_path` (`ca.key`), `crl_path`
(`ca.crl`) and the lock beside it are all resolved relative to the working
directory, as are `server.tls.cert_path` / `key_path` if you enable TLS.
If you set any of them to an absolute path, add that path to `ReadWritePaths`
too.

   > `acme-proxy` shuts down gracefully on `SIGTERM` (and on Ctrl+C when run in
   > a terminal), so `systemctl restart` and `systemctl stop` let in-flight
   > requests finish rather than cutting them off. Both listeners stop together.
   >It also reloads its configuration on `SIGHUP` without restarting, which is
   >what the `ExecReload` line above wires up — see [Reloading the
   >Configuration](../operations/reload.md) for what a reload may change and
   >what it refuses.
   >One case still deserves a quiet period: a request that waits — a `custom`
   >script's `crl` or `renewal_info` hook, or a relay revocation waiting on its
   >job — can take up to `server.request_timeout_ms`. If systemd's
   >`TimeoutStopSec` (90 s by default) is shorter than that, systemd sends
   >`SIGKILL` first and the graceful path is skipped — raise it, or lower the
   >request timeout. Challenge validation and issuance are not among these:
   >they run in the job queue, and a job left unfinished by a restart is
   >reclaimed by lease expiry.

4. **Enable and start the service:**
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now acme-proxy
   ```
