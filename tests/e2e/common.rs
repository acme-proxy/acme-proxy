use std::process::Command;
use std::sync::Once;
use testcontainers::{
    ContainerAsync, ContainerRequest, CopyTargetOptions, GenericImage, ImageExt, core::WaitFor,
    runners::AsyncRunner,
};
use tokio::process::Command as TokioCommand;

fn container_runtime() -> &'static str {
    if let Ok(rt) = std::env::var("CONTAINER_RUNTIME") {
        if rt == "docker" {
            return "docker";
        }
        if rt == "podman" {
            return "podman";
        }
    }
    // `status()` is `Ok` whenever the process *spawned*, whatever it then
    // exited with — and `podman-docker` installs a `docker` shim, so the old
    // `.is_ok()` answered "docker" on a rootless-podman host. That skipped the
    // `podman.socket` check and the `DOCKER_HOST` setup below, and the failure
    // surfaced as an opaque testcontainers connection error instead of the
    // message naming `systemctl --user start podman.socket`.
    //
    // A shim still reports success here, so the daemon is asked as well: only a
    // real docker daemon answers `docker info`.
    let spawned_ok = |program: &str, args: &[&str]| {
        std::process::Command::new(program)
            .args(args)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    };
    if spawned_ok("docker", &["--version"]) && spawned_ok("docker", &["info"]) {
        return "docker";
    }
    "podman"
}

static BUILD_IMAGES: Once = Once::new();

pub fn ensure_images_built() {
    if std::env::var("DOCKER_HOST").is_err() && container_runtime() == "podman" {
        let active = Command::new("systemctl")
            .args(["--user", "is-active", "--quiet", "podman.socket"])
            .status()
            .expect("failed to run systemctl")
            .success();
        assert!(
            active,
            "podman.socket is not running — start it with `systemctl --user start podman.socket` \
             before running the e2e suite (or set DOCKER_HOST yourself)"
        );
        let output = Command::new("id")
            .arg("-u")
            .output()
            .expect("failed to run id -u");
        let uid = String::from_utf8_lossy(&output.stdout).trim().to_string();
        unsafe {
            std::env::set_var(
                "DOCKER_HOST",
                format!("unix:///run/user/{}/podman/podman.sock", uid),
            );
        }
    }

    BUILD_IMAGES.call_once(|| {
        // Guarded by `flock` regardless of how this binary is invoked: nextest
        // runs each test as its own OS process (defeating this in-process
        // `Once` by itself, which is why the lock exists at all), but a plain
        // `cargo test` with multiple test threads — or two overlapping
        // invocations from different shells — races the same `podman build`
        // just as easily. When `NEXTEST_RUN_ID` is unset the flag file falls
        // back to a fixed name rather than skipping the lock, at the cost of
        // that flag persisting across separate non-nextest runs until the
        // temp dir is cleared — the same trade-off the run-id-keyed flag
        // already makes, just scoped wider.
        let run_id = std::env::var("NEXTEST_RUN_ID").unwrap_or_else(|_| "cargo-test".to_string());
        let flag_file = std::env::temp_dir().join(format!("acme-proxy-e2e-built-{}", run_id));
        let lock_file = std::env::temp_dir().join("acme-proxy-e2e-build.lock");

        let build_script = format!(
            r#"
            if [ -f "{flag_file}" ]; then
                exit 0
            fi
            {runtime} build -t bind-e2e -f tests/e2e/bind.Containerfile tests/e2e &&
            {runtime} build -t acme-proxy-e2e -f Containerfile . &&
            {runtime} build -t netbox-mock-e2e -f tests/e2e/netbox_mock.Containerfile tests/e2e &&
            {runtime} build -t phpipam-mock-e2e -f tests/e2e/phpipam_mock.Containerfile tests/e2e &&
            {runtime} build -t certbot-e2e -f tests/e2e/certbot.Containerfile tests/e2e &&
            {runtime} build -t acmesh-e2e -f tests/e2e/acmesh.Containerfile tests/e2e &&
            {runtime} build -t lego-e2e -f tests/e2e/lego.Containerfile tests/e2e &&
            touch "{flag_file}"
            "#,
            flag_file = flag_file.display(),
            runtime = container_runtime()
        );

        let status = Command::new("flock")
            .args([lock_file.to_str().unwrap(), "-c", &build_script])
            .status()
            .expect("Failed to run flock");
        assert!(status.success(), "Image build failed");
    });
}

pub struct Lab {
    pub network: String,
    pub dns: ContainerAsync<GenericImage>,
    pub proxy: ContainerAsync<GenericImage>,
    pub certbot: ContainerAsync<GenericImage>,
    pub acme_sh: ContainerAsync<GenericImage>,
    pub lego: ContainerAsync<GenericImage>,
    pub netbox_mock: Option<ContainerAsync<GenericImage>>,
    pub phpipam_mock: Option<ContainerAsync<GenericImage>>,
    pub proxy_upstream: Option<ContainerAsync<GenericImage>>,
    pub proxy_url: String,
    pub proxy_upstream_url: Option<String>,
}

impl Lab {
    pub async fn new(env: Vec<(&str, &str)>) -> Self {
        Self::new_internal(env, None, vec![]).await
    }

    pub async fn new_with_upstream(
        env: Vec<(&str, &str)>,
        env_upstream: Vec<(&str, &str)>,
    ) -> Self {
        Self::new_internal(env, Some(env_upstream), vec![]).await
    }

    /// Like [`Lab::new`], but additionally copies each `(target_path, bytes)`
    /// pair into the `acme-proxy` container *before* it starts — for
    /// scenarios (e.g. `signer.backend = "custom"`) that need a file present
    /// on disk at startup, not injected afterward via `exec_in` into an
    /// already-running (and possibly already-failed-to-start) container.
    pub async fn new_with_files(env: Vec<(&str, &str)>, files: Vec<(&str, Vec<u8>)>) -> Self {
        Self::new_internal(env, None, files).await
    }

    async fn new_internal(
        env: Vec<(&str, &str)>,
        env_upstream: Option<Vec<(&str, &str)>>,
        files: Vec<(&str, Vec<u8>)>,
    ) -> Self {
        // A cold-cache image build can take minutes; run it on a blocking
        // thread rather than tying up this test's async worker thread for
        // the whole duration.
        tokio::task::spawn_blocking(ensure_images_built)
            .await
            .expect("image build task panicked");

        let uuid = uuid::Uuid::new_v4();
        let network = format!("e2e-lab-{}", uuid);
        let status = TokioCommand::new(container_runtime())
            .args(["network", "create", &network])
            .status()
            .await
            .unwrap();
        assert!(status.success(), "Failed to create network");

        let dns_host = format!("dns-{}", uuid);
        let proxy_host = format!("proxy-{}", uuid);
        let certbot_host = format!("certbot-{}", uuid);
        let acmesh_host = format!("acmesh-{}", uuid);
        let lego_host = format!("lego-{}", uuid);

        let dns_image = GenericImage::new("bind-e2e", "latest")
            .with_wait_for(WaitFor::message_on_stderr("running"))
            .with_network(&network)
            .with_container_name(&dns_host);

        let certbot_image = GenericImage::new("certbot-e2e", "latest")
            .with_entrypoint("sh")
            .with_cmd(vec!["-c", "trap 'exit 0' TERM; sleep infinity & wait"])
            .with_network(&network)
            .with_container_name(&certbot_host);

        let acme_sh_image = GenericImage::new("acmesh-e2e", "latest")
            .with_entrypoint("sh")
            .with_cmd(vec!["-c", "trap 'exit 0' TERM; sleep infinity & wait"])
            .with_network(&network)
            .with_container_name(&acmesh_host);

        let lego_image = GenericImage::new("lego-e2e", "latest")
            .with_entrypoint("sh")
            .with_cmd(vec!["-c", "trap 'exit 0' TERM; sleep infinity & wait"])
            .with_network(&network)
            .with_container_name(&lego_host);

        // None of these four depends on another, so start them concurrently
        // instead of paying for four sequential container-start round trips.
        let (dns, certbot, acme_sh, lego) = tokio::join!(
            dns_image.start(),
            certbot_image.start(),
            acme_sh_image.start(),
            lego_image.start(),
        );
        let dns = dns.expect("Failed to start DNS");
        let certbot = certbot.expect("Failed to start certbot");
        let acme_sh = acme_sh.expect("Failed to start acme-sh");
        let lego = lego.expect("Failed to start lego");

        let (dns_ip, certbot_ip, acmesh_ip, lego_ip) = tokio::join!(
            Self::get_ip(dns.id(), &network),
            Self::get_ip(certbot.id(), &network),
            Self::get_ip(acme_sh.id(), &network),
            Self::get_ip(lego.id(), &network),
        );

        let tls_enabled = env
            .iter()
            .any(|(k, v)| *k == "ACME_PROXY_SERVER__TLS__ENABLED" && *v == "true");
        let scheme = if tls_enabled { "https" } else { "http" };
        let proxy_url = format!("{}://{}:3000", scheme, proxy_host);

        let mut proxy_image = GenericImage::new("acme-proxy-e2e", "latest")
            .with_wait_for(WaitFor::message_on_stdout("server_startup"))
            .with_network(&network)
            .with_container_name(&proxy_host)
            .with_env_var("ACME_PROXY_SERVER__BIND_ADDRESS", "[::]:3000")
            .with_env_var("ACME_PROXY_SERVER__BASE_URL", &proxy_url)
            .with_env_var("ACME_PROXY_PROFILES__DEFAULT__ENABLED", "true")
            .with_env_var("RUST_LOG", "acme_proxy=debug");

        // Most scenarios here are about something other than domain-control
        // proof — EAB, filters, profiles, the admin CLI — and have no responder
        // for a real challenge, so they want the bypass. It used to come from
        // `challenge.bypass`'s own default; now that the default validates, the
        // lab has to ask. Set only when the scenario has not chosen for itself,
        // so `http_01`/`dns_01`/`tls_alpn_01` keep validating for real.
        if !env
            .iter()
            .any(|(k, _)| *k == "ACME_PROXY_CHALLENGE__BYPASS")
        {
            proxy_image = proxy_image.with_env_var("ACME_PROXY_CHALLENGE__BYPASS", "true");
        }

        // The two IPAM mocks are wanted by four of the thirty-odd scenarios, and
        // starting them for the rest was a container plus a `podman inspect`
        // each, on the critical path of every lab. The need is derived from the
        // env vector rather than declared by the caller, so there is no second
        // place to keep in sync: the placeholders below are already how a
        // scenario asks for a mock's address, and asking for one is the only
        // reason to have one.
        let needs_netbox = env.iter().any(|(_, v)| v.contains("NETBOX_IP"));
        let needs_phpipam = env.iter().any(|(_, v)| v.contains("PHPIPAM_IP"));

        let netbox_mock_host = format!("netbox-mock-{}", uuid);
        let netbox_request = GenericImage::new("netbox-mock-e2e", "latest")
            .with_network(&network)
            .with_container_name(&netbox_mock_host)
            .with_env_var("CERTBOT_IP", &certbot_ip)
            .with_env_var("ACMESH_IP", &acmesh_ip);

        let phpipam_mock_host = format!("phpipam-mock-{}", uuid);
        let phpipam_request = GenericImage::new("phpipam-mock-e2e", "latest")
            .with_network(&network)
            .with_container_name(&phpipam_mock_host)
            .with_env_var("CERTBOT_IP", &certbot_ip)
            .with_env_var("ACMESH_IP", &acmesh_ip);

        let upstream_request = env_upstream.map(|upstream_env| {
            let upstream_host = format!("proxy-upstream-{}", uuid);
            let upstream_base_url = format!("http://{}:3000", upstream_host);
            let mut upstream_image = GenericImage::new("acme-proxy-e2e", "latest")
                .with_wait_for(WaitFor::message_on_stdout("server_startup"))
                .with_network(&network)
                .with_container_name(&upstream_host)
                .with_env_var("ACME_PROXY_SERVER__BIND_ADDRESS", "[::]:3000")
                .with_env_var("ACME_PROXY_SERVER__BASE_URL", &upstream_base_url)
                .with_env_var("ACME_PROXY_PROFILES__DEFAULT__ENABLED", "true")
                .with_env_var("ACME_PROXY_CHALLENGE__BYPASS", "true")
                .with_env_var(
                    "ACME_PROXY_SIGNER__LOCAL_CA__CERT_PATH",
                    "/tmp/upstream-ca.pem",
                )
                .with_env_var(
                    "ACME_PROXY_SIGNER__LOCAL_CA__KEY_PATH",
                    "/tmp/upstream-ca.key",
                )
                .with_env_var(
                    "ACME_PROXY_SIGNER__LOCAL_CA__CRL_PATH",
                    "/tmp/upstream-ca.crl",
                )
                .with_env_var("RUST_LOG", "acme_proxy=debug");

            for (k, v) in upstream_env {
                if k == "ACME_PROXY_DNS__RESOLVER" && v == "dns:53" {
                    upstream_image = upstream_image.with_env_var(k, format!("{}:53", dns_ip));
                } else if v.contains("DNS_SERVER_HOST") {
                    upstream_image =
                        upstream_image.with_env_var(k, v.replace("DNS_SERVER_HOST", &dns_ip));
                } else {
                    upstream_image = upstream_image.with_env_var(k, v);
                }
            }
            upstream_image
        });

        // None of these three needs another's address — only the four already
        // started above — so they go up together rather than as three sequential
        // start/inspect round trips. The proxy is the one container that has to
        // wait, since its environment names all of them.
        let (netbox_mock, phpipam_mock, proxy_upstream) = tokio::join!(
            Self::start_if_wanted(needs_netbox.then_some(netbox_request), "netbox-mock"),
            Self::start_if_wanted(needs_phpipam.then_some(phpipam_request), "phpipam-mock"),
            Self::start_if_wanted(upstream_request, "proxy upstream"),
        );

        let (netbox_ip, phpipam_ip, upstream_ip) = tokio::join!(
            Self::get_ip_of(netbox_mock.as_ref(), &network),
            Self::get_ip_of(phpipam_mock.as_ref(), &network),
            Self::get_ip_of(proxy_upstream.as_ref(), &network),
        );

        let proxy_upstream_url =
            upstream_ip.map(|ip| format!("http://{}:3000/profile/default/directory", ip));

        for (k, v) in env {
            if k == "ACME_PROXY_DNS__RESOLVER" && v == "dns:53" {
                proxy_image = proxy_image.with_env_var(k, format!("{}:53", dns_ip));
            } else if v.contains("DNS_SERVER_HOST") {
                proxy_image = proxy_image.with_env_var(k, v.replace("DNS_SERVER_HOST", &dns_ip));
            } else if v.contains("CERTBOT_IP") {
                proxy_image = proxy_image.with_env_var(k, v.replace("CERTBOT_IP", &certbot_ip));
            } else if v.contains("ACMESH_IP") {
                proxy_image = proxy_image.with_env_var(k, v.replace("ACMESH_IP", &acmesh_ip));
            } else if v.contains("LEGO_IP") {
                proxy_image = proxy_image.with_env_var(k, v.replace("LEGO_IP", &lego_ip));
            } else if v.contains("NETBOX_IP") {
                // `needs_netbox` was computed from this same predicate, so the
                // mock is running. The `expect` is here so that a future change
                // separating the two fails loudly instead of substituting an
                // empty host into a URL.
                let ip = netbox_ip
                    .as_deref()
                    .expect("a NETBOX_IP placeholder with no netbox-mock started");
                proxy_image = proxy_image.with_env_var(k, v.replace("NETBOX_IP", ip));
            } else if v.contains("PHPIPAM_IP") {
                let ip = phpipam_ip
                    .as_deref()
                    .expect("a PHPIPAM_IP placeholder with no phpipam-mock started");
                proxy_image = proxy_image.with_env_var(k, v.replace("PHPIPAM_IP", ip));
            } else if v.contains("UPSTREAM_URL") {
                if let Some(ref url) = proxy_upstream_url {
                    proxy_image = proxy_image.with_env_var(k, v.replace("UPSTREAM_URL", url));
                } else {
                    proxy_image = proxy_image.with_env_var(k, v);
                }
            } else {
                proxy_image = proxy_image.with_env_var(k, v);
            }
        }

        for (target, data) in files {
            proxy_image =
                proxy_image.with_copy_to(CopyTargetOptions::new(target).with_mode(0o755), data);
        }

        let proxy = proxy_image.start().await.expect("Failed to start proxy");

        let proxy_url_with_path = format!("{}/profile/default/directory", proxy_url);

        Self {
            network,
            dns,
            proxy,
            certbot,
            acme_sh,
            lego,
            netbox_mock,
            phpipam_mock,
            proxy_upstream,
            proxy_url: proxy_url_with_path,
            proxy_upstream_url,
        }
    }

    /// Starts `request` when there is one, so that a container a scenario has
    /// no use for costs nothing rather than a start and an inspect. Returning
    /// the same `Option` the `Lab` field already holds is what lets the three
    /// optional containers go up in one `tokio::join!`.
    async fn start_if_wanted(
        request: Option<ContainerRequest<GenericImage>>,
        what: &str,
    ) -> Option<ContainerAsync<GenericImage>> {
        let request = request?;
        Some(
            request
                .start()
                .await
                .unwrap_or_else(|error| panic!("Failed to start {}: {}", what, error)),
        )
    }

    /// [`Lab::get_ip`] for a container that may not exist.
    async fn get_ip_of(
        container: Option<&ContainerAsync<GenericImage>>,
        network: &str,
    ) -> Option<String> {
        match container {
            Some(container) => Some(Self::get_ip(container.id(), network).await),
            None => None,
        }
    }

    pub async fn get_ip(id: &str, network: &str) -> String {
        for _ in 0..10 {
            let output = TokioCommand::new(container_runtime())
                .args([
                    "inspect",
                    "-f",
                    &format!(
                        "{{{{ (index .NetworkSettings.Networks \"{}\").IPAddress }}}}",
                        network
                    ),
                    id,
                ])
                .output()
                .await
                .expect("Failed to get ip");

            let ip = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !ip.is_empty() {
                return ip;
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
        panic!(
            "Failed to get IP for container {} in network {}",
            id, network
        );
    }

    pub async fn dns_add_a(&self, host: &str, ip: &str) {
        // printf, not `echo -e` — dash's echo builtin (this container's /bin/sh)
        // doesn't interpret -e the way bash/BusyBox ash do, so nsupdate would
        // read a literal "-e ..." as its first command instead of the intended
        // "server ...". printf's format string always interprets \n, portably.
        let tsig = "-y hmac-sha256:tsig-key.:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let script = format!(
            "printf 'server 127.0.0.1\\nupdate add {} 60 A {}\\nsend\\n' | nsupdate {}",
            host, ip, tsig
        );
        self.exec_in(&self.dns, &script).await;
    }

    pub async fn dns_add_ptr(&self, ip: &str, host: &str) {
        let parts: Vec<&str> = ip.split('.').collect();
        assert_eq!(
            parts.len(),
            4,
            "dns_add_ptr only supports IPv4 addresses, got: {ip}"
        );
        let rev_zone = format!("{}.{}.{}.in-addr.arpa", parts[2], parts[1], parts[0]);
        let ptr_record = format!(
            "{}.{}.{}.{}.in-addr.arpa",
            parts[3], parts[2], parts[1], parts[0]
        );

        let setup_script = format!(
            r#"
            if ! grep -q 'zone "{0}"' /var/bind/lab/named.conf; then
                echo 'zone "{0}" {{ type master; file "/var/bind/lab/{0}.zone"; allow-update {{ key "tsig-key."; }}; }};' >> /var/bind/lab/named.conf
                printf '$TTL 60\n@ IN SOA ns.lab. admin.lab. ( 1 3600 1800 604800 60 )\n@ IN NS ns.lab.\n' > /var/bind/lab/{0}.zone
                chown bind:bind /var/bind/lab/named.conf /var/bind/lab/{0}.zone
                kill -HUP 1
                sleep 1
            fi
        "#,
            rev_zone
        );
        self.exec_in(&self.dns, &setup_script).await;

        let tsig = "-y hmac-sha256:tsig-key.:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let update_script = format!(
            "printf 'server 127.0.0.1\\nupdate add {} 60 PTR {}\\nsend\\n' | nsupdate {}",
            ptr_record, host, tsig
        );
        self.exec_in(&self.dns, &update_script).await;
    }

    pub async fn exec_in(&self, container: &ContainerAsync<GenericImage>, script: &str) {
        let id = container.id();
        let status = TokioCommand::new(container_runtime())
            .args(["exec", id, "sh", "-c", script])
            .status()
            .await
            .expect("Failed to execute command in container");
        assert!(status.success(), "Command in container failed");
    }

    pub async fn exec_in_with_output(
        &self,
        container: &ContainerAsync<GenericImage>,
        script: &str,
    ) -> (bool, String, String) {
        let id = container.id();
        let output = TokioCommand::new(container_runtime())
            .args(["exec", id, "sh", "-c", script])
            .output()
            .await
            .expect("Failed to execute command in container");
        (
            output.status.success(),
            String::from_utf8_lossy(&output.stdout).to_string(),
            String::from_utf8_lossy(&output.stderr).to_string(),
        )
    }

    pub async fn get_proxy_logs(&self) -> String {
        let id = self.proxy.id();
        let output = TokioCommand::new(container_runtime())
            .args(["logs", id])
            .output()
            .await
            .expect("Failed to get proxy logs");
        String::from_utf8_lossy(&output.stderr).to_string()
            + &String::from_utf8_lossy(&output.stdout)
    }

    pub async fn get_proxy_upstream_logs(&self) -> String {
        if let Some(ref upstream) = self.proxy_upstream {
            let id = upstream.id();
            let output = TokioCommand::new(container_runtime())
                .args(["logs", id])
                .output()
                .await
                .expect("Failed to get upstream logs");
            String::from_utf8_lossy(&output.stderr).to_string()
                + &String::from_utf8_lossy(&output.stdout)
        } else {
            "".to_string()
        }
    }

    pub async fn get_netbox_mock_logs(&self) -> String {
        Self::container_logs(self.netbox_mock.as_ref(), "netbox-mock").await
    }

    pub async fn get_phpipam_mock_logs(&self) -> String {
        Self::container_logs(self.phpipam_mock.as_ref(), "phpipam-mock").await
    }

    async fn container_logs(
        container: Option<&ContainerAsync<GenericImage>>,
        what: &str,
    ) -> String {
        let Some(container) = container else {
            return String::new();
        };
        let output = TokioCommand::new(container_runtime())
            .args(["logs", container.id()])
            .output()
            .await
            .unwrap_or_else(|error| panic!("Failed to get {what} logs: {error}"));
        String::from_utf8_lossy(&output.stderr).to_string()
            + &String::from_utf8_lossy(&output.stdout)
    }
}

impl Drop for Lab {
    fn drop(&mut self) {
        let _ = Command::new(container_runtime())
            .args(["network", "rm", "-f", &self.network])
            .status();
    }
}
