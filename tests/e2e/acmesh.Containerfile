# Debian ships no acme.sh package (Alpine's `apk add acme.sh` has no equivalent
# here), so this installs a pinned upstream release from source instead — same
# reason tests/e2e/lego.Containerfile pins a release rather than using a packaged
# one.
FROM debian:trixie-slim
# curl is not just an install-time fetch tool here: acme.sh itself shells out to
# curl (or wget) at runtime for every ACME HTTP call, and some e2e scenarios
# (e.g. ari.rs) run a raw `curl` inside this container directly — so it stays
# in the final image, unlike the throwaway install steps in other Containerfiles.
# bind9-dnsutils (nsupdate) is for dns_01.rs's `--dns dns_nsupdate` scenario —
# baked in here rather than installed at test-run time (as the old Alpine image
# did via `apk add bind-tools`) so the test doesn't pay a network fetch on
# every run and doesn't depend on this image's package manager.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl openssl socat cron bind9-dnsutils \
    && curl -fsSL -o /tmp/acme.sh.tar.gz \
       https://github.com/acmesh-official/acme.sh/archive/refs/tags/3.1.4.tar.gz \
    && tar -xzf /tmp/acme.sh.tar.gz -C /tmp \
    && (cd /tmp/acme.sh-3.1.4 && ./acme.sh --install --no-cron --no-profile --home /opt/acme.sh) \
    && ln -s /opt/acme.sh/acme.sh /usr/local/bin/acme.sh \
    && rm -rf /tmp/acme.sh* \
    && rm -rf /var/lib/apt/lists/*
