FROM debian:trixie-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends bind9 bind9-dnsutils \
    && rm -rf /var/lib/apt/lists/*
COPY bind /var/bind/lab
# named.conf's `directory "/var/bind";` is BIND's declared working directory
# (the parent of the config/zone files below it), so the `bind` user needs
# write access to /var/bind itself, not just the `lab` subdirectory holding
# the config we copied in — Debian's bind9 package doesn't pre-create
# /var/bind with `bind` ownership the way it apparently does on Alpine.
RUN chown -R bind:bind /var/bind
CMD ["named", "-u", "bind", "-c", "/var/bind/lab/named.conf", "-g"]
