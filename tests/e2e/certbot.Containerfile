FROM debian:trixie-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends certbot python3-certbot-dns-rfc2136 openssl \
    && rm -rf /var/lib/apt/lists/*
