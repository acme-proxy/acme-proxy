# Dex, the OpenID Connect provider of `admin_sso.rs`, built from a pinned
# release tag. Dex publishes images but no binaries, and its go.mod carries a
# `replace` directive (`api/v2 => ./api/v2`), which `go install pkg@version`
# refuses -- so this clones the tag and builds it, with Go from the same
# checksum-pinned tarball `lego.Containerfile` uses, for the reason given there.
# cgo stays on: Dex's SQLite storage needs it to build at all, and the runtime
# stage is the same Debian, so the dynamic glibc link is satisfied.
FROM debian:trixie-slim AS build
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl git gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/* \
    && curl -fsSL -o /tmp/go.tar.gz https://go.dev/dl/go1.25.12.linux-amd64.tar.gz \
    && echo "234828b7a89e0e303d2556310ee549fbcf253d28de937bac3da13d6294262ac1  /tmp/go.tar.gz" | sha256sum -c - \
    && tar -C /usr/local -xzf /tmp/go.tar.gz \
    && rm /tmp/go.tar.gz
ENV GOPATH=/go
ENV PATH="/usr/local/go/bin:/go/bin:${PATH}"
RUN git clone --depth 1 --branch v2.41.1 https://github.com/dexidp/dex /src \
    && cd /src \
    && go build -o /usr/local/bin/dex ./cmd/dex

FROM debian:trixie-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /usr/local/bin/dex /usr/bin/dex
ENTRYPOINT ["dex"]
