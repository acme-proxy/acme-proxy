# Alpine's `lego` package is stuck on the 4.x line, which predates `lego
# accounts keyrollover` (added in v5.0.0, PR go-acme/lego#2950) that
# key_change.rs needs — so this builds a real pinned release from source
# instead of a packaged one. Debian trixie's own `golang-go` is 1.24, but
# lego v5.3.1's go.mod declares `go 1.25.0`, so Go itself comes from the
# official tarball (checksum pinned below) rather than apt, same reasoning as
# the root Containerfile's rustup install.
FROM debian:trixie-slim AS build
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && curl -fsSL -o /tmp/go.tar.gz https://go.dev/dl/go1.25.12.linux-amd64.tar.gz \
    && echo "234828b7a89e0e303d2556310ee549fbcf253d28de937bac3da13d6294262ac1  /tmp/go.tar.gz" | sha256sum -c - \
    && tar -C /usr/local -xzf /tmp/go.tar.gz \
    && rm /tmp/go.tar.gz
ENV GOPATH=/go
ENV PATH="/usr/local/go/bin:/go/bin:${PATH}"
RUN go install github.com/go-acme/lego/v5@v5.3.1

FROM debian:trixie-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /go/bin/lego /usr/bin/lego
