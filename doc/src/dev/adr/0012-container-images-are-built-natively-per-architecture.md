# ADR 0012: Images are built natively per architecture, uncached, and published only past a guard

## Status

Accepted.

## Context

The repository shipped a `Containerfile` and documented a container deployment,
but published no image, so every container user compiled the crate. A
contribution ([#3](https://github.com/acme-proxy/acme-proxy/pull/3)) added a
workflow that published one on a release tag. Its approach was right: a
tag-only trigger, GHCR with the workflow's own token, and actions pinned by SHA.
Four of its details were not.

- **It built the lab's binary.** The `Containerfile` compiled
  `--profile e2e`, which is release without fat LTO, tuned for the e2e lab's
  inner loop. Nothing outside the binary tells the two profiles apart, so a
  published image of the wrong one would not have been noticed.
- **It emulated arm64 with QEMU.** The release profile is fat LTO with one
  codegen unit. Under emulation that is the slowest build this project has,
  with no timeout.
- **It configured a build cache that could not help.** `type=gha` is scoped to
  the ref, so a tag never reads another tag's entries. The build's real cache
  is two `RUN --mount=type=cache` mounts, which no cache exporter preserves.
  And `COPY . .` sits directly above the one expensive `RUN`, so layer reuse
  buys nothing. The cost was real, though: `mode=max` writes gigabytes into the
  repository's shared 10 GB Actions cache, and evicts the `rust-cache` entries
  every CI job depends on.
- **Nothing checked the tag.** CI runs on pushes to `main`, not on tags. A tag
  that did not match the manifest's version, or that pointed at a commit CI had
  never passed, would have published.

An image is also the one prebuilt artifact this project distributes, and its
users run it as their certificate authority. That calls for provenance an
operator can check.

## Decision

- **The `Containerfile` takes the cargo profile as a build argument,
  `CARGO_PROFILE`, defaulting to `release`.** The lab passes `e2e` explicitly.
  The default is the distribution build, so a hand-run `podman build .`
  reproduces the published image instead of a near miss.
- **Each architecture builds on a native runner**, `ubuntu-latest` and
  `ubuntu-24.04-arm`, as a matrix. Each leg pushes one single-architecture
  image by digest, with no tag. A final job joins the two digests into one
  manifest list and tags that, after checking there are exactly two.
- **No build cache**, and the workflow says why, since an absent cache is the
  first thing a reader would add.
- **A guard job runs before any build.** It refuses a tag that differs from
  `[workspace.package].version`, or from any crate's `=x.y.z` pin. It refuses
  a tag off its release line, `main` for `X.Y.0` and `release/X.Y` for a
  patch ([ADR 0013](0013-trunk-and-release-branches.md)). It also refuses a
  tag whose commit has no successful `push` run of `ci.yml` on that branch. It
  fails rather than waits: the release procedure tags only once CI is green.
- **Build provenance is attested once, on the manifest list's digest**, and
  pushed to the registry. BuildKit's own per-image attestations are off: with
  them on, each leg pushes an index instead of an image, and joining those
  indexes would carry attestation manifests that nothing references.
- **A release tag publishes `X.Y.Z`, `X.Y` and `latest`.** The floating `X.Y`
  is the newest release of its line. It never crosses a minor, so it never
  picks up a breaking change, and an operator following it gets patch releases
  unattended. There is no floating `X`: before 1.0 a minor release is where
  breaking changes land. Both floating tags move only on a tag push, so a
  manual republish of an older tag moves neither. `latest` also needs the tag
  to be the highest release, so a patch to an older line leaves it alone.
- **Every push to `main` publishes `edge` and `sha-<commit>`**, once all of
  `ci.yml` has passed on it: `ci.yml` calls this workflow as its last job. The
  build is the same release build, attested the same way; only the tags
  differ.
- **The image carries the default feature set**, the same binary
  `cargo install acme-proxy` produces. `hsm` needs a build of one's own.

## Consequences

- An uncached release build takes tens of minutes per architecture, and now
  runs on every merge to `main` as well as on every release. A public
  repository's runners are not billed, and `timeout-minutes` is set to stop a
  wedged builder, not as an estimate. Merges to `main` queue rather than cancel
  each other, since a cancelled publish leaves orphaned manifests.
- `edge` and the `sha-` tags accumulate a version per merge in GHCR. Pruning
  them is a registry policy, and it must keep untagged versions (below).
- A hand-run `podman build .` is now as slow as a release build. Contributors
  building the lab image by hand pass `--build-arg CARGO_PROFILE=e2e`, as
  `tests/e2e/common.rs` does.
- The attestation covers the manifest list. Verifying by tag finds it, since a
  tag resolves to the list. Verifying the digest of one architecture's image
  finds nothing. If that ever matters, the fix is a second attestation per leg,
  not moving this one.
- The per-architecture images show in GHCR as untagged versions. The manifest
  list references them, so a cleanup policy must never prune untagged versions.
- A package that the workflow's token creates under an organisation starts
  private. The first release needs a one-time change to inherit the
  repository's visibility, and the workflow's run summary says so.
- A failed architecture fails the release with no partial publish. The two legs
  are independent (`fail-fast: false`), so the healthy one still shows whether
  the fault is the architecture or the change.

## Enforced by

- `guard` in `.github/workflows/release.yml`: the version and pin check, the
  release-line check, the CI check, and the highest-release check that gates
  `latest`.
- The `image` job in `.github/workflows/ci.yml`, which `needs:` every other
  job before it publishes `edge`.
- The digest-count check in that workflow's `publish` job.
- `tests/e2e/common.rs`, whose image build names `CARGO_PROFILE=e2e`; nothing
  else selects the lab's profile.
