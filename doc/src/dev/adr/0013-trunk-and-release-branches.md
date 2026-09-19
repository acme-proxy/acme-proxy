# ADR 0013: `main` is the trunk, and a patch line is a release branch cut when a fix needs one

## Status

Accepted.

## Context

Every change landed on `main`, and every release was tagged there. That left no
way to ship a fix alone. Once `main` held work towards the next minor, some of
it breaking under [ADR 0001](0001-pre-1-0-compatibility.md), a bug in the last
release could only be fixed by releasing the next minor with it. An operator
who needed the fix had to migrate their configuration to get it.

The only image was a release's. Nothing let an operator try the next release
before it was cut, short of building it themselves.

## Decision

- **`main` is the trunk.** It is the default branch. Every pull request,
  feature or fix, targets it, and it is releasable at every commit: CI is green
  before a merge.
- **A minor release, `X.Y.0`, is a tag on `main`.**
- **A patch line is the branch `release/X.Y`, cut from the `X.Y.0` tag when
  the first fix needs to ship on it**, not at release time. A minor that never
  needs a patch never gets a branch.
- **A fix lands upstream first.** It merges on `main`, then is cherry-picked
  with `git cherry-pick -x` onto a topic branch and merged into `release/X.Y`
  through a pull request. A fix is never made on a release branch alone, so the
  next minor cannot regress it.
- **A patch release, `X.Y.Z` with `Z` above 0, is a tag on `release/X.Y`.**
  Its version bump, pins, SBOM and changelog section are made on that branch.
  The changelog section is then cherry-picked to `main`, so the trunk's
  changelog lists every release.
- **Images follow
  [ADR 0012](0012-container-images-are-built-natively-per-architecture.md).**
  A release tag publishes `X.Y.Z`, `X.Y` and `latest`. Every merge to `main`
  publishes `edge`. A push to a release branch publishes nothing, because its
  image is its next patch tag's.
- **`main` and every `release/*` branch are protected** by a repository
  ruleset: changes arrive by pull request with the CI checks passing, and the
  branch can be neither force-pushed nor deleted.

## Consequences

- A fix reaches operators without the next minor's changes, and `X.Y` gives
  them patch releases without a configuration change.
- Each backport is a second pull request, and a cherry-pick can conflict once
  `main` has moved away from the release. The `-x` trailer records where each
  one came from.
- Only the newest release line is maintained as a rule. An older one gets a
  branch only if a fix is worth the backport, and the nightly advisory scan
  covers the newest release branch alone.
- The book tracks `main`, so between releases it can describe behaviour no
  release has yet.
- A patch tag on `main`, or a tag on a commit its branch does not contain, is
  refused before anything builds. The version in `main`'s `Cargo.toml` stays at
  the last minor until the next one is cut, so `edge` reports that version.

## Enforced by

- `guard` in `.github/workflows/release.yml`: "The tag is on its release line",
  and "CI passed on the tagged commit" against that branch.
- The `push` trigger in `.github/workflows/ci.yml`, which covers `main` and
  `release/[0-9]+.[0-9]+` so that the guard has a run to read.
- The repository rulesets on `main` and `release/*`, configured in the
  repository settings rather than in the tree.
- The procedures in [Contributing](../contributing.md#cutting-a-release):
  review only.
