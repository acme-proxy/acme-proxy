# ADR 0011: Metrics are built on `prometheus-client`, one registry per scrape

## Status

Accepted. Supersedes the metrics clause of
[ADR 0009](0009-dependency-policy.md), which listed the Prometheus text format
among the protocols this project writes by hand.

## Context

The exporter was written by hand: a `BTreeMap` of counters per family and a
`write!` per series. ADR 0009 accepted that for counters and a gauge, and named
latency histograms as the point where a library would earn its place.

A histogram is where hand-writing stops being small. Each series needs its
buckets, a running sum and a count, and every bucket is rendered cumulatively
with a final `+Inf` bucket. A mistake in any of that produces a scrape the
collector reads wrongly, or rejects outright.

Of the Rust clients, most keep a process-wide registry or recorder: the
`metrics` facade installs a global recorder, and the `prometheus` crate has a
default registry. ADR 0009 refuses global state, because tests sharing one
registry would count each other's requests. `prometheus-client` has no global
state at all: a `Registry` is an ordinary value. It adds `dtoa` and a derive
macro to the graph; `itoa` and `parking_lot` were already there. Its licence is
Apache-2.0 OR MIT.

## Decision

- **`crates/jobs/src/metrics.rs` is built on `prometheus-client`.** The
  families are fields of `Metrics`, which `server::Assembly` holds across
  reloads, as before.
- **The registry is built per scrape.** `Metrics::render` builds a `Registry`
  over clones of the families (a clone shares its series) with the `role` label
  as a registry label. Nothing registers into shared state, and the roles stay a
  builder step on `Metrics`.
- **Every family is declared even when empty.** The library leaves an empty
  family out of the exposition; a wrapper keeps it in, so a dashboard can tell
  "has not happened yet" from a misspelled name.
- **The output is OpenMetrics**, the library's only text format. Series names
  are unchanged; a counter's `# TYPE` line drops `_total`, and the body ends
  with `# EOF`.
- **Label values are escaped before they reach the library**, which writes them
  verbatim.
- **Two histograms**: request latency by profile and route, and issuance latency
  (finalize accepted to certificate stored) by profile. Neither carries `status`
  or `reason`, since a histogram multiplies every label by its buckets.

## Consequences

- Histograms and their buckets are the library's to get right, not this
  project's.
- A new family is a field and a `register` call in `render`. It appears on an
  empty registry at once, which `tests/grafana_dashboard.rs` relies on.
- Series order within a family is no longer sorted, so tests match series
  individually rather than comparing the whole output.
- A scraper that only reads the old text format and ignores the content type
  would misread `# EOF` and the `_total`-less `# TYPE` lines. Prometheus
  negotiates OpenMetrics and reads both.

## Enforced by

- The unit tests in `crates/jobs/src/metrics.rs`, which assert the exposition as
  text, including an empty registry's families and the closing `# EOF`.
- `tests/grafana_dashboard.rs`, both directions, per family.
- `cargo deny check` and the SBOM drift check, as for every dependency.
