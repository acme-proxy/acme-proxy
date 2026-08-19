# Grafana Dashboard

A dashboard over the four metric families the
[`[metrics]`](../configuration/reference.md#metrics) listener exposes ships in
the repository at `dashboards/acme-proxy.json`. It is a starting point rather
than a fixed artifact — import it, then change whatever your deployment needs.

Enable the metrics listener first; the dashboard has nothing to draw otherwise.
See [Monitoring](monitoring.md#metrics) for the endpoint and a scrape
configuration.

## Importing it

Download it from the repository:

```bash
curl -O https://raw.githubusercontent.com/acme-proxy/acme-proxy/main/dashboards/acme-proxy.json
```

Then **Dashboards → New → Import** in Grafana, upload the file, and pick your
Prometheus data source when asked.

For a provisioned Grafana, drop it in the dashboards directory your provider
config points at:

```yaml
# /etc/grafana/provisioning/dashboards/acme-proxy.yaml
apiVersion: 1
providers:
  - name: acme-proxy
    type: file
    options:
      path: /var/lib/grafana/dashboards
```

The data source is a **template variable**, deliberately, rather than the
`__inputs` block Grafana's "export for sharing externally" produces: that block
is never substituted under file provisioning, so a dashboard carrying one works
when a human imports it and silently breaks when a machine does.

## What is on it

Twelve panels in three rows.

**Issuance** — certificates signed and refused over the dashboard's time range,
the success ratio between them, the issuance rate split by endpoint, and
refusals broken down by ACME problem type. That last panel is the one worth
knowing about: `reason` says *why* the CA refused, in the same vocabulary
[`acme-proxy audit list`](audit.md) prints, because both are rendered from one
record.

**Requests** — request rate by route and by status, the 5xx share, requests shed
by admission control, and unmatched paths.

**Database** — the SQLite pool by state, and its saturation.

There are **no latency panels**, because there are no latency metrics: the
exporter has counters and one gauge, and histograms are an open item. Until
then, `latency_ms` on the access line is where per-request timing lives.

## Two things to know before editing it

**`route` is safe to group by.** It is the matched route *pattern*, so
`/order/{id}` is one series however many orders exist. Grouping by a raw URI
would be a series per order, per account and per challenge — which is memory in
Prometheus for as long as it retains them. The same reason every unmatched
request collapses into a single `<unmatched>` series rather than one per path a
scanner tries.

**The pool panels must not be filtered by `$profile`.** Everything else on the
dashboard is scoped to the profile variable, so reaching for it on the two
database panels is the natural next edit — but
`acme_proxy_database_pool_connections` is process-wide and carries no `profile`
label at all. Filtering it matches nothing, and the panel goes blank with no
error to explain why. A test in the repository (`tests/grafana_dashboard.rs`)
fails if the shipped dashboard ever grows that filter.

## Empty panels are not always a fault

Three cases read as "no data" and are all correct:

- **Refusals by reason** is empty on a CA that has refused nothing. Only
  refusals the CA itself made are counted — an order rejected at `newOrder`,
  for a wildcard on an endpoint offering no `dns-01` for instance, is protocol
  bookkeeping rather than a CA action, and appears as a `403` on the request
  panels instead.
- **Success ratio** and **5xx share** show `NaN` when nothing has happened at
  all, because the ratio is genuinely undefined. They read `0` only when
  something *did* happen and all of it failed.
- Everything is empty for the first scrape or two after a restart. Counters do
  not survive a restart, though they do survive a `SIGHUP` reload.

## Keeping it honest

`tests/grafana_dashboard.rs` runs in CI and asserts that every metric the
dashboard queries is one this build actually emits — and the converse, that no
emitted family is missing from it. The names come from rendering a real, empty
registry rather than from a list somebody maintains by hand, so a renamed metric
fails the build instead of quietly blanking a panel that nobody looks at until
an incident.
