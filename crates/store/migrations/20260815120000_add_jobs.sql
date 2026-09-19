-- The durable job queue: one row per unit of background work this server owes
-- itself, outliving the process that scheduled it.
--
-- This table exists because the one long-running task the server had before it
-- (`signer::relay::flow`) kept its *state* on `upstream_orders` and its
-- *schedule* nowhere at all: a `tokio::spawn` a restart destroyed, re-created
-- from scratch by a startup sweep, with no attempt count, no backoff, no lease,
-- and no way for anything but that one backend to queue work. A failure of any
-- kind -- a TCP reset mid-poll, a nameserver hiccup, a whole-attempt timeout --
-- was therefore terminal, because there was nowhere to record that it should be
-- tried again.
--
-- **There is deliberately no foreign key**, which is the opposite of every other
-- table here but `audit_log` (20260809120000), and for a different reason than
-- that one's. A queue is generic: `payload` names whatever `kind` means -- an
-- order today, a certificate serial or nothing at all tomorrow -- so a typed FK
-- would either be wrong for every other kind or force one nullable column per
-- kind. The consequence is stated rather than hidden: a job whose subject was
-- deleted is *retired by its handler* ("the order no longer exists"), which is a
-- terminal outcome recorded in `last_error`, not an orphan nothing sweeps.
--
-- `payload` is JSON TEXT rather than a BLOB, and that is only possible because
-- the one genuinely binary piece of state in the crate -- the relayed CSR --
-- stays on `upstream_orders.csr_der` where it already lives. Keeping it that way
-- is what lets an operator read this table with `sqlite3` and see what is
-- queued; every other structured column in this schema (`orders.identifiers`,
-- `orders.error`, `audit_log.identifiers`) is JSON TEXT for the same reason.
CREATE TABLE IF NOT EXISTS jobs
(
    id           VARCHAR(36) PRIMARY KEY NOT NULL,
    -- Which handler runs this row. A closed set in code and deliberately **not**
    -- a CHECK: a kind is registered by whichever subsystem owns it, and a CHECK
    -- is exactly what SQLite cannot add later without a table rebuild, so every
    -- future kind would cost one. The runner claims only kinds its registry
    -- holds, so an unknown one is skipped rather than mis-run -- which is also
    -- what lets an older binary meet a row a newer one wrote.
    kind         TEXT NOT NULL,
    -- The identity of the work within its kind: the local order id for a relay,
    -- a profile name for a periodic sweep. Paired with `kind` in the partial
    -- unique index below, this is the whole deduplication story.
    dedup_key    TEXT NOT NULL,
    -- What the work needs, as JSON. The *identity* of the subject, never a
    -- snapshot of its state: a snapshot goes stale across a retry, and every
    -- durable thing a handler needs is already in its own table.
    payload      TEXT NOT NULL DEFAULT '{}',
    -- 'ready'     eligible at `run_at`
    -- 'running'   claimed, lease held until `lease_until`
    -- 'done'      the handler said so
    -- 'failed'    permanently: the handler refused, the attempts ran out, or
    --             `deadline` passed
    -- 'cancelled' retired by an operator. Nothing writes it yet, and it is
    --             declared now for the reason above -- the
    --             `admin_sessions.state = 'pending_mfa'` treatment
    --             (20260808120000), where a CHECK was written before anything
    --             filled it precisely so no rebuild would be needed later.
    status       TEXT NOT NULL
                     CHECK (status IN ('ready', 'running', 'done', 'failed',
                                       'cancelled')),
    -- Not before this instant. The backoff is a write to this column, so the
    -- schedule is durable: a restart mid-backoff resumes the wait rather than
    -- retrying immediately, which is the whole difference from a `tokio::sleep`.
    run_at       INTEGER NOT NULL,
    -- Incremented at *claim*, not at completion. A job that reliably kills the
    -- process therefore still exhausts its budget instead of crash-looping for
    -- ever: the counter has to cost something even when nothing reports back.
    attempts     INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL,
    -- The outer bound on retrying, epoch seconds, NULL for "no deadline".
    -- `max_attempts` bounds the effort and this bounds the calendar; a long
    -- outage needs both. Set by whoever enqueues, from the thing the work is
    -- *for*: the relay sets it to the local order's own `expires`, because past
    -- that point the order is refused on read and a certificate obtained
    -- upstream could never be collected.
    deadline     INTEGER,
    -- While 'running': when the claim goes stale and another runner may take the
    -- row. A process killed mid-job leaves it 'running' for ever otherwise.
    lease_until  INTEGER,
    -- Which runner holds it, one id per process. Every write that settles a job
    -- is guarded on this, so a runner whose lease expired and was reclaimed
    -- cannot overwrite the row a second runner now owns.
    lease_owner  TEXT,
    -- Why the last attempt did not finish. Operator-facing; the client-visible
    -- consequence is written by the handler onto its own subject.
    last_error   TEXT,
    created_at   INTEGER NOT NULL,
    updated_at   INTEGER NOT NULL
);

-- The deduplication guard, and **partial on purpose**: only a live job holds an
-- identity. A plain UNIQUE(kind, dedup_key) would let one finished job block its
-- own kind for that key for ever -- fatal for a periodic kind whose key is a
-- constant, and wrong for an order retried after a failure. Serves
-- `Job::enqueue`'s `INSERT OR IGNORE`, whose `rows_affected() == 0` reads as
-- "already queued", the same guard shape `UpstreamOrder::create` takes on its
-- primary key (20260730120000).
CREATE UNIQUE INDEX IF NOT EXISTS idx_jobs_identity
    ON jobs (kind, dedup_key) WHERE status IN ('ready', 'running');
-- `Job::claim_next`: the oldest eligible row of a registered kind.
CREATE INDEX IF NOT EXISTS idx_jobs_claim ON jobs (status, run_at);
-- `Job::reclaim_expired`: rows whose runner died holding the lease.
CREATE INDEX IF NOT EXISTS idx_jobs_lease ON jobs (status, lease_until);
-- `Job::cleanup`: the retention sweep over terminal rows.
CREATE INDEX IF NOT EXISTS idx_jobs_retention ON jobs (status, updated_at);
