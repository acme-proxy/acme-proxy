//! `[jobs]` — the durable background-work queue.

use serde::Deserialize;

/// Governs the `jobs` table and the one runner that drains it.
///
/// Process-wide, so deliberately absent from `PROFILE_SECTIONS`: there is one
/// queue, one table and one runner for the process, and a per-endpoint retry
/// budget would mean a job's pacing depended on which profile happened to
/// enqueue it rather than on what the work is. The per-job knobs that genuinely
/// vary — how long one attempt may take, how many times to try, when to give up
/// altogether — are set by the handler and by whoever enqueues, not here.
///
/// There is no `enabled` key. The runner is how the server finishes work it has
/// already promised a client (an order answered `processing` is owed a
/// certificate), so switching it off would not disable a feature, it would strand
/// the orders. What an operator can tune is how hard and how long it tries.
///
/// **Every key here reloads on `SIGHUP`**, six of the seven having been refused
/// by name until the runner stopped snapshotting them at spawn. That mattered
/// more than most: these are the knobs somebody reaches for while an incident is
/// running, and charging a restart for them dropped the very in-flight orders the
/// retuning was meant to save. Each takes effect at a different grain, said on
/// each key below.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct JobsConfig {
    /// How often the runner looks for work nobody woke it for.
    ///
    /// Bounds only *scheduled* work — a backoff coming due, a periodic job
    /// firing. An enqueue wakes the runner directly, so a relay queued by
    /// `finalize` starts immediately whatever this says, which is what keeps the
    /// client's own polling from waiting on a tick. Milliseconds rather than
    /// seconds so a test can drive it below one.
    ///
    /// A reload of this one takes effect *at once* rather than after one last
    /// sleep at the old value — lowering it is something an operator does because
    /// something is waiting now.
    pub poll_interval_ms: u64,
    /// How many jobs may run at once.
    ///
    /// This was `MAX_CONCURRENT_RELAYS`, a constant inside the `relay` backend,
    /// and the reasoning carries over unchanged: a restart after an upstream
    /// outage that left a few thousand orders in flight would otherwise become a
    /// few thousand concurrent pollers against one CA, which is how a recoverable
    /// backlog turns into a rate-limit ban. Eight is well under any public CA's
    /// concurrency expectations and still drains a backlog steadily.
    ///
    /// A reload raising it widens the pool immediately; lowering it takes back
    /// only the slots that are free and converges as running jobs finish, since
    /// nothing in flight is ever cancelled to reach a number.
    pub max_concurrent: usize,
    /// How many attempts a job gets before it is retired permanently.
    ///
    /// Counted at claim, so a job that kills the process still exhausts it.
    /// With the 30-second base below and doubling, five attempts span roughly
    /// seven and a half minutes of retrying: long enough to outlast an upstream
    /// blip, short enough not to keep a doomed order alive. The long tail is
    /// bounded by the job's own deadline rather than by this.
    ///
    /// **Frozen onto each row when it is queued**, unlike every other key here,
    /// which the runner re-derives on each pass of its loop. A reload therefore
    /// reaches jobs queued from then on and not a backlog already waiting — which
    /// is the safe direction, since the alternative would silently extend the
    /// life of work an operator had already decided to give up on.
    pub max_attempts: u32,
    /// The first retry delay; each subsequent one doubles.
    ///
    /// Longer than any single upstream round trip, so a retry is not simply the
    /// same failure again, and short enough that a blip clears inside one
    /// client poll cycle.
    pub retry_base_seconds: u64,
    /// The ceiling the doubling stops at.
    ///
    /// An hour sits well under the default order lifetime (`order.validity_seconds`,
    /// seven days), which keeps a job's deadline the binding constraint rather
    /// than this: a day-long outage should not schedule the next attempt days
    /// out.
    pub retry_max_seconds: u64,
    /// The default budget for one attempt, and therefore how long a claim is
    /// held before another runner may take the row.
    ///
    /// Matches `signer.relay.poll_timeout_secs`'s own default, the longest job
    /// this crate has. A handler needing a different one says so itself, so this
    /// is the floor for everything that does not care.
    ///
    /// This and the two retry keys above reach the *next claim*. A job already
    /// running keeps the budget and the backoff it was claimed under, because
    /// moving an attempt's deadline out from under it mid-flight is how a job
    /// gets reclaimed as crashed while it is still working.
    pub lease_seconds: u64,
    /// Delete settled job rows older than this many days.
    ///
    /// Unlike `audit.retention_days`, this defaults to a *non-zero* value: a
    /// finished job is a receipt, not evidence, and the trail that has to be
    /// complete is `audit_log`'s. A week outlives a weekend, which is the span
    /// that matters for reading why an issuance failed. `0` keeps everything for
    /// ever and stops the sweep from being scheduled at all.
    pub retention_days: u64,
}

impl Default for JobsConfig {
    fn default() -> Self {
        Self {
            poll_interval_ms: 1_000,
            max_concurrent: 8,
            max_attempts: 5,
            retry_base_seconds: 30,
            retry_max_seconds: 3_600,
            lease_seconds: 300,
            retention_days: 7,
        }
    }
}
