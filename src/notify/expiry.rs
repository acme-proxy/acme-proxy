//! The periodic expiry digest: one message per profile, listing the
//! certificates approaching their notAfter.
//!
//! ## Why a digest, and not one message per certificate
//!
//! The obvious shape is a reminder per certificate, rate-limited per
//! certificate. It does not work, and the reason is worth stating once here
//! rather than being rediscovered: **a renewal does not stop its predecessor
//! expiring.** A client renewing at day 60 of 90 places a *new* order, which
//! becomes a new row with a new certificate; the old row keeps its own
//! notAfter and reaches it a month later regardless. A per-certificate
//! reminder therefore fires for every certificate the CA has ever issued, on
//! its way out, in exactly the deployments where everything is working — and a
//! channel that reports healthy automation as if it were a problem is one an
//! operator learns to filter.
//!
//! So the unit is the profile and the period, not the certificate. Two things
//! fall out of that:
//!
//! - **There is no "already reminded" column.** The per-certificate shape
//!   needed one, plus a guarded claim to make it safe against two runners.
//!   Here the job's own [`JobOutcome::Reschedule`] *is* the cadence, and it
//!   survives a restart because the row keeps its `run_at` — the property
//!   [`crate::jobs::sweep`] documents.
//! - **Supersession is an annotation, never a filter.** Each entry says
//!   whether something has replaced it, and the operator reads the digest by
//!   looking for the entries where nothing has. Filtering the replaced ones
//!   out would be tidier and is the wrong risk: a wrong "already renewed" is
//!   an operator ignoring a certificate that really is about to lapse, where a
//!   wrong "not renewed" is one line of noise. Every rule below therefore errs
//!   towards *not* claiming supersession.
//!
//! ## One row per profile
//!
//! One registered kind, one job row per profile, keyed on the profile name.
//! Each profile keeps its own `interval_days` and produces its own message,
//! which is what "one summary per profile" means.
//!
//! That makes the rows something this handler has to maintain, because
//! [`JobHandler::recover`] does not run on every reload — `recover_new_kinds`
//! in [`crate::jobs::runner`] runs it only for kinds the previous generation
//! did not have, so a profile mounted by a `SIGHUP` into a process that
//! already had this kind registered would never get a row. Each pass therefore
//! re-enqueues for every profile it knows about; the enqueue is `INSERT OR
//! IGNORE` against the partial identity index, so a profile that already has a
//! live row costs one statement and changes nothing. The bound is that a newly
//! mounted profile is noticed on the next pass of an existing one — its row is
//! then `run_at = now`, so it fires as soon as it exists.
//!
//! A row whose profile is *gone* is the one case that answers
//! [`JobOutcome::Done`] rather than rescheduling. [`crate::jobs::sweep`]'s law
//! is *never [`JobOutcome::Failed`]* — a retired periodic job never
//! re-enqueues itself, so one transient database error would stop the digest
//! for the life of the process — and that is a different statement from
//! *always reschedule*: an unmounted profile has nothing left to report, and
//! retiring its row is how it stops.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tracing::{debug, error, info};

use super::{CertificatesExpiringData, ExpiringCertificate, Notifiers, NotifyEvent};
use crate::admin;
use crate::jobs::{JobHandler, JobOutcome, JobQueue, JobSpec};
use crate::sqlite::db::Database;
use crate::sqlite::job::Job;
use crate::sqlite::nonce::now_secs;
use crate::sqlite::order::{Order, UNPARSABLE_NOT_AFTER};

/// The `jobs.kind` the digest runs under.
pub const EXPIRY_JOB_KIND: &str = "notify_expiry_digest";

/// How many un-stamped rows one pass backfills.
///
/// Each one parses an X.509 chain, and this runs on the same runner as every
/// other job in the process. A deployment upgrading with a hundred thousand
/// historical orders converges over a few passes instead of holding a worker
/// for minutes on the first one.
const BACKFILL_BATCH: i64 = 500;

/// One profile's digest settings, snapshotted from its resolved `[notify]`.
#[derive(Debug, Clone, Copy)]
pub struct ExpirySettings {
    lead: Duration,
    lead_days: u64,
    interval: Duration,
    max_entries: i64,
}

impl ExpirySettings {
    /// The settings for a profile, or `None` when `lead_days` is `0` — which is
    /// off, and is why a profile with the default configuration never gets a
    /// row.
    #[must_use]
    pub fn from_config(config: &crate::config::ExpiryNotifyConfig) -> Option<Self> {
        if config.lead_days == 0 {
            return None;
        }
        Some(Self {
            lead: Duration::from_secs(config.lead_days * 24 * 60 * 60),
            lead_days: config.lead_days,
            // Floored at a day: `interval_days = 0` would otherwise make the
            // runner re-run this immediately and for ever, which is a busy loop
            // that also sends a message every pass.
            interval: Duration::from_secs(config.interval_days.max(1) * 24 * 60 * 60),
            max_entries: i64::try_from(config.max_entries).unwrap_or(i64::MAX).max(1),
        })
    }
}

/// The digest, over every profile that configured one.
pub struct ExpiryDigestJob {
    profiles: HashMap<String, ExpirySettings>,
    notifiers: Notifiers,
    database: Arc<Database>,
    /// The queue, held so [`Self::run`] can reconcile the per-profile rows.
    /// [`JobHandler::run`] is handed only the row it claimed, and the
    /// reconcile cannot wait for `recover` — see the module docs.
    queue: JobQueue,
}

impl ExpiryDigestJob {
    /// Builds the handler from the resolved profiles, or `None` when not one of
    /// them asked for a digest — registering a handler whose every pass finds
    /// nothing to do is a row an operator has to learn to ignore, the reasoning
    /// `CrlSweepJob` and `SweepJob::audit` are both registered conditionally
    /// for.
    #[must_use]
    pub fn from_profiles(
        resolved: &[crate::config::ProfileConfig],
        notifiers: Notifiers,
        database: Arc<Database>,
        queue: JobQueue,
    ) -> Option<Self> {
        let profiles: HashMap<String, ExpirySettings> = resolved
            .iter()
            .filter_map(|profile| {
                ExpirySettings::from_config(&profile.sections.notify.expiry)
                    .map(|settings| (profile.name.clone(), settings))
            })
            .collect();
        if profiles.is_empty() {
            return None;
        }
        Some(Self {
            profiles,
            notifiers,
            database,
            queue,
        })
    }

    /// Stamps `cert_not_after` onto rows finalized before the column existed.
    ///
    /// Best-effort in both directions: a row whose chain will not parse takes
    /// the sentinel so the next pass skips it, and a failure to *write* is
    /// logged and dropped, since the digest below is still worth sending
    /// without it.
    async fn backfill(&self, profile: &str) {
        let rows = match Order::find_unstamped(profile, BACKFILL_BATCH, &self.database).await {
            Ok(rows) => rows,
            Err(error) => {
                error!(event = "notify_expiry_backfill_failed", outcome = "failure", profile = %profile, error = %error);
                return;
            }
        };
        if rows.is_empty() {
            return;
        }

        let mut stamped = 0_u64;
        let mut unparsable = 0_u64;
        for (id, chain) in rows {
            let not_after = leaf_not_after(&chain);
            if not_after == UNPARSABLE_NOT_AFTER {
                unparsable += 1;
            } else {
                stamped += 1;
            }
            if let Err(error) = Order::set_cert_not_after(id, not_after, &self.database).await {
                error!(event = "notify_expiry_backfill_failed", outcome = "failure", profile = %profile, order_id = %id, error = %error);
                return;
            }
        }
        info!(
            event = "notify_expiry_backfilled",
            outcome = "success",
            profile = %profile,
            rows_stamped = stamped,
            rows_unparsable = unparsable
        );
    }

    /// Builds one profile's digest, or `None` when nothing is expiring.
    ///
    /// Silence is the design: a message that arrives every week whether or not
    /// anything is wrong is one nobody opens, so the *absence* of a digest is
    /// what "everything is renewed" looks like.
    async fn collect(
        &self,
        profile: &str,
        settings: ExpirySettings,
    ) -> Result<Option<CertificatesExpiringData>, sqlx::Error> {
        let now = now_secs();
        // The window, the annotation and the ordering all come from
        // `crate::admin` — the digest is one of three consumers of that listing
        // (the panel and `order list --expiring-in` are the others), and it
        // asks for the same thing they do so the three cannot come to disagree
        // about what "expiring" or "already replaced" means. `include_superseded`
        // is always `true` here: supersession is an annotation and never a
        // filter, for the reason in this module's docs.
        let query = admin::ExpiringQuery {
            profile: Some(profile.to_string()),
            before: now.saturating_add(i64::try_from(settings.lead.as_secs()).unwrap_or(0)),
            include_superseded: true,
            limit: settings.max_entries,
            offset: 0,
        };
        let (entries, total, _hidden) = admin::list_expiring(&query, self.database.clone()).await?;
        if entries.is_empty() {
            return Ok(None);
        }

        let certificates = entries
            .into_iter()
            .map(|entry| ExpiringCertificate {
                order_id: entry.order.id.to_string(),
                account_id: entry.order.account_id.to_string(),
                cert_serial: entry.order.cert_serial.unwrap_or_default(),
                identifiers: entry
                    .order
                    .identifiers
                    .into_iter()
                    .map(|identifier| identifier.value)
                    .collect(),
                not_after: entry.order.cert_not_after.unwrap_or_default(),
                days_remaining: entry.days_remaining,
                superseded_by: entry.superseded_by,
            })
            .collect();

        Ok(Some(CertificatesExpiringData {
            profile: profile.to_string(),
            generated_at: now,
            lead_days: settings.lead_days,
            total,
            certificates,
        }))
    }

    /// Enqueues a row for every profile that wants one.
    ///
    /// Idempotent — the identity index refuses a second live row per profile —
    /// which is what lets this run from both `recover` and every pass. See the
    /// module docs for why the second caller is needed at all.
    async fn reconcile(&self, queue: &JobQueue) {
        for profile in self.profiles.keys() {
            queue
                .enqueue_or_log(JobSpec::now(EXPIRY_JOB_KIND, profile.clone()))
                .await;
        }
    }
}

/// The leaf's notAfter out of a stored PEM chain, or [`UNPARSABLE_NOT_AFTER`].
fn leaf_not_after(chain: &str) -> i64 {
    crate::cert::leaf_der_from_chain(chain)
        .ok()
        .and_then(|der| crate::cert::cert_validity(&der).ok())
        .map_or(UNPARSABLE_NOT_AFTER, |(_, not_after)| not_after)
}

#[async_trait]
impl JobHandler for ExpiryDigestJob {
    fn kind(&self) -> &'static str {
        EXPIRY_JOB_KIND
    }

    async fn run(&self, job: &Job) -> JobOutcome {
        let profile = job.dedup_key.clone();
        let Some(settings) = self.profiles.get(&profile).copied() else {
            // The profile was unmounted, or its `lead_days` went back to zero.
            // The one case that retires the row rather than rescheduling it —
            // see the module docs.
            info!(
                event = "notify_expiry_digest_retired",
                outcome = "success",
                profile = %profile
            );
            return JobOutcome::Done;
        };

        // Before the work, not after: a pass that fails below still leaves the
        // other profiles' rows in place.
        self.reconcile(&self.queue).await;

        self.backfill(&profile).await;

        match self.collect(&profile, settings).await {
            Ok(None) => debug!(
                event = "notify_expiry_digest_skipped",
                outcome = "success",
                profile = %profile
            ),
            Ok(Some(data)) => {
                let listed = data.certificates.len();
                let total = data.total;
                if let Some(dispatcher) = self.notifiers.get(&profile) {
                    dispatcher
                        .dispatch(NotifyEvent::CertificatesExpiring(data))
                        .await;
                    info!(
                        event = "notify_expiry_digest_sent",
                        outcome = "success",
                        profile = %profile,
                        certificates_listed = listed,
                        certificates_total = total
                    );
                }
            }
            Err(error) => {
                error!(event = "notify_expiry_digest_failed", outcome = "failure", profile = %profile, error = %error);
            }
        }

        // **Never `Failed`**, whatever happened above — see the module docs.
        JobOutcome::Reschedule(settings.interval)
    }

    async fn recover(&self, queue: &JobQueue) {
        self.reconcile(queue).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ExpiryNotifyConfig, JobsConfig};
    use crate::notify::{BackendSlot, NotifyDispatcher};
    use crate::testutil::account_id;
    use serde_json::json;
    use std::collections::HashMap;

    const DAY: i64 = 24 * 60 * 60;

    /// A claimed row for `profile`, as the runner would hand one to `run`.
    fn row(profile: &str) -> Job {
        Job {
            id: crate::sqlite::id::mint(),
            kind: EXPIRY_JOB_KIND.to_string(),
            dedup_key: profile.to_string(),
            payload: json!({}),
            status: "running".to_string(),
            run_at: now_secs(),
            attempts: 1,
            max_attempts: 5,
            deadline: None,
            lease_until: None,
            lease_owner: None,
            last_error: None,
            created_at: now_secs(),
            updated_at: now_secs(),
        }
    }

    fn settings(lead_days: u64) -> ExpiryNotifyConfig {
        ExpiryNotifyConfig {
            lead_days,
            ..ExpiryNotifyConfig::default()
        }
    }

    /// A handler over one profile, plus the queue its rows live in.
    async fn harness(lead_days: u64) -> (ExpiryDigestJob, Arc<Database>) {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let queue = JobQueue::new(database.clone(), &JobsConfig::default());
        let dispatchers: super::super::DispatcherMap = HashMap::from([(
            "default".to_string(),
            Arc::new(NotifyDispatcher::new(
                "default",
                Vec::<BackendSlot>::new(),
                queue.clone(),
            )),
        )]);
        let (_tx, notifiers) = super::super::notifiers_channel(dispatchers);
        let job = ExpiryDigestJob {
            profiles: HashMap::from([(
                "default".to_string(),
                ExpirySettings::from_config(&settings(lead_days)).unwrap(),
            )]),
            notifiers,
            database: database.clone(),
            queue,
        };
        (job, database)
    }

    /// An issued order on the `default` profile. The real signing lives in
    /// [`crate::testutil::issued_order`], hoisted there when `admin::ops`
    /// gained the supersession annotation and needed the same row.
    async fn issued(
        db: &Database,
        account: uuid::Uuid,
        names: &[&str],
        not_after_days: i64,
    ) -> Order {
        crate::testutil::issued_order(db, "default", account, names, not_after_days).await
    }

    /// The digest's own content: what is expiring, in order, with the days
    /// counted from the sweep.
    #[tokio::test]
    async fn a_digest_lists_what_is_expiring() {
        let (job, db) = harness(14).await;
        let acct = account_id(&db).await;
        let soon = issued(&db, acct, &["soon.example.com"], 3).await;
        issued(&db, acct, &["later.example.com"], 60).await;
        // Half a day past the three, so the assertion below distinguishes a
        // floor from a round: an operator told "4 days" about a certificate
        // that lapses in three and a half has been told the wrong week.
        Order::set_cert_not_after(soon.id, now_secs() + 3 * DAY + DAY / 2, &db)
            .await
            .unwrap();

        let data = job
            .collect("default", job.profiles["default"])
            .await
            .unwrap()
            .expect("something is expiring");

        assert_eq!(data.total, 1);
        assert_eq!(data.lead_days, 14);
        assert_eq!(data.certificates.len(), 1);
        assert_eq!(
            data.certificates[0].identifiers,
            vec!["soon.example.com".to_string()]
        );
        assert_eq!(
            data.certificates[0].days_remaining, 3,
            "floored, not rounded"
        );
        assert!(data.certificates[0].superseded_by.is_none());
    }

    /// Silence when nothing is expiring — the absence of a message is what
    /// "everything is renewed" looks like, so this must be `None` and not an
    /// empty digest.
    #[tokio::test]
    async fn nothing_expiring_produces_no_digest_at_all() {
        let (job, db) = harness(14).await;
        let acct = account_id(&db).await;
        issued(&db, acct, &["fine.example.com"], 60).await;

        assert!(
            job.collect("default", job.profiles["default"])
                .await
                .unwrap()
                .is_none()
        );
    }

    /// The backfill stamps what it can read and records what it cannot, so the
    /// unreadable row is parsed once rather than on every pass for ever.
    #[tokio::test]
    async fn the_backfill_stamps_once_and_records_an_unparsable_chain() {
        let (job, db) = harness(14).await;
        let acct = account_id(&db).await;

        let good = issued(&db, acct, &["good.example.com"], 30).await;
        let bad = issued(&db, acct, &["bad.example.com"], 30).await;
        sqlx::query("UPDATE orders SET cert_not_after = NULL WHERE id IN (?, ?);")
            .bind(good.id)
            .bind(bad.id)
            .execute(&db.pool)
            .await
            .unwrap();
        sqlx::query("UPDATE orders SET certificate = 'not a pem' WHERE id = ?;")
            .bind(bad.id)
            .execute(&db.pool)
            .await
            .unwrap();

        job.backfill("default").await;

        let good = Order::find_by_id(good.id.to_string().as_str(), &db)
            .await
            .unwrap()
            .unwrap();
        assert!(good.cert_not_after.unwrap() > now_secs());
        let bad = Order::find_by_id(bad.id.to_string().as_str(), &db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(bad.cert_not_after, Some(UNPARSABLE_NOT_AFTER));

        // Nothing is left for a second pass to re-parse.
        assert!(
            Order::find_unstamped("default", 10, &db)
                .await
                .unwrap()
                .is_empty()
        );
    }

    /// A row for a profile that is no longer mounted retires. The one case
    /// that does not reschedule — see the module docs.
    #[tokio::test]
    async fn a_row_for_an_unmounted_profile_retires() {
        let (job, _db) = harness(14).await;
        assert!(matches!(job.run(&row("gone")).await, JobOutcome::Done));
    }

    /// The law the module rests on: a pass that could not reach the database
    /// must still be scheduled again. A `Failed` here retires the row, and a
    /// retired periodic job never re-enqueues itself — so one transient error
    /// would stop the digest for the life of the process.
    #[tokio::test]
    async fn a_failing_pass_reschedules_rather_than_retiring() {
        let (job, db) = harness(14).await;
        db.pool.close().await;
        assert!(matches!(
            job.run(&row("default")).await,
            JobOutcome::Reschedule(_)
        ));
    }

    /// `recover` puts one row per configured profile in the queue, and running
    /// again is safe — the identity index refuses a second live row, which is
    /// what lets the reconcile also run on every pass.
    #[tokio::test]
    async fn recovery_queues_one_row_per_profile_however_often_it_runs() {
        let (job, db) = harness(14).await;
        job.recover(&job.queue).await;
        job.recover(&job.queue).await;
        job.recover(&job.queue).await;

        assert_eq!(Job::count_live(EXPIRY_JOB_KIND, &db).await.unwrap(), 1);
    }

    /// `lead_days = 0` is off, and it is off by being absent rather than by
    /// being checked later: no settings, so no handler and no row at all.
    #[test]
    fn a_zero_lead_configures_no_digest() {
        assert!(ExpirySettings::from_config(&settings(0)).is_none());
        assert!(ExpirySettings::from_config(&settings(1)).is_some());
    }

    /// A zero interval would make the runner re-run this immediately and for
    /// ever, sending a message every pass.
    #[test]
    fn the_interval_is_floored_at_a_day() {
        let config = ExpiryNotifyConfig {
            lead_days: 7,
            interval_days: 0,
            ..ExpiryNotifyConfig::default()
        };
        let settings = ExpirySettings::from_config(&config).unwrap();
        assert_eq!(settings.interval, Duration::from_secs(24 * 60 * 60));
    }
}
