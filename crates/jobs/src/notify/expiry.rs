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
//!
//! ## Addressed to the account
//!
//! With `notify.expiry.contact` set, the same pass also sends each account its
//! own cut of the digest — one message per account, listing only the
//! certificates it holds, addressed to the `mailto:` addresses in its
//! `contact` ([`NotifyEvent::AccountCertificatesExpiring`]). Four rules shape
//! it, and each is a decision rather than an accident:
//!
//! - **Opt-in.** A `contact` is text a client typed and nobody verified, so
//!   mailing it is the operator's call, and `contact_domains` is how an
//!   operator who makes it keeps the mail inside their own domains. Empty is
//!   any domain.
//! - **Email only, and never the configured `to`.** The dispatcher queues it
//!   on the `email` slot alone, and an account with no address left after the
//!   allowlist is skipped rather than mailed to the operator — see
//!   `notify`'s module docs.
//! - **Silence when everything is renewed.** An account whose every listed
//!   certificate is already superseded gets nothing. The operator digest keeps
//!   supersession as an annotation for the reason above; an account holder
//!   whose automation works would otherwise get a mail every interval, which
//!   is the channel-nobody-opens failure this module exists to avoid. The
//!   rule errs towards sending: a truncated list is sent whatever its listed
//!   entries say, since the ones it did not list may not be renewed, and the
//!   annotation itself is conservative.
//! - **A deactivated account is not written to.** It can renew nothing.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tracing::{debug, error, info};

use super::{
    AccountCertificatesExpiringData, CertificatesExpiringData, ExpiringCertificate, Notifiers,
    NotifyEvent,
};
use crate::jobs::{JobHandler, JobOutcome, JobQueue, JobSpec};
use acme_proxy_store::account::Account;
use acme_proxy_store::db::Database;
use acme_proxy_store::expiring::{ExpiringEntry, ExpiringQuery};
use acme_proxy_store::job::Job;
use acme_proxy_store::nonce::now_secs;
use acme_proxy_store::order::Order;
use acme_proxy_store::order::UNPARSABLE_NOT_AFTER;

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
#[derive(Debug, Clone)]
pub struct ExpirySettings {
    lead: Duration,
    lead_days: u64,
    interval: Duration,
    max_entries: i64,
    /// `Some` when `notify.expiry.contact` asks for the per-account digest.
    contact: Option<ContactPolicy>,
}

/// Which of an account's contacts the per-account digest may mail.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ContactPolicy {
    /// `notify.expiry.contact_domains`, trimmed and lowercased. Empty is any
    /// domain.
    domains: Vec<String>,
}

impl ContactPolicy {
    /// The bare addresses in `contact` this policy admits, each once.
    ///
    /// `newAccount` and the account update have already refused anything but a
    /// single-address `mailto:` with a domain (`rules::contact_shape_error`),
    /// so this only strips the scheme and reads the domain. An entry that
    /// somehow is not of that shape is dropped, never guessed at.
    fn recipients(&self, contact: &[String]) -> Vec<String> {
        let mut seen = HashSet::new();
        contact
            .iter()
            .filter_map(|uri| uri.strip_prefix("mailto:"))
            .filter(|address| {
                address
                    .rsplit_once('@')
                    .is_some_and(|(_, domain)| self.admits(domain))
            })
            .filter(|address| seen.insert(address.to_ascii_lowercase()))
            .map(str::to_string)
            .collect()
    }

    /// Whether `domain` is one of the allowed domains or beneath one. A label
    /// boundary, so `example.com` admits `mail.example.com` and not
    /// `badexample.com`.
    fn admits(&self, domain: &str) -> bool {
        if self.domains.is_empty() {
            return true;
        }
        let domain = domain.to_ascii_lowercase();
        self.domains.iter().any(|allowed| {
            domain == *allowed
                || domain
                    .strip_suffix(allowed.as_str())
                    .is_some_and(|head| head.ends_with('.'))
        })
    }
}

impl ExpirySettings {
    /// The settings for a profile, or `None` when `lead_days` is `0` — which is
    /// off, and is why a profile with the default configuration never gets a
    /// row.
    #[must_use]
    pub fn from_config(config: &acme_proxy_core::config::ExpiryNotifyConfig) -> Option<Self> {
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
            contact: config.contact.then(|| ContactPolicy {
                domains: config
                    .contact_domains
                    .iter()
                    .map(|domain| domain.trim().to_ascii_lowercase())
                    .collect(),
            }),
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
        resolved: &[acme_proxy_core::config::ProfileConfig],
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
        settings: &ExpirySettings,
    ) -> Result<Option<CertificatesExpiringData>, sqlx::Error> {
        let now = now_secs();
        // The window, the annotation and the ordering all come from
        // `admin` — the digest is one of three consumers of that listing
        // (the panel and `order list --expiring-in` are the others), and it
        // asks for the same thing they do so the three cannot come to disagree
        // about what "expiring" or "already replaced" means. `include_superseded`
        // is always `true` here: supersession is an annotation and never a
        // filter, for the reason in this module's docs.
        let query = ExpiringQuery {
            profile: Some(profile.to_string()),
            account: None,
            before: acme_proxy_store::expiring::horizon_from(now, settings.lead.as_secs()),
            include_superseded: true,
            limit: settings.max_entries,
            offset: 0,
        };
        let (entries, total, _hidden) =
            acme_proxy_store::expiring::list_expiring(&query, self.database.clone()).await?;
        if entries.is_empty() {
            return Ok(None);
        }

        Ok(Some(CertificatesExpiringData {
            profile: profile.to_string(),
            generated_at: now,
            lead_days: settings.lead_days,
            total,
            certificates: entries.into_iter().map(certificate).collect(),
        }))
    }

    /// Builds one digest per account holding something in the window, for the
    /// accounts the rules in the module docs say to write to.
    ///
    /// The same window, ordering and annotation as [`Self::collect`], through
    /// the same listing scoped to one account, so the account's message and the
    /// operator's cannot come to disagree about a certificate.
    async fn collect_for_accounts(
        &self,
        profile: &str,
        settings: &ExpirySettings,
        policy: &ContactPolicy,
    ) -> Result<Vec<AccountCertificatesExpiringData>, sqlx::Error> {
        let now = now_secs();
        let before = acme_proxy_store::expiring::horizon_from(now, settings.lead.as_secs());
        let mut digests = Vec::new();

        for account_id in Order::expiring_accounts(profile, before, &self.database).await? {
            let account =
                Account::find_by_id(profile, &account_id.to_string(), &self.database).await?;
            let Some(account) = account.filter(|account| !account.is_deactivated()) else {
                debug!(event = "notify_expiry_account_digest_skipped", outcome = "success", profile = %profile, account_id = %account_id, reason = "deactivated");
                continue;
            };
            let recipients = policy.recipients(&account.contact);
            if recipients.is_empty() {
                debug!(event = "notify_expiry_account_digest_skipped", outcome = "success", profile = %profile, account_id = %account_id, reason = "no_contact");
                continue;
            }

            let query = ExpiringQuery {
                profile: Some(profile.to_string()),
                account: Some(account_id),
                before,
                include_superseded: true,
                limit: settings.max_entries,
                offset: 0,
            };
            let (entries, total, _hidden) =
                acme_proxy_store::expiring::list_expiring(&query, self.database.clone()).await?;
            if !worth_telling(&entries, total) {
                debug!(event = "notify_expiry_account_digest_skipped", outcome = "success", profile = %profile, account_id = %account_id, reason = "renewed");
                continue;
            }

            digests.push(AccountCertificatesExpiringData {
                profile: profile.to_string(),
                account_id: account_id.to_string(),
                recipients,
                generated_at: now,
                lead_days: settings.lead_days,
                total,
                certificates: entries.into_iter().map(certificate).collect(),
            });
        }

        Ok(digests)
    }

    /// The per-account half of a pass: one message per account the rules in
    /// the module docs say to write to. Logged and swallowed on failure, like
    /// the operator digest beside it — the pass reschedules regardless.
    async fn send_to_accounts(
        &self,
        profile: &str,
        settings: &ExpirySettings,
        policy: &ContactPolicy,
    ) {
        let digests = match self.collect_for_accounts(profile, settings, policy).await {
            Ok(digests) => digests,
            Err(error) => {
                error!(event = "notify_expiry_account_digest_failed", outcome = "failure", profile = %profile, error = %error);
                return;
            }
        };
        let Some(dispatcher) = self.notifiers.get(profile) else {
            return;
        };
        for data in digests {
            let account_id = data.account_id.clone();
            let listed = data.certificates.len();
            let total = data.total;
            dispatcher
                .dispatch(NotifyEvent::AccountCertificatesExpiring(data))
                .await;
            info!(
                event = "notify_expiry_account_digest_sent",
                outcome = "success",
                profile = %profile,
                account_id = %account_id,
                certificates_listed = listed,
                certificates_total = total
            );
        }
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

/// One listing entry as the digest carries it.
fn certificate(entry: ExpiringEntry) -> ExpiringCertificate {
    ExpiringCertificate {
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
    }
}

/// Whether an account's listing is worth a message: something on it is not
/// yet replaced, or the list was truncated and the rows it left out might not
/// be. See the module docs for why this errs towards sending.
fn worth_telling(entries: &[ExpiringEntry], total: i64) -> bool {
    let listed = i64::try_from(entries.len()).unwrap_or(i64::MAX);
    !entries.is_empty()
        && (total > listed || entries.iter().any(|entry| entry.superseded_by.is_none()))
}

/// The leaf's notAfter out of a stored PEM chain, or [`UNPARSABLE_NOT_AFTER`].
fn leaf_not_after(chain: &str) -> i64 {
    acme_proxy_core::cert::leaf_der_from_chain(chain)
        .ok()
        .and_then(|der| acme_proxy_core::cert::cert_validity(&der).ok())
        .map_or(UNPARSABLE_NOT_AFTER, |(_, not_after)| not_after)
}

#[async_trait]
impl JobHandler for ExpiryDigestJob {
    fn kind(&self) -> &'static str {
        EXPIRY_JOB_KIND
    }

    async fn run(&self, job: &Job) -> JobOutcome {
        let profile = job.dedup_key.clone();
        let Some(settings) = self.profiles.get(&profile).cloned() else {
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

        match self.collect(&profile, &settings).await {
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

        if let Some(policy) = &settings.contact {
            self.send_to_accounts(&profile, &settings, policy).await;
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
    use crate::notify::{BackendSlot, NotifyDispatcher};
    use acme_proxy_core::config::ExpiryNotifyConfig;
    use acme_proxy_core::config::JobsConfig;
    use acme_proxy_store::testutil::account_id;
    use serde_json::json;
    use std::collections::HashMap;

    const DAY: i64 = 24 * 60 * 60;

    /// A claimed row for `profile`, as the runner would hand one to `run`.
    fn row(profile: &str) -> Job {
        Job {
            id: acme_proxy_store::id::mint(),
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
        harness_with(&settings(lead_days), Vec::new()).await
    }

    /// [`harness`] over a whole `[notify.expiry]` and the profile's backends.
    async fn harness_with(
        config: &ExpiryNotifyConfig,
        slots: Vec<BackendSlot>,
    ) -> (ExpiryDigestJob, Arc<Database>) {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let queue = JobQueue::new(database.clone(), &JobsConfig::default());
        let dispatchers: super::super::DispatcherMap = HashMap::from([(
            "default".to_string(),
            Arc::new(NotifyDispatcher::new("default", slots, queue.clone())),
        )]);
        let (_tx, notifiers) = super::super::notifiers_channel(dispatchers);
        let job = ExpiryDigestJob {
            profiles: HashMap::from([(
                "default".to_string(),
                ExpirySettings::from_config(config).unwrap(),
            )]),
            notifiers,
            database: database.clone(),
            queue,
        };
        (job, database)
    }

    /// An issued order on the `default` profile. The real signing lives in
    /// [`acme_proxy_store::testutil::issued_order`], hoisted there when `admin::ops`
    /// gained the supersession annotation and needed the same row.
    async fn issued(
        db: &Database,
        account: uuid::Uuid,
        names: &[&str],
        not_after_days: i64,
    ) -> Order {
        acme_proxy_store::testutil::issued_order(db, "default", account, names, not_after_days)
            .await
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
            .collect("default", &job.profiles["default"])
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
            job.collect("default", &job.profiles["default"])
                .await
                .unwrap()
                .is_none()
        );
    }

    /// `[notify.expiry]` with the per-account digest on, over `domains`.
    fn contact_settings(lead_days: u64, domains: &[&str]) -> ExpiryNotifyConfig {
        ExpiryNotifyConfig {
            lead_days,
            contact: true,
            contact_domains: domains.iter().map(|d| (*d).to_string()).collect(),
            ..ExpiryNotifyConfig::default()
        }
    }

    /// An account on `default` with its own key and `contact`.
    async fn account_with(db: &Database, key: u8, contact: &[&str]) -> Account {
        Account::find_or_create(
            "default",
            &[key, key, key],
            contact.iter().map(|c| (*c).to_string()).collect(),
            &acme_proxy_core::audit::ClientContext::default(),
            db,
        )
        .await
        .unwrap()
        .0
    }

    /// The handler's own contact policy, which `from_config` built.
    fn policy(job: &ExpiryDigestJob) -> ContactPolicy {
        job.profiles["default"]
            .contact
            .clone()
            .expect("contact is on")
    }

    /// One message per account, each naming that account's certificates and
    /// nobody else's, and each addressed to that account's contacts.
    #[tokio::test]
    async fn each_account_hears_about_its_own_certificates_at_its_own_contacts() {
        let (job, db) = harness_with(&contact_settings(14, &[]), Vec::new()).await;
        let alice = account_with(&db, 1, &["mailto:alice@example.com"]).await;
        let bob = account_with(&db, 2, &["mailto:bob@example.org"]).await;
        issued(&db, alice.id, &["alice.example.com"], 3).await;
        issued(&db, bob.id, &["bob.example.org"], 5).await;
        issued(&db, bob.id, &["fine.example.org"], 60).await;

        let mut digests = job
            .collect_for_accounts("default", &job.profiles["default"], &policy(&job))
            .await
            .unwrap();
        digests.sort_by(|a, b| a.recipients.cmp(&b.recipients));

        assert_eq!(digests.len(), 2);
        assert_eq!(digests[0].account_id, alice.id.to_string());
        assert_eq!(digests[0].recipients, vec!["alice@example.com".to_string()]);
        assert_eq!(digests[0].total, 1);
        assert_eq!(
            digests[0].certificates[0].identifiers,
            vec!["alice.example.com".to_string()]
        );
        assert_eq!(digests[1].account_id, bob.id.to_string());
        assert_eq!(digests[1].recipients, vec!["bob@example.org".to_string()]);
        assert_eq!(digests[1].total, 1, "the 60-day one is outside the window");
        assert_eq!(
            digests[1].certificates[0].identifiers,
            vec!["bob.example.org".to_string()]
        );
    }

    /// An allowed domain admits itself and its subdomains on a label boundary,
    /// in any case, and nothing else; an empty list admits every domain. A
    /// contact that is not a `mailto:` is never guessed at, and an address
    /// listed twice is mailed once.
    #[test]
    fn the_allowlist_admits_a_domain_and_what_is_beneath_it() {
        let contact: Vec<String> = [
            "mailto:a@example.com",
            "mailto:b@Mail.EXAMPLE.com",
            "mailto:c@badexample.com",
            "mailto:d@other.test",
            "mailto:A@example.com",
            "tel:+15551234",
        ]
        .iter()
        .map(|c| (*c).to_string())
        .collect();

        let restricted = ExpirySettings::from_config(&contact_settings(14, &[" Example.COM "]))
            .unwrap()
            .contact
            .unwrap();
        assert_eq!(
            restricted.recipients(&contact),
            vec!["a@example.com", "b@Mail.EXAMPLE.com"]
        );

        let open = ExpirySettings::from_config(&contact_settings(14, &[]))
            .unwrap()
            .contact
            .unwrap();
        assert_eq!(
            open.recipients(&contact),
            vec![
                "a@example.com",
                "b@Mail.EXAMPLE.com",
                "c@badexample.com",
                "d@other.test"
            ]
        );

        assert!(
            ExpirySettings::from_config(&settings(14))
                .unwrap()
                .contact
                .is_none(),
            "off unless asked for"
        );
    }

    /// Nobody to write to, or nobody worth writing to: an account with no
    /// admitted address, with no contact at all, or deactivated, gets nothing
    /// — and nothing falls back to the operator.
    #[tokio::test]
    async fn an_account_with_no_admitted_contact_or_deactivated_hears_nothing() {
        let (job, db) = harness_with(&contact_settings(14, &["example.com"]), Vec::new()).await;
        let outside = account_with(&db, 1, &["mailto:someone@other.test"]).await;
        let silent = account_with(&db, 2, &[]).await;
        let mut gone = account_with(&db, 3, &["mailto:gone@example.com"]).await;
        gone.deactivate(&db).await.unwrap();
        for account in [outside.id, silent.id, gone.id] {
            issued(&db, account, &["x.example.com"], 3).await;
        }

        let digests = job
            .collect_for_accounts("default", &job.profiles["default"], &policy(&job))
            .await
            .unwrap();
        assert!(digests.is_empty(), "{digests:?}");
    }

    /// An account whose every expiring certificate is already renewed hears
    /// nothing; one more that is not renewed and the account hears about both,
    /// the renewed one annotated.
    #[tokio::test]
    async fn an_account_whose_certificates_are_all_renewed_hears_nothing() {
        let (job, db) = harness_with(&contact_settings(14, &[]), Vec::new()).await;
        let alice = account_with(&db, 1, &["mailto:alice@example.com"]).await;
        issued(&db, alice.id, &["www.example.com"], 3).await;
        // The renewal: the same names, much later.
        issued(&db, alice.id, &["www.example.com"], 80).await;

        let digests = job
            .collect_for_accounts("default", &job.profiles["default"], &policy(&job))
            .await
            .unwrap();
        assert!(digests.is_empty(), "{digests:?}");

        issued(&db, alice.id, &["api.example.com"], 5).await;
        let digests = job
            .collect_for_accounts("default", &job.profiles["default"], &policy(&job))
            .await
            .unwrap();
        assert_eq!(digests.len(), 1);
        assert_eq!(digests[0].total, 2);
        assert!(digests[0].certificates[0].superseded_by.is_some());
        assert!(digests[0].certificates[1].superseded_by.is_none());
    }

    /// A truncated list is sent even when every entry it shows is renewed: the
    /// ones it did not show may not be.
    #[tokio::test]
    async fn a_truncated_list_is_sent_whatever_its_listed_entries_say() {
        let config = ExpiryNotifyConfig {
            max_entries: 1,
            ..contact_settings(14, &[])
        };
        let (job, db) = harness_with(&config, Vec::new()).await;
        let alice = account_with(&db, 1, &["mailto:alice@example.com"]).await;
        issued(&db, alice.id, &["www.example.com"], 3).await;
        issued(&db, alice.id, &["www.example.com"], 80).await;
        issued(&db, alice.id, &["api.example.com"], 5).await;

        let digests = job
            .collect_for_accounts("default", &job.profiles["default"], &policy(&job))
            .await
            .unwrap();
        assert_eq!(digests.len(), 1);
        assert_eq!(digests[0].certificates.len(), 1);
        assert!(digests[0].certificates[0].superseded_by.is_some());
        assert_eq!(digests[0].total, 2);
    }

    /// A pass with the per-account digest on queues the operator's digest and
    /// one delivery per account; with it off, the operator's alone.
    #[tokio::test]
    async fn a_pass_queues_one_account_digest_per_account_only_when_asked() {
        for (contact, expected) in [(true, 3), (false, 1)] {
            let email = BackendSlot::new(
                "email",
                Arc::new(crate::notify::tests::RecordingNotifyBackend::default()),
                &acme_proxy_core::config::ALL_NOTIFY_EVENTS
                    .iter()
                    .map(|k| (*k).to_string())
                    .collect::<Vec<_>>(),
            )
            .delivering_to_contacts();
            let config = ExpiryNotifyConfig {
                contact,
                ..contact_settings(14, &[])
            };
            let (job, db) = harness_with(&config, vec![email]).await;
            for (key, name) in [(1, "a.example.com"), (2, "b.example.com")] {
                let account = account_with(&db, key, &["mailto:someone@example.com"]).await;
                issued(&db, account.id, &[name], 3).await;
            }

            assert!(matches!(
                job.run(&row("default")).await,
                JobOutcome::Reschedule(_)
            ));
            assert_eq!(
                Job::count_live(crate::notify::NOTIFY_JOB_KIND, &db)
                    .await
                    .unwrap(),
                expected,
                "contact = {contact}"
            );
        }
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
            .execute(db.raw_pool())
            .await
            .unwrap();
        sqlx::query("UPDATE orders SET certificate = 'not a pem' WHERE id = ?;")
            .bind(bad.id)
            .execute(db.raw_pool())
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
        db.close().await;
        assert!(matches!(
            job.run(&row("default")).await,
            JobOutcome::Reschedule(_)
        ));
    }

    /// The account half obeys the same law: a pass whose per-account read
    /// fails still reschedules.
    #[tokio::test]
    async fn a_failing_account_pass_reschedules_rather_than_retiring() {
        let (job, db) = harness_with(&contact_settings(14, &[]), Vec::new()).await;
        db.close().await;
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
