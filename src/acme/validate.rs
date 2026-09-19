//! Challenge validation as queued work.
//!
//! `POST /chall/{id}` claims a challenge and enqueues one of these rows; the job
//! runner performs the outbound check. Validation reaches out to an address the
//! *client* named — over DNS, HTTP or TLS, to a host that may simply not answer
//! — so running it inside the request held an admission permit for the length of
//! `challenge.timeout_ms` and coupled that budget to
//! `server.request_timeout_ms`. RFC 8555 §7.1.6 already has the state this
//! needs: a challenge "transitions to the `processing` state when the client
//! responds to the challenge", and §8.2 pairs that with a `Retry-After`.
//!
//! **One handler over every profile**, the [`SignerRevokeJob`] shape: a row names
//! its challenge, the challenge walks up to its order, and the order names the
//! profile whose validators and notifier decide it. The registry refuses a
//! second handler for one kind, so one per profile could not be registered
//! anyway.
//!
//! [`SignerRevokeJob`]: super::revoke::SignerRevokeJob

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use tracing::{error, warn};

use super::order::OrderService;
use crate::auditor::Auditor;
use crate::jobs::{JobHandler, JobOutcome, JobQueue, JobSpec};
use crate::profile::Profile;
use crate::sqlite::{
    account::Account,
    authz::{Authorization, Challenge},
    db::Database,
    job::Job,
    nonce::now_secs,
    order::Order,
    status::ChallengeStatus,
};

/// The `jobs.kind` one challenge validation is queued under.
pub const CHALLENGE_VALIDATE_KIND: &str = "challenge_validate";

/// The row asking a worker to validate the challenge `claim_challenge` just
/// claimed.
///
/// Keyed on the challenge, so the claim and the job identity are the same fact
/// twice: the partial unique index refuses a second live row, exactly as the
/// `pending → processing` CAS refuses a second claim.
///
/// The payload carries the challenge id and the address that triggered it —
/// the latter only so `challenge_failed` can name the client, the way
/// `run_validation` names it today. Everything else is read back when the job
/// runs, since a snapshot goes stale across a retry.
///
/// `deadline` is the authorization's own `expires`: past it the authorization
/// is refused on read, so a validation settled afterwards could never carry the
/// order anywhere. That is the rule `RelayJob` already applies with the order's.
#[must_use]
pub fn challenge_validate_spec(
    challenge_id: &str,
    client_ip: Option<IpAddr>,
    authz_expires: i64,
) -> JobSpec {
    JobSpec::now(CHALLENGE_VALIDATE_KIND, challenge_id)
        .with_payload(serde_json::json!({
            "challenge_id": challenge_id,
            "client_ip": client_ip.map(|ip| acme_proxy_core::client::canonical(ip).to_string()),
        }))
        .with_deadline(Some(authz_expires))
}

/// Performs a claimed challenge validation and records its answer.
pub struct ChallengeValidateJob {
    database: Arc<Database>,
    audit: Arc<Auditor>,
    profiles: Vec<(String, Arc<Profile>)>,
}

/// Everything one row needs, read back from the database when it runs.
struct Subject {
    challenge: Challenge,
    authz: Authorization,
    order: Order,
    account: Account,
    profile: Arc<Profile>,
}

impl ChallengeValidateJob {
    /// `profiles` is this generation's profile per name.
    #[must_use]
    pub fn new(
        database: Arc<Database>,
        audit: Arc<Auditor>,
        profiles: Vec<(String, Arc<Profile>)>,
    ) -> Self {
        Self {
            database,
            audit,
            profiles,
        }
    }

    /// The profile this process mounts under `name`, if any.
    fn profile(&self, name: &str) -> Option<&Arc<Profile>> {
        self.profiles
            .iter()
            .find(|(mounted, _)| mounted == name)
            .map(|(_, profile)| profile)
    }

    /// Walks a row back to everything deciding it needs.
    ///
    /// `Err` is the outcome to answer with: `Failed` where the subject is gone
    /// for good, `Retry` where this process simply cannot see it yet.
    async fn load(&self, challenge_id: &str) -> Result<Subject, JobOutcome> {
        let challenge = match Challenge::find_by_id(challenge_id, &self.database).await {
            Ok(Some(challenge)) => challenge,
            Ok(None) => {
                return Err(JobOutcome::Failed(
                    "the challenge no longer exists".to_string(),
                ));
            }
            Err(error) => {
                return Err(JobOutcome::Retry(format!(
                    "reading the challenge failed: {error}"
                )));
            }
        };

        let authz = match Authorization::find_by_id(
            challenge.authz_id.to_string().as_str(),
            &self.database,
        )
        .await
        {
            Ok(Some(authz)) => authz,
            Ok(None) => {
                return Err(JobOutcome::Failed(
                    "the authorization no longer exists".to_string(),
                ));
            }
            Err(error) => {
                return Err(JobOutcome::Retry(format!(
                    "reading the authorization failed: {error}"
                )));
            }
        };

        let order =
            match Order::find_by_id(authz.order_id.to_string().as_str(), &self.database).await {
                Ok(Some(order)) => order,
                Ok(None) => {
                    return Err(JobOutcome::Failed("the order no longer exists".to_string()));
                }
                Err(error) => {
                    return Err(JobOutcome::Retry(format!(
                        "reading the order failed: {error}"
                    )));
                }
            };

        // Before the account, because an unmounted profile is the one answer
        // that is about *this process* rather than about the row.
        let Some(profile) = self.profile(&order.profile) else {
            return Err(JobOutcome::Retry(format!(
                "profile `{}` is not mounted by this process",
                order.profile
            )));
        };

        let account = match Account::find_by_id(
            &order.profile,
            order.account_id.to_string().as_str(),
            &self.database,
        )
        .await
        {
            Ok(Some(account)) => account,
            Ok(None) => {
                return Err(JobOutcome::Failed(
                    "the account no longer exists".to_string(),
                ));
            }
            Err(error) => {
                return Err(JobOutcome::Retry(format!(
                    "reading the account failed: {error}"
                )));
            }
        };

        Ok(Subject {
            challenge,
            authz,
            order,
            account,
            profile: profile.clone(),
        })
    }
}

#[async_trait::async_trait]
impl JobHandler for ChallengeValidateJob {
    fn kind(&self) -> &'static str {
        CHALLENGE_VALIDATE_KIND
    }

    /// One attempt at the outbound check.
    ///
    /// **A validation that ran is terminal, whichever way it went.** A refused
    /// challenge is the challenge's answer — recorded by `run_validation` in one
    /// transaction with its authorization and order, exactly as it was when this
    /// ran inside the request — so the job is `Done`. [`JobOutcome::Retry`] is
    /// reserved for the attempt never having happened: a database that would not
    /// answer, or a profile this process does not mount. That keeps
    /// `challenge_failed` meaning what it has always meant, and keeps a client's
    /// order reaching `invalid` as promptly as it used to.
    async fn run(&self, job: &Job) -> JobOutcome {
        let Some(challenge_id) = job.payload["challenge_id"].as_str() else {
            return JobOutcome::Failed("the payload names no challenge".to_string());
        };
        let client_ip = job.payload["client_ip"]
            .as_str()
            .and_then(|ip| ip.parse::<IpAddr>().ok());

        let Subject {
            mut challenge,
            mut authz,
            mut order,
            account,
            profile,
        } = match self.load(challenge_id).await {
            Ok(subject) => subject,
            Err(outcome) => return outcome,
        };

        // Settled already: the row was redelivered after a lease was lost, and
        // the previous attempt's verdict stands. §7.5.1's "client requests for
        // retries do not cause a state change", applied to the runner.
        if challenge.status != ChallengeStatus::Processing {
            return JobOutcome::Done;
        }

        let orders = OrderService {
            database: &self.database,
            audit: &self.audit,
            profile: &profile,
        };
        match orders
            .run_validation(&account, &mut challenge, &mut authz, &mut order, client_ip)
            .await
        {
            Ok(()) => JobOutcome::Done,
            // `run_validation` has already logged which half failed; the reason
            // here is what an operator reads in `jobs show`.
            Err(_) => JobOutcome::Retry(
                "the validation answer could not be computed or stored".to_string(),
            ),
        }
    }

    /// One attempt may take a whole `challenge.timeout_ms`.
    ///
    /// Which profile's is not knowable here — the row names a challenge, and
    /// walking it up to its order is a database read this synchronous hook
    /// cannot make — so the budget is the widest any mounted profile allows.
    /// Erring long costs only a longer wait before another runner may reclaim a
    /// stranded row; erring short would let two runners probe one client's host
    /// at once, which is the thing the claim exists to prevent.
    fn lease(&self, _job: &Job) -> Option<Duration> {
        self.profiles
            .iter()
            .map(|(_, profile)| profile.challenges.timeout())
            .max()
            .map(|timeout| timeout + LEASE_HEADROOM)
    }

    /// The attempts ran out, or the authorization expired under it.
    ///
    /// A challenge left `processing` would be polled by its client until the
    /// authorization expired, saying nothing. Record the failure instead, so the
    /// order goes `invalid` and the client stops — `RelayJob::abandon`'s rule,
    /// which marks its order `invalid` for the same reason.
    async fn abandon(&self, job: &Job, reason: &str) {
        let Some(challenge_id) = job.payload["challenge_id"].as_str() else {
            return;
        };
        warn!(
            event = "challenge_validation_abandoned",
            outcome = "failure",
            challenge_id = %challenge_id,
            attempts = job.attempts,
            reason = %reason,
            "a queued challenge validation was given up; its order is marked invalid"
        );

        let Ok(Subject {
            mut challenge,
            mut authz,
            mut order,
            profile,
            ..
        }) = self.load(challenge_id).await
        else {
            return;
        };
        if challenge.status != ChallengeStatus::Processing {
            return;
        }

        let orders = OrderService {
            database: &self.database,
            audit: &self.audit,
            profile: &profile,
        };
        if orders
            .abandon_validation(&mut challenge, &mut authz, &mut order, reason)
            .await
            .is_err()
        {
            error!(
                event = "challenge_validation_abandon_failed",
                outcome = "failure",
                challenge_id = %challenge_id,
                "the challenge could not be marked invalid and will stay `processing` \
                 until its authorization expires"
            );
        }
    }

    /// Re-queues a claim a previous process took and never settled.
    ///
    /// The window is small but real: `post_challenge` claims the challenge and
    /// then enqueues, so a crash between the two leaves a row `processing` with
    /// no job. Without this it would stay that way until its authorization
    /// expired — the trade `claim_for_validation` documents, and the one this
    /// closes now that something outlives the request.
    ///
    /// Safely repeatable: the identity index refuses a duplicate, so a
    /// challenge whose job is still live is simply not re-queued.
    async fn recover(&self, queue: &JobQueue) {
        let stranded = match Challenge::find_processing(now_secs(), &self.database).await {
            Ok(rows) => rows,
            Err(error) => {
                error!(
                    event = "challenge_validation_recovery_failed",
                    outcome = "failure",
                    error = %error
                );
                return;
            }
        };
        for (challenge_id, authz_expires) in stranded {
            queue
                .enqueue_or_log(challenge_validate_spec(
                    challenge_id.to_string().as_str(),
                    None,
                    authz_expires,
                ))
                .await;
        }
    }
}

/// How much longer than one attempt's own budget a lease is held.
///
/// The runner already adds its own slack on top; this covers the database reads
/// around the check, which the validator's timeout does not.
const LEASE_HEADROOM: Duration = Duration::from_secs(30);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acme::order::tests::{account, profile};
    use crate::challenge::{
        ChallengeError, ChallengeRegistry, ChallengeValidator, ValidationContext,
    };
    use crate::sqlite::status::{AuthzStatus, OrderStatus};
    use acme_proxy_core::identifier::Identifier;

    /// A validator refusing every attempt, so the failure arm is reachable
    /// without a network.
    struct Refusing;

    #[async_trait::async_trait]
    impl ChallengeValidator for Refusing {
        fn typ(&self) -> &'static str {
            "http-01"
        }
        async fn validate(&self, _ctx: &ValidationContext<'_>) -> Result<(), ChallengeError> {
            Err(ChallengeError::IncorrectResponse("wrong body".into()))
        }
    }

    /// One order, one authorization, one `http-01` challenge, all `pending`.
    async fn subject(
        database: &Arc<Database>,
        account: &Account,
    ) -> (Order, Authorization, Challenge) {
        let order = Order::create(
            "default",
            account.id,
            crate::testutil::dns_identifiers(&["a.example.com"]),
            now_secs() + 3600,
            None,
            None,
            database,
        )
        .await
        .unwrap();
        let authz = Authorization::create(
            order.id,
            Identifier::dns("a.example.com"),
            order.expires,
            database,
        )
        .await
        .unwrap();
        let challenge = Challenge::create(authz.id, "http-01", database)
            .await
            .unwrap();
        (order, authz, challenge)
    }

    /// The handler over one `default` profile with `challenges`.
    fn handler(database: &Arc<Database>, challenges: ChallengeRegistry) -> ChallengeValidateJob {
        let profile = Arc::new(profile(database, challenges));
        ChallengeValidateJob::new(
            database.clone(),
            Arc::new(Auditor::offline(database.clone())),
            vec![(profile.name.clone(), profile)],
        )
    }

    fn row(challenge_id: &str) -> Job {
        let spec = challenge_validate_spec(challenge_id, None, now_secs() + 3600);
        Job {
            dedup_key: spec.key.clone(),
            payload: spec.payload.clone(),
            ..crate::testutil::job_fixture()
        }
    }

    #[tokio::test]
    async fn a_claimed_challenge_is_validated_and_its_order_promoted() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let account = account(&database).await;
        let (order, authz, mut challenge) = subject(&database, &account).await;
        assert!(challenge.claim_for_validation(&database).await.unwrap());

        // `ChallengeRegistry::default()` bypasses, so this passes with no network.
        let job = handler(&database, ChallengeRegistry::default());
        assert!(matches!(
            job.run(&row(challenge.id.to_string().as_str())).await,
            JobOutcome::Done
        ));

        let reloaded = Challenge::find_by_id(challenge.id.to_string().as_str(), &database)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reloaded.status, ChallengeStatus::Valid);
        assert_eq!(
            Authorization::find_by_id(authz.id.to_string().as_str(), &database)
                .await
                .unwrap()
                .unwrap()
                .status,
            AuthzStatus::Valid
        );
        assert_eq!(
            Order::find_by_id(order.id.to_string().as_str(), &database)
                .await
                .unwrap()
                .unwrap()
                .status,
            OrderStatus::Ready
        );
    }

    /// A refused validation is the challenge's *answer*, so the job is `Done`
    /// and the order is `invalid`. This is the decision that keeps the move a
    /// move rather than a change of semantics.
    #[tokio::test]
    async fn a_refused_validation_is_recorded_and_the_job_is_done() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let account = account(&database).await;
        let (order, _, mut challenge) = subject(&database, &account).await;
        assert!(challenge.claim_for_validation(&database).await.unwrap());

        let registry = ChallengeRegistry::new(
            vec![Arc::new(Refusing)],
            vec!["http-01".to_string()],
            false,
            Duration::from_secs(5),
        );
        let job = handler(&database, registry);
        assert!(matches!(
            job.run(&row(challenge.id.to_string().as_str())).await,
            JobOutcome::Done
        ));

        assert_eq!(
            Order::find_by_id(order.id.to_string().as_str(), &database)
                .await
                .unwrap()
                .unwrap()
                .status,
            OrderStatus::Invalid
        );
    }

    #[tokio::test]
    async fn an_unmounted_profile_is_retried() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let account = account(&database).await;
        let (_, _, mut challenge) = subject(&database, &account).await;
        assert!(challenge.claim_for_validation(&database).await.unwrap());

        // A handler mounting nothing: the row's profile is somebody else's.
        let job = ChallengeValidateJob::new(
            database.clone(),
            Arc::new(Auditor::offline(database.clone())),
            vec![],
        );
        let JobOutcome::Retry(reason) = job.run(&row(challenge.id.to_string().as_str())).await
        else {
            panic!("an unmounted profile must be retried, never failed");
        };
        assert!(reason.contains("not mounted"), "{reason}");
    }

    #[tokio::test]
    async fn a_vanished_challenge_is_failed() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let job = handler(&database, ChallengeRegistry::default());
        let missing = uuid::Uuid::now_v7().to_string();
        assert!(matches!(
            job.run(&row(&missing)).await,
            JobOutcome::Failed(_)
        ));
    }

    #[tokio::test]
    async fn a_payload_naming_no_challenge_is_failed() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let job = handler(&database, ChallengeRegistry::default());
        let row = Job {
            payload: serde_json::json!({}),
            ..crate::testutil::job_fixture()
        };
        assert!(matches!(job.run(&row).await, JobOutcome::Failed(_)));
    }

    /// A redelivery after a lost lease must not re-probe the client's host: the
    /// previous attempt's verdict stands.
    #[tokio::test]
    async fn a_settled_challenge_is_done_without_revalidating() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let account = account(&database).await;
        let (_, _, mut challenge) = subject(&database, &account).await;
        assert!(challenge.claim_for_validation(&database).await.unwrap());

        let job = handler(&database, ChallengeRegistry::default());
        assert!(matches!(
            job.run(&row(challenge.id.to_string().as_str())).await,
            JobOutcome::Done
        ));

        // Second delivery: a refusing validator would mark it invalid if it ran.
        let registry = ChallengeRegistry::new(
            vec![Arc::new(Refusing)],
            vec!["http-01".to_string()],
            false,
            Duration::from_secs(5),
        );
        let job = handler(&database, registry);
        assert!(matches!(
            job.run(&row(challenge.id.to_string().as_str())).await,
            JobOutcome::Done
        ));
        assert_eq!(
            Challenge::find_by_id(challenge.id.to_string().as_str(), &database)
                .await
                .unwrap()
                .unwrap()
                .status,
            ChallengeStatus::Valid
        );
    }

    #[tokio::test]
    async fn abandoning_marks_the_challenge_and_its_order_invalid() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let account = account(&database).await;
        let (order, authz, mut challenge) = subject(&database, &account).await;
        assert!(challenge.claim_for_validation(&database).await.unwrap());

        let job = handler(&database, ChallengeRegistry::default());
        job.abandon(
            &row(challenge.id.to_string().as_str()),
            "the attempts ran out",
        )
        .await;

        let reloaded = Challenge::find_by_id(challenge.id.to_string().as_str(), &database)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reloaded.status, ChallengeStatus::Invalid);
        assert_eq!(
            Authorization::find_by_id(authz.id.to_string().as_str(), &database)
                .await
                .unwrap()
                .unwrap()
                .status,
            AuthzStatus::Invalid
        );
        assert_eq!(
            Order::find_by_id(order.id.to_string().as_str(), &database)
                .await
                .unwrap()
                .unwrap()
                .status,
            OrderStatus::Invalid
        );
    }

    /// The crash-between-claim-and-enqueue window: the claim is on the row and
    /// nothing is queued for it.
    #[tokio::test]
    async fn recover_requeues_a_stranded_claim_exactly_once() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let account = account(&database).await;
        let (_, _, mut challenge) = subject(&database, &account).await;
        assert!(challenge.claim_for_validation(&database).await.unwrap());

        let queue = crate::testutil::idle_job_queue(database.clone());
        let job = handler(&database, ChallengeRegistry::default());

        job.recover(&queue).await;
        assert_eq!(
            crate::sqlite::job::Job::count_live(CHALLENGE_VALIDATE_KIND, &database)
                .await
                .unwrap(),
            1
        );

        // Safely repeatable: the identity index refuses the duplicate.
        job.recover(&queue).await;
        assert_eq!(
            crate::sqlite::job::Job::count_live(CHALLENGE_VALIDATE_KIND, &database)
                .await
                .unwrap(),
            1
        );
    }

    /// A `pending` challenge was never claimed, so there is nothing to recover.
    #[tokio::test]
    async fn recover_ignores_a_challenge_nobody_claimed() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let account = account(&database).await;
        let (_, _, _challenge) = subject(&database, &account).await;

        let queue = crate::testutil::idle_job_queue(database.clone());
        handler(&database, ChallengeRegistry::default())
            .recover(&queue)
            .await;
        assert_eq!(
            crate::sqlite::job::Job::count_live(CHALLENGE_VALIDATE_KIND, &database)
                .await
                .unwrap(),
            0
        );
    }
}
