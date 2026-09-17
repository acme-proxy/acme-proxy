//! The order state machine: authorizations, challenges, finalization and
//! revocation, as operations on stored rows rather than on HTTP requests.

use std::net::IpAddr;
use std::sync::Arc;

use serde_json::Value;
use tracing::{error, info, warn};

use super::error::Error;
use super::policy::challenge_problem;
use crate::audit::Auditor;
use crate::challenge::ValidationContext;
use crate::error::Problem;
use crate::extractors::acme::jwk_thumbprint;
use crate::notify::{ChallengeFailedData, NotifyEvent};
use crate::server::Profile;
use crate::sqlite::{
    account::Account,
    authz::{Authorization, Challenge},
    db::Database,
    nonce::now_secs,
    order::Order,
    status::{AuthzStatus, ChallengeStatus, OrderStatus},
};

/// The order-side operations of one endpoint.
///
/// A borrowed bundle rather than an owned service: every caller already holds
/// these — the ACME handlers in `AppState`, the web admin in `AdminState`, a
/// background job in its own state — and building one is three references.
/// The profile is the endpoint's whole configuration (its signer, filter,
/// validators and notifier), which is what makes one operation mean the same
/// thing whichever front end reached it.
pub struct OrderService<'a> {
    pub database: &'a Arc<Database>,
    pub audit: &'a Auditor,
    pub profile: &'a Profile,
}

impl OrderService<'_> {
    /// Deactivates `authz` and re-derives its order's status (RFC 8555 §7.5.2).
    ///
    /// Already-`deactivated` is a no-op rather than an error: §7.5.2 describes the
    /// client sending the same static object to *each* authorization of an
    /// identifier, and a retry after a partial failure must not start reporting
    /// errors halfway through.
    pub async fn deactivate_authz(
        &self,
        authz: &mut Authorization,
        order: &mut Order,
    ) -> Result<(), Error> {
        let database = self.database;
        if authz.status == AuthzStatus::Deactivated {
            return Ok(());
        }

        // A certificate already exists for this order, so relinquishing the
        // authorization it was issued under would claim something untrue. §7.5.2 is
        // about giving up the *ability* to issue, not about undoing issuance —
        // that is what revocation (§7.6) is for.
        if order.status == OrderStatus::Valid {
            warn!(event = "authz_deactivate_refused_order_valid", outcome = "failure", authz_id = %authz.id, order_id = %order.id);
            return Err(Problem::malformed(
                "Cannot deactivate an authorization whose order has already been issued; revoke the certificate instead",
            )
            .into());
        }

        if authz.status != AuthzStatus::Pending && authz.status != AuthzStatus::Valid {
            warn!(event = "authz_deactivate_refused_terminal", outcome = "failure", authz_id = %authz.id, status = %authz.status);
            return Err(Problem::malformed(
                "Authorization is in a terminal state and cannot be deactivated",
            )
            .into());
        }

        // §7.5.2: "The server MUST NOT treat deactivated authorization objects as
        // sufficient for issuing certificates." For a `pending` order that falls
        // out of the readiness check on its own, but an order already promoted to
        // `ready` would still finalize — so demote it.
        //
        // Both in one transaction. Between them, an order sits `ready` with a
        // deactivated authorization under it: finalizable for a name the client has
        // just given up, which is exactly what §7.5.2 forbids.
        let demote = order.status == OrderStatus::Ready;
        let outcome = async {
            let mut tx = database.transaction().await?;
            Authorization::set_deactivated(authz.id, &mut *tx).await?;
            if demote {
                Order::set_pending(order.id, &mut *tx).await?;
            }
            tx.commit().await
        }
        .await;

        outcome.map_err(|error| {
            error!(event = "authz_deactivate_failed", outcome = "failure", authz_id = %authz.id, error = %error);
            Problem::server_internal("Authorization deactivation failed")
        })?;

        // Only once the transaction has committed: a rollback must not leave these
        // objects claiming a status the database never took.
        authz.status = AuthzStatus::Deactivated;
        if demote {
            order.status = OrderStatus::Pending;
        }

        info!(event = "authz_deactivated", outcome = "success", authz_id = %authz.id, order_id = %order.id);
        Ok(())
    }

    /// Decides whether a challenge trigger (RFC 8555 §7.5.1) starts a
    /// validation, and if so claims the challenge for it.
    ///
    /// `Ok(false)` is not a refusal: the challenge is already decided — here or
    /// by a sibling — or another trigger holds the claim, and the caller answers
    /// with the challenge as it stands. `Ok(true)` obliges the caller to follow
    /// with [`run_validation`](Self::run_validation).
    pub async fn claim_challenge(
        &self,
        challenge: &mut Challenge,
        authz: &Authorization,
    ) -> Result<bool, Error> {
        if authz.status != AuthzStatus::Valid && authz.expires <= now_secs() {
            warn!(event = "authz_expired", outcome = "failure", authz_id = %authz.id, expires = authz.expires);
            return Err(Problem::malformed("Authorization has expired").into());
        }

        // The client gave this authorization up (RFC 8555 §7.5.2). Validating a
        // challenge under it would walk it straight back to `valid` — which §7.5.2
        // forbids being sufficient for issuance — so refuse before doing any work.
        if authz.status == AuthzStatus::Deactivated {
            warn!(event = "authz_already_deactivated", outcome = "failure", authz_id = %authz.id);
            return Err(Problem::malformed("Authorization has been deactivated").into());
        }

        // Already answered, here or by a sibling: §7.5.1's "client requests for
        // retries do not cause a state change".
        let decided = challenge.status == ChallengeStatus::Valid
            || challenge.status == ChallengeStatus::Invalid
            || authz.status == AuthzStatus::Valid;

        // The claim, and the reason it is a claim rather than the status check
        // above: `challenges.validate` reaches out to an address the *client*
        // named, so two triggers that both read this row as `pending` become two
        // probes of that host from this server — bounded only by
        // `server.max_concurrent_requests`, on a default configuration with no
        // filter to refuse them. Deciding it in the `UPDATE` makes "one validation
        // per challenge" a property of the row instead of one of scheduling.
        //
        // The loser answers with the challenge as it now stands, which reports
        // `processing` — §8.2's answer for a challenge the server is still
        // working on.
        let claimed = !decided
            && challenge
                .claim_for_validation(self.database)
                .await
                .map_err(|error| {
                    error!(event = "challenge_claim_failed", outcome = "failure", challenge_id = %challenge.id, error = %error);
                    Problem::server_internal("Challenge could not be claimed for validation")
                })?;
        Ok(claimed)
    }

    /// Validates a challenge [`claim_challenge`](Self::claim_challenge) claimed,
    /// and records the answer.
    ///
    /// Either outcome is recorded — a failed validation is the challenge's
    /// answer, not an error of this call — so `Err` means only that the answer
    /// could not be computed or stored. On failure the operator hears about it
    /// through `challenge_failed`, after the commit.
    ///
    /// `client_ip` is the address the notification names: the client that
    /// triggered the validation, when there was one.
    pub async fn run_validation(
        &self,
        account: &Account,
        challenge: &mut Challenge,
        authz: &mut Authorization,
        order: &mut Order,
        client_ip: Option<IpAddr>,
    ) -> Result<(), Error> {
        let (database, profile) = (self.database, self.profile);
        let thumbprint = jwk_thumbprint(&account.pubkey).map_err(|error| {
            error!(event = "authz_thumbprint_failed", outcome = "failure", account_id = %account.id, error = %error);
            Problem::server_internal("Key authorization could not be computed")
        })?;
        let key_authorization = format!("{}.{}", challenge.token, thumbprint);
        let challenge_id = challenge.id.to_string();

        let context = ValidationContext {
            identifier: authz.base_identifier(),
            wildcard: authz.is_wildcard(),
            token: &challenge.token,
            key_authorization: &key_authorization,
            challenge_id: &challenge_id,
        };

        match profile.challenges.validate(&challenge.typ, &context).await {
            Ok(()) => {
                commit_validation(challenge, authz, order, database).await?;
            }
            Err(error) => {
                let problem = challenge_problem(&error).to_value();
                warn!(
                    event = "challenge_failed",
                    outcome = "failure",
                    challenge_id = %challenge_id,
                    typ = %challenge.typ,
                    kind = error.kind()
                );

                commit_validation_failure(challenge, authz, order, &problem, database).await?;

                // After the commit, not before. Dispatched first, a persistence
                // failure would have notified an operator about a failure that
                // was never recorded — and the client, which gets a 500, would
                // see the challenge still `pending`.
                profile
                    .notify
                    .dispatch(NotifyEvent::ChallengeFailed(ChallengeFailedData {
                        profile: profile.name.clone(),
                        order_id: order.id.to_string(),
                        account_id: account.id.to_string(),
                        authz_id: authz.id.to_string(),
                        challenge_id: challenge.id.clone().to_string(),
                        challenge_type: challenge.typ.clone(),
                        identifier: authz.base_identifier().to_string(),
                        error: error.kind().to_string(),
                        client_ip: client_ip.map(|ip| crate::filter::canonical(ip).to_string()),
                    }))
                    .await;
            }
        }
        Ok(())
    }
}

/// Records a successful validation as **one** transaction: the challenge becomes
/// `valid`, its authorization becomes `valid`, and the order is promoted to
/// `ready` if that was the last one outstanding.
///
/// Three separate statements — which is what this was — can stop between any
/// two. The gap that matters is the last one: an order left `pending` with every
/// authorization already `valid` can never be finalized and nothing re-derives
/// readiness, because the check only ever ran from here and the client has no
/// challenge left to answer to make it run again. The order is stuck until it
/// expires. `post_new_order` has always used one transaction for the same
/// reason.
///
/// It also fixes a second, quieter bug. The readiness check used to re-read the
/// authorizations *from the pool* after the write above had committed, so two
/// concurrent validations of two authorizations of one order could each read
/// before the other's write landed: neither would see a complete set, and
/// neither would promote. Reading inside the transaction that just wrote means
/// SQLite serializes the two writers, and whichever commits second is the one
/// that sees them all `valid`.
async fn commit_validation(
    challenge: &mut Challenge,
    authz: &mut Authorization,
    order: &mut Order,
    database: &Arc<Database>,
) -> Result<(), Problem> {
    let validated = now_secs();
    let outcome = async {
        let mut tx = database.transaction().await?;
        Challenge::set_valid(challenge.id, validated, &mut *tx).await?;
        Authorization::set_valid(authz.id, &mut *tx).await?;

        // `transaction()` issues a deferred BEGIN, but the two writes above
        // have already taken the RESERVED lock by the time this reads — so this
        // sees its own write and no other writer can interleave. Putting a read
        // first here would break that.
        let promote = order.status == OrderStatus::Pending && {
            let authzs = Authorization::find_by_order_with(order.id, &mut *tx).await?;
            authzs.len() == order.identifiers.len()
                && authzs
                    .iter()
                    .all(|authz| authz.status == AuthzStatus::Valid)
        };
        if promote {
            Order::set_ready(order.id, &mut *tx).await?;
        }
        tx.commit().await?;
        Ok::<bool, sqlx::Error>(promote)
    }
    .await;

    match outcome {
        Ok(promoted) => {
            // In-memory sync only after the commit; see `Authorization::set_valid`.
            challenge.status = ChallengeStatus::Valid;
            challenge.validated = Some(validated);
            authz.status = AuthzStatus::Valid;
            if promoted {
                order.status = OrderStatus::Ready;
            }
            Ok(())
        }
        Err(error) => {
            error!(
                event = "challenge_validation_persist_failed",
                outcome = "failure",
                challenge_id = %challenge.id,
                authz_id = %authz.id,
                order_id = %order.id,
                error = %error
            );
            Err(Problem::server_internal("Challenge validation failed"))
        }
    }
}

/// The failure arm of [`commit_validation`], same shape: the challenge takes the
/// problem document explaining why, and its authorization and order both become
/// `invalid`, in one transaction.
async fn commit_validation_failure(
    challenge: &mut Challenge,
    authz: &mut Authorization,
    order: &mut Order,
    problem: &Value,
    database: &Arc<Database>,
) -> Result<(), Problem> {
    let outcome = async {
        let mut tx = database.transaction().await?;
        Challenge::set_invalid(challenge.id, problem, &mut *tx).await?;
        Authorization::set_invalid(authz.id, &mut *tx).await?;
        Order::set_invalid(order.id, problem, &mut *tx).await?;
        tx.commit().await
    }
    .await;

    match outcome {
        Ok(()) => {
            challenge.status = ChallengeStatus::Invalid;
            challenge.error = Some(problem.clone());
            authz.status = AuthzStatus::Invalid;
            order.status = OrderStatus::Invalid;
            order.error = Some(problem.clone());
            Ok(())
        }
        Err(error) => {
            error!(
                event = "challenge_failure_persist_failed",
                outcome = "failure",
                challenge_id = %challenge.id,
                authz_id = %authz.id,
                order_id = %order.id,
                error = %error
            );
            Err(Problem::server_internal("Challenge validation failed"))
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::challenge::{ChallengeError, ChallengeRegistry, ChallengeValidator};
    use crate::notify::NotifyDispatcher;
    use crate::server::ProfileParts;
    use crate::sqlite::order::Identifier;
    use std::time::Duration;

    /// A `default` profile over `database`: an in-memory CA, no filter, no
    /// notifier, and `challenges` as the validators.
    pub(crate) fn profile(database: &Arc<Database>, challenges: ChallengeRegistry) -> Profile {
        Profile::new(
            "default",
            "http://localhost:3000",
            ProfileParts {
                signer: Arc::new(
                    crate::signer::local_ca::LocalCa::generate_in_memory(
                        "ecdsa-p256",
                        90,
                        database.clone(),
                    )
                    .unwrap(),
                ),
                filter: Arc::new(crate::filter::FilterPolicy::default()),
                challenges: Arc::new(challenges),
                order: crate::config::OrderConfig::default(),
                eab: crate::config::EabConfig::default(),
                meta: crate::config::MetaConfig::default(),
                notify: Arc::new(NotifyDispatcher::disabled(crate::testutil::idle_job_queue(
                    database.clone(),
                ))),
            },
        )
    }

    /// An account whose stored key is a real SPKI, so a key authorization can
    /// be computed from it.
    pub(crate) async fn account(database: &Arc<Database>) -> Account {
        use rcgen::PublicKeyData;
        let key = rcgen::KeyPair::generate().unwrap();
        Account::find_or_create(
            "default",
            &key.subject_public_key_info(),
            vec![],
            &crate::audit::ClientContext::default(),
            database,
        )
        .await
        .unwrap()
        .0
    }

    /// An order for `names`, one pending authorization and `http-01` challenge
    /// each.
    async fn pending_order(
        database: &Arc<Database>,
        account: &Account,
        names: &[&str],
    ) -> (Order, Vec<(Authorization, Challenge)>) {
        let order = Order::create(
            "default",
            account.id,
            crate::testutil::dns_identifiers(names),
            now_secs() + 3600,
            None,
            None,
            database,
        )
        .await
        .unwrap();
        let mut authzs = Vec::new();
        for name in names {
            let authz =
                Authorization::create(order.id, Identifier::dns(*name), order.expires, database)
                    .await
                    .unwrap();
            let challenge = Challenge::create(authz.id, "http-01", database)
                .await
                .unwrap();
            authzs.push((authz, challenge));
        }
        (order, authzs)
    }

    async fn reload(database: &Database, order: &Order) -> Order {
        Order::find_by_id(&order.id.to_string(), database)
            .await
            .unwrap()
            .unwrap()
    }

    /// A validator refusing every attempt.
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

    #[tokio::test]
    async fn deactivating_under_a_ready_order_demotes_it_in_the_same_write() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let profile = profile(&database, ChallengeRegistry::default());
        let audit = Auditor::offline(database.clone());
        let orders = OrderService {
            database: &database,
            audit: &audit,
            profile: &profile,
        };
        let account = account(&database).await;
        let (mut order, mut authzs) = pending_order(&database, &account, &["a.example.com"]).await;
        let (authz, challenge) = &mut authzs[0];

        assert!(orders.claim_challenge(challenge, authz).await.unwrap());
        orders
            .run_validation(&account, challenge, authz, &mut order, None)
            .await
            .unwrap();
        assert_eq!(reload(&database, &order).await.status, OrderStatus::Ready);

        orders.deactivate_authz(authz, &mut order).await.unwrap();
        assert_eq!(authz.status, AuthzStatus::Deactivated);
        assert_eq!(reload(&database, &order).await.status, OrderStatus::Pending);

        // A repeat is a no-op, not an error.
        orders.deactivate_authz(authz, &mut order).await.unwrap();

        // And the challenge under it can no longer be triggered.
        let refused = orders.claim_challenge(challenge, authz).await.unwrap_err();
        assert_eq!(
            Problem::from(refused).to_value()["detail"],
            "Authorization has been deactivated"
        );
    }

    #[tokio::test]
    async fn an_issued_order_refuses_deactivation() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let profile = profile(&database, ChallengeRegistry::default());
        let audit = Auditor::offline(database.clone());
        let orders = OrderService {
            database: &database,
            audit: &audit,
            profile: &profile,
        };
        let account = account(&database).await;
        let (mut order, mut authzs) = pending_order(&database, &account, &["a.example.com"]).await;
        order.status = OrderStatus::Valid;

        let refused = orders
            .deactivate_authz(&mut authzs[0].0, &mut order)
            .await
            .unwrap_err();
        assert_eq!(Problem::from(refused).status(), 400);
        assert_eq!(authzs[0].0.status, AuthzStatus::Pending);
    }

    /// The claim is what makes "one validation per challenge" a property of the
    /// row: the second trigger answers without validating.
    #[tokio::test]
    async fn a_challenge_is_claimed_once() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let profile = profile(&database, ChallengeRegistry::default());
        let audit = Auditor::offline(database.clone());
        let orders = OrderService {
            database: &database,
            audit: &audit,
            profile: &profile,
        };
        let account = account(&database).await;
        let (_, mut authzs) = pending_order(&database, &account, &["a.example.com"]).await;
        let (authz, challenge) = &mut authzs[0];
        let mut twin = Challenge::find_by_id(&challenge.id.to_string(), &database)
            .await
            .unwrap()
            .unwrap();

        assert!(orders.claim_challenge(challenge, authz).await.unwrap());
        assert!(!orders.claim_challenge(&mut twin, authz).await.unwrap());
    }

    /// Two authorizations of one order validated at once: whichever commits
    /// second reads both as `valid` inside its own transaction and promotes.
    #[tokio::test]
    async fn concurrent_validations_of_one_order_promote_it() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let profile = profile(&database, ChallengeRegistry::default());
        let audit = Auditor::offline(database.clone());
        let orders = OrderService {
            database: &database,
            audit: &audit,
            profile: &profile,
        };
        let account = account(&database).await;
        let (order, authzs) =
            pending_order(&database, &account, &["a.example.com", "b.example.com"]).await;
        let mut authzs = authzs.into_iter();
        let (mut authz_a, mut challenge_a) = authzs.next().unwrap();
        let (mut authz_b, mut challenge_b) = authzs.next().unwrap();
        let (mut order_a, mut order_b) = (
            reload(&database, &order).await,
            reload(&database, &order).await,
        );

        let a = async {
            assert!(
                orders
                    .claim_challenge(&mut challenge_a, &authz_a)
                    .await
                    .unwrap()
            );
            orders
                .run_validation(&account, &mut challenge_a, &mut authz_a, &mut order_a, None)
                .await
                .unwrap();
        };
        let b = async {
            assert!(
                orders
                    .claim_challenge(&mut challenge_b, &authz_b)
                    .await
                    .unwrap()
            );
            orders
                .run_validation(&account, &mut challenge_b, &mut authz_b, &mut order_b, None)
                .await
                .unwrap();
        };
        tokio::join!(a, b);

        assert_eq!(reload(&database, &order).await.status, OrderStatus::Ready);
    }

    #[tokio::test]
    async fn a_failed_validation_invalidates_challenge_authorization_and_order_together() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let profile = profile(
            &database,
            ChallengeRegistry::new(
                vec![Arc::new(Refusing)],
                vec!["http-01".to_string()],
                false,
                Duration::from_secs(5),
            ),
        );
        let audit = Auditor::offline(database.clone());
        let orders = OrderService {
            database: &database,
            audit: &audit,
            profile: &profile,
        };
        let account = account(&database).await;
        let (mut order, mut authzs) = pending_order(&database, &account, &["a.example.com"]).await;
        let (authz, challenge) = &mut authzs[0];

        assert!(orders.claim_challenge(challenge, authz).await.unwrap());
        orders
            .run_validation(&account, challenge, authz, &mut order, None)
            .await
            .expect("a refused validation is the challenge's answer, not an error");

        let stored = Challenge::find_by_id(&challenge.id.to_string(), &database)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.status, ChallengeStatus::Invalid);
        assert_eq!(
            stored.error.unwrap()["type"],
            "urn:ietf:params:acme:error:incorrectResponse"
        );
        let reloaded = reload(&database, &order).await;
        assert_eq!(reloaded.status, OrderStatus::Invalid);
        assert_eq!(authz.status, AuthzStatus::Invalid);
    }
}
