//! Accounts (RFC 8555 §7.3): creation, update, deactivation and key rollover.

use std::net::IpAddr;
use std::sync::Arc;

use axum::http::StatusCode;
use serde::Deserialize;
use tracing::{error, info, warn};
use uuid::Uuid;

use super::access::signer_account;
use super::error::Error;
use super::rules::validate_contacts;
use crate::profile::Profile;
use acme_proxy_core::audit::RequestContext;
use acme_proxy_core::eab;
use acme_proxy_core::error::Problem;
use acme_proxy_core::jws::ProtectedHeader;
use acme_proxy_core::jws::signature::spki_to_jwk;
use acme_proxy_core::key_change;
use acme_proxy_jobs::auditor::Auditor;
use acme_proxy_jobs::notify::AccountCreatedData;
use acme_proxy_jobs::notify::AccountDeactivatedData;
use acme_proxy_jobs::notify::NotifyDispatcher;
use acme_proxy_jobs::notify::NotifyEvent;
use acme_proxy_store::account::Account;
use acme_proxy_store::account::pubkey_fingerprint;
use acme_proxy_store::db::Database;
use acme_proxy_store::eab::Eab;
use acme_proxy_store::order::Order;

/// Every field is optional: real clients may omit `contact`, and the two flags
/// default to `false`.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct NewAccountPayload {
    pub contact: Vec<String>,
    #[serde(alias = "termsOfServiceAgreed")]
    pub terms_of_service_agreed: bool,
    #[serde(alias = "onlyReturnExisting")]
    pub only_return_existing: bool,
    #[serde(alias = "externalAccountBinding")]
    pub external_account_binding: Option<eab::EabJws>,
}

/// Fields an account-update request may carry.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct UpdateAccountPayload {
    pub contact: Option<Vec<String>>,
    pub status: Option<String>,
}

/// The account-side operations of one endpoint — the
/// [`OrderService`](super::OrderService) shape.
pub struct AccountService<'a> {
    pub database: &'a Arc<Database>,
    pub audit: &'a Auditor,
    pub profile: &'a Profile,
}

impl AccountService<'_> {
    /// `newAccount` (RFC 8555 §7.3): finds the account `pubkey` holds at this
    /// endpoint, or creates one. The `bool` is whether it was created — `201`
    /// against `200` at the edge.
    ///
    /// `onlyReturnExisting` (§7.3.1) looks up and never creates. A refusal to
    /// agree to configured terms is [`Error::TermsNotAgreed`], since the
    /// response it owes carries a `Link` a problem document cannot.
    pub async fn new_account(
        &self,
        payload: NewAccountPayload,
        header: &ProtectedHeader,
        pubkey: &[u8],
        client_ip: Option<IpAddr>,
        request: &RequestContext,
    ) -> Result<(Account, bool), Error> {
        let (database, profile, audit) = (self.database, self.profile, self.audit);

        if payload.only_return_existing {
            let account = Account::find_by_pubkey(&profile.name, pubkey, database)
                .await
                .map_err(|error| {
                    // Distinct from `acme::access`'s `account_lookup_failed`: same
                    // query, but this one is `newAccount`'s §7.3.1 lookup, not the
                    // one that resolves the signer of an order-side request.
                    error!(event = "account_only_return_existing_lookup_failed", outcome = "failure", error = %error);
                    Problem::server_internal("Account lookup failed")
                })?
                .ok_or_else(|| {
                    info!(event = "account_only_return_existing_miss", outcome = "failure");
                    Problem::account_does_not_exist("No account for this key")
                })?;

            refuse_deactivated(&account, true)?;
            return Ok((account, false));
        }

        // Checked before the EAB, so a client with a typo'd address hears about the
        // typo rather than burning its one-shot EAB credential on a doomed request.
        validate_contacts(&payload.contact)?;

        // RFC 8555 §7.3.3: a client agrees to the terms by setting
        // `termsOfServiceAgreed`, and §6.7's `userActionRequired` is the refusal
        // when it has not. Enforced only when `meta.termsOfService` is configured —
        // §7.3.3 ties the requirement to the directory advertising a ToS, so an
        // endpoint with none must not demand agreement to something it never named.
        if !profile.meta.terms_of_service.is_empty() && !payload.terms_of_service_agreed {
            warn!(event = "account_terms_not_agreed", outcome = "failure");
            return Err(Error::TermsNotAgreed);
        }

        let eab_kid = if profile.eab.enabled {
            Some(
                verify_eab(
                    payload.external_account_binding.as_ref(),
                    header,
                    &profile.name,
                    database,
                )
                .await?,
            )
        } else {
            None
        };

        // Resolved before the write, and only on this path: `onlyReturnExisting`
        // returned above without ever creating anything, and `find_or_create`
        // stamps these columns on the creating branch alone — so a PTR lookup for a
        // request that turns out to find an existing account is wasted, but a
        // lookup after the INSERT would need a second UPDATE to record it.
        let client = audit.client(request).await;
        // The credential that authorized this registration and the agreement to
        // the terms are columns of the insert, not writes that follow it: an
        // account bound to no credential escapes `eab delete
        // --deactivate-accounts` and fails every `eab` filter rule closed.
        // Recorded only where the endpoint has terms to agree to — the check
        // above already refused a request that did not agree, so reaching here
        // with a ToS configured means the client set the flag.
        let registration = acme_proxy_store::account::Registration {
            eab_kid,
            terms_agreed: !profile.meta.terms_of_service.is_empty(),
        };
        let (account, created) = Account::find_or_register(
            &profile.name,
            pubkey,
            payload.contact,
            &registration,
            &client,
            database,
        )
        .await
        .map_err(|error| {
            error!(event = "account_creation_failed", outcome = "failure", error = %error);
            Problem::server_internal("Account persistence failed")
        })?;

        // Only on the found branch: an account this request just created is never
        // deactivated, and asking would be reading a column we wrote a line ago.
        if !created {
            refuse_deactivated(&account, false)?;
        }

        if created {
            profile
                .notify
                .dispatch(NotifyEvent::AccountCreated(AccountCreatedData {
                    profile: profile.name.clone(),
                    account_id: account.id.to_string(),
                    contact: account.contact.clone(),
                    client_ip: client_ip
                        .map(|ip| acme_proxy_core::client::canonical(ip).to_string()),
                }))
                .await;
        }

        let status = if created {
            StatusCode::CREATED
        } else {
            StatusCode::OK
        };
        // Two names, because §7.3's find-or-create makes them two different
        // events: one registered a key, the other recognised one. An operator
        // counting registrations must not have to filter a field out of the
        // count.
        if created {
            info!(event = "account_created", outcome = "success", account_id = %account.id, status = %status);
        } else {
            info!(event = "account_found", outcome = "success", account_id = %account.id, status = %status);
        }
        Ok((account, created))
    }

    /// `POST /acct/{id}` (RFC 8555 §7.3.2, §7.3.6): replaces the contact list, or
    /// deactivates the account, for a request signed by the account's own key.
    pub async fn update(
        &self,
        id: &str,
        payload: UpdateAccountPayload,
        pubkey: &[u8],
        client_ip: Option<IpAddr>,
    ) -> Result<Account, Error> {
        let (database, profile) = (self.database, self.profile);

        let mut account = match Account::find_by_id(&profile.name, id, database).await {
            Ok(Some(account)) => account,
            Ok(None) => {
                warn!(event = "account_not_found", outcome = "failure", account_id = %id);
                return Err(Problem::account_does_not_exist("Unknown account").into());
            }
            Err(error) => {
                error!(
                    event = "account_update_lookup_failed",
                    outcome = "failure",
                    account_id = %id,
                    error = %error
                );
                return Err(Problem::server_internal("Account lookup failed").into());
            }
        };

        if account.pubkey != pubkey {
            warn!(
                event = "account_key_mismatch",
                outcome = "failure",
                account_id = %id,
                expected_pubkey_fp = %pubkey_fingerprint(&account.pubkey),
                actual_pubkey_fp = %pubkey_fingerprint(pubkey)
            );
            return Err(Problem::unauthorized("Signed by a different account key").into());
        }

        if account.is_deactivated() {
            warn!(
                event = "account_deactivated_modify_refused",
                outcome = "failure",
                account_id = %id
            );
            return Err(Problem::unauthorized("Account deactivated").into());
        }

        if let Some(status) = payload.status {
            if status != acme_proxy_store::account::DEACTIVATED {
                warn!(event = "account_update_bad_status", outcome = "failure", account_id = %id, status = %status);
                return Err(Problem::malformed("Only 'deactivated' status is accepted").into());
            }
            deactivate(
                &mut account,
                database,
                Some(&profile.notify),
                client_ip.map(|ip| acme_proxy_core::client::canonical(ip).to_string()),
            )
            .await
            .map_err(|error| {
                error!(
                    event = "account_deactivation_failed",
                    outcome = "failure",
                    account_id = %id,
                    error = %error
                );
                Problem::server_internal("Account update failed")
            })?;
            info!(
                event = "account_deactivated",
                outcome = "success",
                account_id = %id
            );
        } else if let Some(contact) = payload.contact {
            update_contact(&mut account, contact, database)
                .await
                .map_err(|error| match error {
                    ContactUpdateError::Refused(problem) => problem,
                    ContactUpdateError::Database(error) => {
                        error!(
                            event = "account_contact_update_failed",
                            outcome = "failure",
                            account_id = %id,
                            error = %error
                        );
                        Problem::server_internal("Account update failed")
                    }
                })?;
            info!(
                event = "account_contact_updated",
                outcome = "success",
                account_id = %id
            );
        }

        info!(
            event = "account_updated",
            outcome = "success",
            account_id = %id
        );
        Ok(account)
    }

    /// `keyChange` (RFC 8555 §7.3.5): moves the signer's account onto the key the
    /// nested JWS proves possession of.
    ///
    /// A new key already held by another account is
    /// [`Error::KeyChangeConflict`], carrying the holder so the edge can answer
    /// with its `Location`.
    pub async fn key_change(
        &self,
        cached: Option<Account>,
        old_pubkey: &[u8],
        header: &ProtectedHeader,
        inner_jws: &key_change::KeyChangeJws,
    ) -> Result<Account, Error> {
        let (database, profile) = (self.database, self.profile);
        let base = &profile.base_url;

        let mut old_account = signer_account(cached, &profile.name, old_pubkey, database).await?;

        let inner_header = key_change::parse_header(inner_jws, &header.url)
            .map_err(key_change::key_change_problem)?;
        let new_pubkey = key_change::verify_signature(inner_jws, &inner_header)
            .map_err(key_change::key_change_problem)?;

        let account_url = format!("{base}/acct/{}", old_account.id);
        let old_key_jwk = spki_to_jwk(&old_account.pubkey).map_err(|error| {
            error!(event = "key_change_old_key_decode_failed", outcome = "failure", account_id = %old_account.id, error = %error);
            Problem::server_internal("Stored account key could not be decoded")
        })?;
        key_change::verify_payload(inner_jws, &account_url, &old_key_jwk)
            .map_err(key_change::key_change_problem)?;

        let conflicting_account = Account::find_by_pubkey(&profile.name, &new_pubkey, database)
            .await
            .map_err(|error| {
                error!(event = "key_change_conflict_lookup_failed", outcome = "failure", account_id = %old_account.id, error = %error);
                Problem::server_internal("Account lookup failed")
            })?;
        if let Some(existing) = conflicting_account {
            warn!(event = "key_change_conflict", outcome = "failure", account_id = %old_account.id, conflicting_account_id = %existing.id);
            return Err(Error::KeyChangeConflict {
                holder: existing.id,
            });
        }

        if let Err(error) = old_account.update_pubkey(&new_pubkey, database).await {
            // The check above and this write are two statements, and another
            // rollover onto the same key can land between them — at which point
            // `UNIQUE (profile, pubkey)` is what says so. §7.3.5 gives that case a
            // status and a `Location`, so answering `serverInternal` here would
            // report "something went wrong" for a condition the RFC describes
            // exactly, and deny the client the one field it needs to recover.
            //
            // Re-read rather than reuse `new_pubkey`'s earlier (empty) lookup: the
            // account that won is by definition committed now.
            if acme_proxy_store::account::is_pubkey_conflict(&error)
                && let Ok(Some(winner)) =
                    Account::find_by_pubkey(&profile.name, &new_pubkey, database).await
            {
                warn!(event = "key_change_conflict", outcome = "failure", account_id = %old_account.id, conflicting_account_id = %winner.id);
                return Err(Error::KeyChangeConflict { holder: winner.id });
            }
            error!(event = "key_change_persist_failed", outcome = "failure", account_id = %old_account.id, error = %error);
            return Err(Problem::server_internal("Account key update failed").into());
        }

        info!(event = "account_key_changed", outcome = "success", account_id = %old_account.id);
        Ok(old_account)
    }

    /// The orders-list resource (RFC 8555 §7.1.2.1) of account `id`, for a request
    /// signed by that account: its orders still worth handing back.
    pub async fn orders(
        &self,
        cached: Option<Account>,
        pubkey: &[u8],
        id: &str,
    ) -> Result<Vec<Order>, Error> {
        let (database, profile) = (self.database, self.profile);
        let account = signer_account(cached, &profile.name, pubkey, database).await?;
        if account.id.to_string() != id {
            warn!(
                event = "account_orders_ownership_mismatch",
                outcome = "failure",
                requested = %id,
                signer = %account.id
            );
            return Err(Problem::unauthorized("Not your account").into());
        }

        // RFC 8555 §7.1.2.1's filtered view — expired and `invalid` orders are not
        // URLs worth handing back (see `find_active_by_account`).
        Ok(Order::find_active_by_account(account.id, database)
            .await
            .map_err(|error| {
                error!(
                    event = "account_orders_lookup_failed",
                    outcome = "failure",
                    account_id = %id,
                    error = %error
                );
                Problem::server_internal("Order list failed")
            })?)
    }
}

/// Refuses a request signed by the key of a deactivated account.
///
/// RFC 8555 §7.3.6: "If a server receives a POST or POST-as-GET from a
/// deactivated account, it MUST return an error response with status code 401
/// (Unauthorized) and type `urn:ietf:params:acme:error:unauthorized`." Every
/// order-side endpoint and `keyChange` get this through `signer_account`, and
/// `update` checks it directly — `newAccount` was the one path that did not, on
/// either of its branches, so a deactivated key could still confirm its account
/// existed and read its own `contact` list back out of the `Location` response.
///
/// The wording matches `signer_account`'s byte for byte, so a deactivated key
/// gets one answer wherever it knocks.
fn refuse_deactivated(account: &Account, only_return_existing: bool) -> Result<(), Problem> {
    if !account.is_deactivated() {
        return Ok(());
    }
    warn!(
        event = "account_deactivated_registration_refused",
        outcome = "failure",
        account_id = %account.id,
        only_return_existing = only_return_existing
    );
    Err(Problem::unauthorized("Account is deactivated"))
}

/// Verifies the RFC 8555 §7.3.4 External Account Binding.
pub async fn verify_eab(
    eab_jws: Option<&eab::EabJws>,
    header: &ProtectedHeader,
    profile: &str,
    database: &Arc<Database>,
) -> Result<Uuid, Problem> {
    let eab_jws = eab_jws.ok_or_else(|| {
        warn!(event = "eab_required", outcome = "failure", profile);
        Problem::external_account_required("This server requires External Account Binding")
    })?;

    let outer_jwk = header.jwk.as_ref().ok_or_else(|| {
        warn!(event = "eab_missing_jwk", outcome = "failure", profile);
        Problem::malformed("newAccount requires an embedded jwk for External Account Binding")
    })?;

    let eab_header = eab::parse_header(eab_jws, &header.url).map_err(eab::eab_problem)?;

    let key = Eab::find_by_kid(&eab_header.kid, profile, database)
        .await
        .map_err(|error| {
            error!(event = "eab_lookup_failed", outcome = "failure", kid = %eab_header.kid, error = %error);
            Problem::server_internal("External Account Binding lookup failed")
        })?
        .filter(Eab::is_active)
        .ok_or_else(|| {
            warn!(event = "eab_unknown_or_revoked_kid", outcome = "failure", kid = %eab_header.kid);
            Problem::unauthorized("Unknown or revoked External Account Binding key")
        })?;

    eab::verify_payload_and_signature(eab_jws, &key.secret, outer_jwk).map_err(eab::eab_problem)?;

    info!(event = "eab_verified", outcome = "success", kid = %key.kid);
    Ok(key.kid)
}

/// Deactivates `account` (RFC 8555 §7.3.6), then queues `account_deactivated`.
///
/// Shared by the account's own request and an operator's: the notification is
/// about the account, whoever shut it. `notify` is the account's profile's
/// dispatcher where this process has one, and `client_ip` whoever asked — the
/// client, the operator, or nobody. Logs nothing; each caller names its own
/// events.
pub async fn deactivate(
    account: &mut Account,
    database: &Database,
    notify: Option<&NotifyDispatcher>,
    client_ip: Option<String>,
) -> Result<(), sqlx::Error> {
    account.deactivate(database).await?;
    if let Some(dispatcher) = notify {
        dispatcher
            .dispatch(NotifyEvent::AccountDeactivated(AccountDeactivatedData {
                profile: account.profile.clone(),
                account_id: account.id.to_string(),
                client_ip,
            }))
            .await;
    }
    Ok(())
}

/// Why [`update_contact`] did not write.
#[derive(Debug, thiserror::Error)]
pub enum ContactUpdateError {
    /// A contact RFC 8555 §7.3 refuses, as the problem `newAccount` would answer.
    #[error("{0}")]
    Refused(Problem),
    #[error("the contact list could not be stored")]
    Database(#[from] sqlx::Error),
}

/// Replaces `account`'s contact list, refusing one `newAccount` would refuse.
///
/// One check for every surface — the ACME update, the admin API, the panel and
/// the CLI — so no front end can store a contact another would reject.
pub async fn update_contact(
    account: &mut Account,
    contact: Vec<String>,
    database: &Database,
) -> Result<(), ContactUpdateError> {
    validate_contacts(&contact).map_err(ContactUpdateError::Refused)?;
    account
        .update_contact(contact, database)
        .await
        .map_err(ContactUpdateError::Database)
}
