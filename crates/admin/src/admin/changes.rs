//! A change to an operator — by another operator, or, for the contact
//! address, by themselves: each change with everything it owes — the write,
//! the audit rows, the message — in one function both front ends call.
//!
//! The CLI and the web admin each used to spell these four as "apply → audit →
//! revoked-sessions row → notify", and the copies had drifted twice over: the
//! CLI wrote a `session_revoked` row counting zero sessions after a role or
//! password change, and an `operator_contact_updated` row for an address set to
//! what it already was, where the panel wrote neither. What genuinely differs
//! between the surfaces — who the actor is, how the client is resolved, which
//! dispatcher carries the message — is an [`OperatorTrail`]; the sequence is
//! here, once.
//!
//! Log lines stay with each front end: they name the surface and the signed-in
//! operator, which only the front end knows.

use std::future::Future;
use std::sync::Arc;

use acme_proxy_jobs::auditor::admin as audit;
use acme_proxy_jobs::auditor::admin::SessionScope;
use acme_proxy_jobs::notify::AdminCredentialChange;
use acme_proxy_store::admin_session::AdminSession;
use acme_proxy_store::admin_user::{AdminRole, AdminStatus, AdminUser};
use acme_proxy_store::db::Database;

use crate::admin::mfa;
pub use crate::admin::trail::ActionTrail;
use crate::admin::users::{self, UserError};

/// Where one surface's record of an operator change goes: its rows, through
/// the [`ActionTrail`] this extends, and the message to the operator changed.
///
/// The futures are `Send` because the web admin awaits them inside an axum
/// handler.
pub trait OperatorTrail: ActionTrail {
    /// Queues the `admin_credential_changed` message to the operator `user`.
    /// `previous_recipient` is the address a contact change replaced.
    fn notify(
        &self,
        user: &AdminUser,
        change: AdminCredentialChange,
        previous_recipient: Option<String>,
    ) -> impl Future<Output = ()> + Send;
}

/// A change to an operator's own credentials:
/// [`AdminCredentialChange`] less the contact address, which
/// [`change_contact`] owns because it knows the address it replaced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialChange {
    Password,
    SecondFactorEnabled,
    SecondFactorDisabled,
    RecoveryCodesRegenerated,
}

impl From<CredentialChange> for AdminCredentialChange {
    fn from(change: CredentialChange) -> Self {
        match change {
            CredentialChange::Password => Self::Password,
            CredentialChange::SecondFactorEnabled => Self::SecondFactorEnabled,
            CredentialChange::SecondFactorDisabled => Self::SecondFactorDisabled,
            CredentialChange::RecoveryCodesRegenerated => Self::RecoveryCodesRegenerated,
        }
    }
}

/// Records a credential change **both ways at once**: the audit row and the
/// message to the operator it happened to.
///
/// The two are one event with two audiences — the trail says what the CA did,
/// the message tells the person it was done to — and writing them as two
/// adjacent calls meant one could be forgotten. One was: the `/ui` enrolment
/// path notified and left no row. Taking a single [`CredentialChange`] and
/// deriving the event from it makes that unrepresentable, on every surface.
///
/// `by_self` is `false` when another operator — or the host CLI — made the
/// change.
pub async fn record_credential_change(
    user: &AdminUser,
    change: CredentialChange,
    by_self: bool,
    trail: &impl OperatorTrail,
) {
    let username = user.username.as_str();
    trail
        .record(|actor, client| match change {
            CredentialChange::Password => {
                audit::operator_password_changed(actor, client, username, by_self)
            }
            CredentialChange::SecondFactorEnabled => {
                audit::operator_totp_enrolled(actor, client, username)
            }
            CredentialChange::SecondFactorDisabled => {
                audit::operator_totp_disabled(actor, client, username, !by_self)
            }
            CredentialChange::RecoveryCodesRegenerated => {
                audit::operator_recovery_codes_regenerated(actor, client, username)
            }
        })
        .await;
    trail.notify(user, change.into(), None).await;
}

/// Sets `username`'s password on someone else's say-so, ending their sessions;
/// recorded and announced as a [`CredentialChange::Password`], plus a
/// `session_revoked` row when there was a session to end. `None` when there is
/// no such operator.
pub async fn set_password(
    username: &str,
    plaintext: &str,
    context: &crate::admin::password::PasswordContext,
    database: Arc<Database>,
    trail: &impl OperatorTrail,
) -> Result<Option<(AdminUser, u64)>, UserError> {
    let Some((user, revoked)) = users::set_password(username, plaintext, context, database).await?
    else {
        return Ok(None);
    };
    record_credential_change(&user, CredentialChange::Password, false, trail).await;
    record_revoked(&user, revoked, trail).await;
    Ok(Some((user, revoked)))
}

/// Replaces `user`'s recovery codes on someone else's say-so, returning the new
/// set to show once; recorded and announced as a
/// [`CredentialChange::RecoveryCodesRegenerated`]. Whether `user` has a factor
/// for the codes to recover is the caller's to check first.
pub async fn regenerate_recovery_codes(
    user: &AdminUser,
    database: Arc<Database>,
    trail: &impl OperatorTrail,
) -> Result<Vec<String>, sqlx::Error> {
    let codes = mfa::regenerate_recovery_codes(user, database).await?;
    record_credential_change(
        user,
        CredentialChange::RecoveryCodesRegenerated,
        false,
        trail,
    )
    .await;
    Ok(codes)
}

/// Enables or disables `username`. Disabling ends every session they held,
/// which is a second thing that happened and so a second row — only when
/// there was a session to end. `None` when there is no such operator.
pub async fn change_status(
    username: &str,
    status: AdminStatus,
    database: Arc<Database>,
    trail: &impl OperatorTrail,
) -> Result<Option<(AdminUser, u64)>, sqlx::Error> {
    let Some((user, revoked)) = users::set_status(username, status, database).await? else {
        return Ok(None);
    };
    let active = status == AdminStatus::Active;
    trail
        .record(|actor, client| {
            audit::operator_status_changed(actor, client, &user.username, active)
        })
        .await;
    record_revoked(&user, revoked, trail).await;
    Ok(Some((user, revoked)))
}

/// Sets `username`'s tier, ending their sessions so the new one applies at
/// once — recorded as for [`change_status`]. `None` when there is no such
/// operator.
pub async fn change_role(
    username: &str,
    role: AdminRole,
    database: Arc<Database>,
    trail: &impl OperatorTrail,
) -> Result<Option<(AdminUser, u64)>, UserError> {
    let Some((user, revoked)) = users::set_role(username, role, database).await? else {
        return Ok(None);
    };
    trail
        .record(|actor, client| {
            audit::operator_role_changed(actor, client, &user.username, role.as_str())
        })
        .await;
    record_revoked(&user, revoked, trail).await;
    Ok(Some((user, revoked)))
}

/// Brings an external operator's tier in line with what their provider says,
/// at sign-in -- [`change_role`]'s record, through `users::sync_role` rather
/// than the refusal [`users::set_role`] gives an external operator.
pub(crate) async fn sync_role(
    user: AdminUser,
    role: AdminRole,
    database: Arc<Database>,
    trail: &impl OperatorTrail,
) -> Result<(AdminUser, u64), UserError> {
    let (user, revoked) = users::sync_role(user, role, database).await?;
    trail
        .record(|actor, client| {
            audit::operator_role_changed(actor, client, &user.username, role.as_str())
        })
        .await;
    record_revoked(&user, revoked, trail).await;
    Ok((user, revoked))
}

/// Sets or clears `username`'s notification address.
///
/// An address set to what it already was writes no row and sends no message:
/// telling somebody their alarms moved to the address they were already using
/// is noise that teaches them to ignore the real one. Otherwise the message
/// goes to the address the change **replaced** — whoever made the change
/// controls the new one. The `bool` is whether anything changed; `None` when
/// there is no such operator.
pub async fn change_contact(
    username: &str,
    contact: Option<&str>,
    database: Arc<Database>,
    trail: &impl OperatorTrail,
) -> Result<Option<(AdminUser, bool)>, UserError> {
    let previous = AdminUser::find_by_username(username, &database)
        .await?
        .and_then(|user| user.contact_email);
    let Some(user) = users::set_contact_email(username, contact, database).await? else {
        return Ok(None);
    };
    if user.contact_email == previous {
        return Ok(Some((user, false)));
    }
    let set = user.contact_email.is_some();
    trail
        .record(|actor, client| audit::operator_contact_updated(actor, client, &user.username, set))
        .await;
    trail
        .notify(&user, AdminCredentialChange::ContactAddress, previous)
        .await;
    Ok(Some((user, true)))
}

/// Whether `user` has a second factor — confirmed or half-enrolled — for
/// [`reset_totp`] to remove. A front end that asks before resetting checks
/// this first, so it does not prompt for nothing.
#[must_use]
pub fn has_totp_to_reset(user: &AdminUser) -> bool {
    user.has_totp() || user.has_pending_totp()
}

/// Removes `user`'s second factor and every recovery code on another
/// operator's say-so, ending their sessions: there is no session of theirs to
/// keep, the change being made from somewhere they are not signed in. They are
/// told, since they did not do it.
///
/// `Ok(false)` when there was nothing to remove: no write, no audit row and no
/// message, on every surface — a trail that recorded a reset which removed
/// nothing would tell the operator their factor was taken away when it never
/// existed.
pub async fn reset_totp(
    user: &mut AdminUser,
    database: Arc<Database>,
    trail: &impl OperatorTrail,
) -> Result<bool, sqlx::Error> {
    if !has_totp_to_reset(user) {
        return Ok(false);
    }
    mfa::disable_totp(user, None, database).await?;
    trail
        .record(|actor, client| audit::operator_totp_disabled(actor, client, &user.username, true))
        .await;
    trail
        .notify(user, AdminCredentialChange::SecondFactorDisabled, None)
        .await;
    Ok(true)
}

/// Ends one of `user`'s sessions, named by the fingerprint every listing
/// shows, and records it. `Ok(false)` when `user` holds no such session.
///
/// No message: unlike the changes above, the operator loses a sign-in, not a
/// credential, and the next request from it says so.
pub async fn revoke_session(
    user: &AdminUser,
    fingerprint: &str,
    database: Arc<Database>,
    trail: &impl ActionTrail,
) -> Result<bool, sqlx::Error> {
    let Some(session) =
        AdminSession::find_by_user_and_fingerprint(user.id, fingerprint, &database).await?
    else {
        return Ok(false);
    };
    AdminSession::delete(&session.token_hash, &database).await?;
    trail
        .record(|actor, client| {
            audit::session_revoked(actor, client, SessionScope::OneOf(user.username.clone()), 1)
        })
        .await;
    Ok(true)
}

pub(crate) async fn record_revoked(user: &AdminUser, revoked: u64, trail: &impl OperatorTrail) {
    if revoked > 0 {
        trail
            .record(|actor, client| {
                audit::session_revoked(
                    actor,
                    client,
                    SessionScope::AllOf(user.username.clone()),
                    revoked,
                )
            })
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use acme_proxy_core::audit::{Actor, AuditRecord, ClientContext};
    use acme_proxy_store::admin_session::NewSession;
    use std::sync::Mutex;

    /// A trail that keeps what it was given: the event of each row, and the
    /// change and previous recipient of each message.
    #[derive(Default)]
    struct Recording {
        events: Mutex<Vec<String>>,
        messages: Mutex<Vec<(AdminCredentialChange, Option<String>)>>,
    }

    impl ActionTrail for Recording {
        async fn record_all(
            &self,
            build: impl FnOnce(Actor, ClientContext) -> Vec<AuditRecord> + Send,
        ) {
            let records = build(Actor::cli(), ClientContext::default());
            self.events.lock().unwrap().extend(
                records
                    .iter()
                    .map(|record| record.event.as_str().to_string()),
            );
        }
    }

    impl OperatorTrail for Recording {
        async fn notify(
            &self,
            _user: &AdminUser,
            change: AdminCredentialChange,
            previous_recipient: Option<String>,
        ) {
            self.messages
                .lock()
                .unwrap()
                .push((change, previous_recipient));
        }
    }

    impl Recording {
        fn events(&self) -> Vec<String> {
            self.events.lock().unwrap().clone()
        }
    }

    async fn db() -> Arc<Database> {
        Arc::new(Database::connect_in_memory().await.unwrap())
    }

    /// An admin with a placeholder hash: nothing here signs in.
    async fn operator(username: &str, database: &Database) -> AdminUser {
        AdminUser::create(username, "unused", Some(AdminRole::Admin), database)
            .await
            .unwrap()
    }

    async fn session_for(user: &AdminUser, database: &Database) {
        AdminSession::create(
            NewSession {
                user_id: user.id,
                token_hash: "hash",
                csrf_token: "csrf",
                created_ip: None,
                user_agent: None,
            },
            std::time::Duration::from_secs(60),
            database,
        )
        .await
        .unwrap();
    }

    /// The sessions row only when there were sessions — the drift this module
    /// was extracted to end.
    #[tokio::test]
    async fn a_status_change_records_the_sessions_it_ended_and_only_those() {
        let database = db().await;
        let alice = operator("alice", &database).await;
        operator("root", &database).await;

        let trail = Recording::default();
        change_status("alice", AdminStatus::Disabled, database.clone(), &trail)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(trail.events(), ["operator_disabled"]);

        change_status("alice", AdminStatus::Active, database.clone(), &trail)
            .await
            .unwrap();
        session_for(&alice, &database).await;
        let trail = Recording::default();
        let (_, revoked) = change_role("alice", AdminRole::Viewer, database.clone(), &trail)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(revoked, 1);
        assert_eq!(trail.events(), ["operator_role_changed", "session_revoked"]);

        assert!(
            change_status("nobody", AdminStatus::Disabled, database, &trail)
                .await
                .unwrap()
                .is_none()
        );
    }

    /// An address set to what it already was writes nothing and tells nobody;
    /// a real change is one row and one message, to the address it replaced.
    #[tokio::test]
    async fn a_contact_change_records_and_notifies_only_a_real_change() {
        let database = db().await;
        operator("alice", &database).await;

        let trail = Recording::default();
        change_contact("alice", Some("a@example.com"), database.clone(), &trail)
            .await
            .unwrap();
        let trail = Recording::default();
        let (_, changed) = change_contact("alice", Some("a@example.com"), database.clone(), &trail)
            .await
            .unwrap()
            .unwrap();
        assert!(!changed);
        assert!(trail.events().is_empty());
        assert!(trail.messages.lock().unwrap().is_empty());

        let (_, changed) = change_contact("alice", Some("b@example.com"), database, &trail)
            .await
            .unwrap()
            .unwrap();
        assert!(changed);
        assert_eq!(trail.events(), ["operator_contact_updated"]);
        assert_eq!(
            *trail.messages.lock().unwrap(),
            [(
                AdminCredentialChange::ContactAddress,
                Some("a@example.com".to_string())
            )]
        );
    }

    #[tokio::test]
    async fn a_totp_reset_is_recorded_and_the_operator_told() {
        let database = db().await;
        let mut alice = operator("alice", &database).await;

        // Nothing to remove: no write, no row, no message.
        let trail = Recording::default();
        assert!(
            !reset_totp(&mut alice, database.clone(), &trail)
                .await
                .unwrap()
        );
        assert!(trail.events().is_empty());
        assert!(trail.messages.lock().unwrap().is_empty());

        alice.set_totp_pending(b"secret", &database).await.unwrap();
        assert!(reset_totp(&mut alice, database, &trail).await.unwrap());
        assert!(!alice.has_pending_totp());
        assert_eq!(trail.events(), ["operator_totp_disabled"]);
        assert_eq!(
            *trail.messages.lock().unwrap(),
            [(AdminCredentialChange::SecondFactorDisabled, None)]
        );
    }

    /// A password set from the host is recorded and announced as one
    /// credential change, and its revoked sessions as a second row — the same
    /// pair the panel writes.
    #[tokio::test]
    async fn a_password_set_for_someone_is_recorded_announced_and_ends_sessions() {
        let database = db().await;
        let alice = operator("alice", &database).await;
        session_for(&alice, &database).await;

        let trail = Recording::default();
        let (_, revoked) = set_password(
            "alice",
            "a long and unusual passphrase",
            &crate::admin::password::PasswordContext::empty(),
            database.clone(),
            &trail,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(revoked, 1);
        assert_eq!(
            trail.events(),
            ["operator_password_changed", "session_revoked"]
        );
        assert_eq!(
            *trail.messages.lock().unwrap(),
            [(AdminCredentialChange::Password, None)]
        );

        assert!(
            set_password(
                "nobody",
                "a long and unusual passphrase",
                &crate::admin::password::PasswordContext::empty(),
                database,
                &trail,
            )
            .await
            .unwrap()
            .is_none()
        );
    }

    #[tokio::test]
    async fn regenerated_recovery_codes_are_recorded_and_announced() {
        let database = db().await;
        let alice = operator("alice", &database).await;

        let trail = Recording::default();
        let codes = regenerate_recovery_codes(&alice, database, &trail)
            .await
            .unwrap();
        assert!(!codes.is_empty());
        assert_eq!(trail.events(), ["operator_recovery_codes_regenerated"]);
        assert_eq!(
            *trail.messages.lock().unwrap(),
            [(AdminCredentialChange::RecoveryCodesRegenerated, None)]
        );
    }

    #[tokio::test]
    async fn revoking_one_session_records_it_and_an_unknown_one_is_false() {
        let database = db().await;
        let alice = operator("alice", &database).await;
        session_for(&alice, &database).await;
        // `session_for` stores the token hash `hash`; listings show its
        // fingerprint.
        let fp = acme_proxy_store::nonce::fingerprint("hash");

        let trail = Recording::default();
        assert!(
            !revoke_session(&alice, "no-such-fp", database.clone(), &trail)
                .await
                .unwrap()
        );
        assert!(revoke_session(&alice, fp, database, &trail).await.unwrap());
        assert_eq!(trail.events(), ["session_revoked"]);
    }
}
