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

use acme_proxy_core::audit::{Actor, AuditRecord, ClientContext};
use acme_proxy_jobs::auditor::admin as audit;
use acme_proxy_jobs::auditor::admin::SessionScope;
use acme_proxy_jobs::notify::AdminCredentialChange;
use acme_proxy_store::admin_user::{AdminRole, AdminStatus, AdminUser};
use acme_proxy_store::db::Database;

use crate::admin::mfa;
use crate::admin::users::{self, UserError};

/// Where one surface's record of an operator change goes.
///
/// The futures are `Send` because the web admin awaits them inside an axum
/// handler.
pub trait OperatorTrail: Sync {
    /// Writes one audit row, built from this surface's actor and client.
    fn record(
        &self,
        build: impl FnOnce(Actor, ClientContext) -> AuditRecord + Send,
    ) -> impl Future<Output = ()> + Send;

    /// Queues the `admin_credential_changed` message to the operator `user`.
    /// `previous_recipient` is the address a contact change replaced.
    fn notify(
        &self,
        user: &AdminUser,
        change: AdminCredentialChange,
        previous_recipient: Option<String>,
    ) -> impl Future<Output = ()> + Send;
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

/// Removes `user`'s second factor and every recovery code on another
/// operator's say-so, ending their sessions: there is no session of theirs to
/// keep, the change being made from somewhere they are not signed in. They are
/// told, since they did not do it.
pub async fn reset_totp(
    user: &mut AdminUser,
    database: Arc<Database>,
    trail: &impl OperatorTrail,
) -> Result<(), sqlx::Error> {
    mfa::disable_totp(user, None, database).await?;
    trail
        .record(|actor, client| audit::operator_totp_disabled(actor, client, &user.username, true))
        .await;
    trail
        .notify(user, AdminCredentialChange::SecondFactorDisabled, None)
        .await;
    Ok(())
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
    use acme_proxy_store::admin_session::{AdminSession, NewSession};
    use std::sync::Mutex;

    /// A trail that keeps what it was given: the event of each row, and the
    /// change and previous recipient of each message.
    #[derive(Default)]
    struct Recording {
        events: Mutex<Vec<String>>,
        messages: Mutex<Vec<(AdminCredentialChange, Option<String>)>>,
    }

    impl OperatorTrail for Recording {
        async fn record(&self, build: impl FnOnce(Actor, ClientContext) -> AuditRecord + Send) {
            let record = build(Actor::cli(), ClientContext::default());
            self.events
                .lock()
                .unwrap()
                .push(record.event.as_str().to_string());
        }

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

        let trail = Recording::default();
        reset_totp(&mut alice, database, &trail).await.unwrap();
        assert_eq!(trail.events(), ["operator_totp_disabled"]);
        assert_eq!(
            *trail.messages.lock().unwrap(),
            [(AdminCredentialChange::SecondFactorDisabled, None)]
        );
    }
}
