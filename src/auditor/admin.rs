//! Constructors for the administrative half of the audit trail.
//!
//! `audit_log` records two kinds of thing now: what the CA did to a certificate
//! (built in `src/handlers/` and `src/admin/ops.rs`'s `revoke_order`/`cancel_job`,
//! which take an [`Actor`] because the row is written from inside the operation)
//! and what an operator did to the CA — an account, an EAB credential, an
//! operator, a session, the nonce or audit tables. Those latter operations are
//! plain CRUD whose audit row is a side effect of success, so the record is
//! built **here** and the front end (`src/cli/`, `src/webadmin/handlers/`,
//! `src/webadmin/pages/`) writes it with [`crate::auditor::write`] once the
//! operation has returned success. A not-found or refused operation writes
//! nothing.
//!
//! One function per event so the three front ends cannot describe one action
//! differently. The web front end passes [`Actor::admin`] with the operator's
//! username and the client address it resolved through the shared
//! [`Auditor`](crate::auditor::Auditor); the CLI passes [`Actor::cli`] and an
//! empty [`ClientContext`].

use acme_proxy_core::audit::Actor;
use acme_proxy_core::audit::AuditEvent;
use acme_proxy_core::audit::AuditRecord;
use acme_proxy_core::audit::ClientContext;
use acme_proxy_store::account::Account;
use acme_proxy_store::order::Order;

/// The actor and (empty) client context a host-CLI administrative action is
/// attributed with. The web front end builds [`Actor::admin`] with the
/// operator's username and a resolved address instead.
///
/// Prefer [`record_cli_action`], which pairs this with the write.
#[must_use]
pub fn cli_actor() -> (Actor, ClientContext) {
    (Actor::cli(), ClientContext::default())
}

/// Writes one administrative audit row attributed to the host CLI.
///
/// The terminal twin of `AdminState::record_admin_action`, and it exists for
/// that helper's reason: every one of these rows is a *side effect of success*,
/// so the pairing of "build the record" with "write it, after the operation
/// returned success" wants one home rather than nineteen. Spelled out at each
/// call site, the rule survived only as long as nobody forgot half of it — and
/// `order delete` did, hard-deleting an order and leaving the trail silent.
///
/// Call it **after** the operation succeeded. A not-found or refused operation
/// writes nothing, which is the whole difference between this half of the
/// vocabulary and the certificate half.
pub async fn record_cli_action(
    database: &acme_proxy_store::db::Database,
    build: impl FnOnce(Actor, ClientContext) -> AuditRecord,
) {
    let (actor, client) = cli_actor();
    crate::auditor::write(build(actor, client), database).await;
}

/// [`record_cli_action`] for an action that writes several rows — `eab delete`,
/// one per account it changed and one for the credential.
pub async fn record_cli_actions(
    database: &acme_proxy_store::db::Database,
    build: impl FnOnce(Actor, ClientContext) -> Vec<AuditRecord>,
) {
    let (actor, client) = cli_actor();
    for record in build(actor, client) {
        crate::auditor::write(record, database).await;
    }
}

fn base(
    event: AuditEvent,
    profile: impl Into<String>,
    actor: Actor,
    client: ClientContext,
) -> AuditRecord {
    AuditRecord::new(event, profile, actor).with_client(client)
}

/// An action with no ACME subject and no profile — an operator, a session, or a
/// table swept whole.
fn process_wide(
    event: AuditEvent,
    actor: Actor,
    client: ClientContext,
    detail: impl Into<String>,
) -> AuditRecord {
    AuditRecord::admin(event, actor)
        .with_client(client)
        .with_detail(detail)
}

// --- accounts -------------------------------------------------------------

#[must_use]
pub fn account_deactivated(actor: Actor, client: ClientContext, account: &Account) -> AuditRecord {
    base(
        AuditEvent::AccountDeactivated,
        &account.profile,
        actor,
        client,
    )
    .with_account(account.id.to_string())
}

#[must_use]
pub fn account_contact_updated(
    actor: Actor,
    client: ClientContext,
    account: &Account,
    contact: &[String],
) -> AuditRecord {
    let detail = if contact.is_empty() {
        "contact cleared".to_string()
    } else {
        format!("contact = [{}]", contact.join(", "))
    };
    base(
        AuditEvent::AccountContactUpdated,
        &account.profile,
        actor,
        client,
    )
    .with_account(account.id.to_string())
    .with_detail(detail)
}

#[must_use]
pub fn account_deleted(
    actor: Actor,
    client: ClientContext,
    account: &Account,
    cascaded: u64,
) -> AuditRecord {
    base(AuditEvent::AccountDeleted, &account.profile, actor, client)
        .with_account(account.id.to_string())
        .with_detail(format!("{cascaded} order(s) cascaded"))
}

// --- orders -------------------------------------------------------------

#[must_use]
pub fn order_deleted(
    actor: Actor,
    client: ClientContext,
    order: &Order,
    cascaded: u64,
) -> AuditRecord {
    base(AuditEvent::OrderDeleted, &order.profile, actor, client)
        .with_order(order.id, order.account_id, &order.identifiers)
        .with_detail(format!("{cascaded} authorization(s) cascaded"))
}

// --- external account binding -----------------------------------------------

#[must_use]
pub fn eab_created(
    actor: Actor,
    client: ClientContext,
    kid: &str,
    profile: Option<&str>,
    label: Option<&str>,
) -> AuditRecord {
    let detail = match label {
        Some(label) => format!("kid {kid}, label {label:?}"),
        None => format!("kid {kid}"),
    };
    base(
        AuditEvent::EabCreated,
        profile.unwrap_or_default(),
        actor,
        client,
    )
    .with_detail(detail)
}

#[must_use]
pub fn eab_revoked(
    actor: Actor,
    client: ClientContext,
    kid: &str,
    profile: Option<&str>,
) -> AuditRecord {
    base(
        AuditEvent::EabRevoked,
        profile.unwrap_or_default(),
        actor,
        client,
    )
    .with_detail(format!("kid {kid}"))
}

/// `eab_deleted`. `accounts` says what became of the accounts the credential
/// bound; each account deactivated or deleted also gets its own
/// `account_deactivated`/`account_deleted` row, written by the front end, so
/// `audit list --account-id` explains it without this row.
#[must_use]
pub fn eab_deleted(
    actor: Actor,
    client: ClientContext,
    deleted: &acme_proxy_store::eab::DeletedEab,
) -> AuditRecord {
    use acme_proxy_store::eab::BoundAccounts;

    let eab = &deleted.eab;
    let accounts = match deleted.accounts {
        BoundAccounts::Keep => format!("{} account(s) kept", deleted.remaining),
        BoundAccounts::Deactivate => format!(
            "{} account(s) deactivated, {} kept",
            deleted.deactivated.len(),
            deleted.remaining
        ),
        BoundAccounts::Delete => format!("{} account(s) deleted", deleted.deleted.len()),
    };
    let detail = match &eab.label {
        Some(label) => format!("kid {}, label {label:?}, {accounts}", eab.kid),
        None => format!("kid {}, {accounts}", eab.kid),
    };
    base(
        AuditEvent::EabDeleted,
        eab.profile.as_deref().unwrap_or_default(),
        actor,
        client,
    )
    .with_detail(detail)
}

/// Every row one `eab delete` writes: an `account_deactivated` or
/// `account_deleted` per account it changed — so `audit list --account-id`
/// explains each without reading `eab_deleted` — then the `eab_deleted` row.
/// Accounts kept, or already deactivated, changed nothing and get nothing.
#[must_use]
pub fn eab_deleted_records(
    actor: Actor,
    client: ClientContext,
    deleted: &acme_proxy_store::eab::DeletedEab,
) -> Vec<AuditRecord> {
    let mut records: Vec<AuditRecord> = deleted
        .deactivated
        .iter()
        .map(|account| account_deactivated(actor.clone(), client.clone(), account))
        .chain(deleted.deleted.iter().map(|(account, orders)| {
            account_deleted(actor.clone(), client.clone(), account, *orders)
        }))
        .collect();
    records.push(eab_deleted(actor, client, deleted));
    records
}

// --- operators ---------------------------------------------------------------

#[must_use]
pub fn operator_created(
    actor: Actor,
    client: ClientContext,
    username: &str,
    role: &str,
) -> AuditRecord {
    process_wide(
        AuditEvent::OperatorCreated,
        actor,
        client,
        format!("{username} (role {role})"),
    )
}

#[must_use]
pub fn operator_role_changed(
    actor: Actor,
    client: ClientContext,
    username: &str,
    role: &str,
) -> AuditRecord {
    process_wide(
        AuditEvent::OperatorRoleChanged,
        actor,
        client,
        format!("{username} -> role {role}"),
    )
}

#[must_use]
pub fn operator_contact_updated(
    actor: Actor,
    client: ClientContext,
    username: &str,
    set: bool,
) -> AuditRecord {
    process_wide(
        AuditEvent::OperatorContactUpdated,
        actor,
        client,
        format!("{username} contact {}", if set { "set" } else { "cleared" }),
    )
}

#[must_use]
pub fn operator_password_changed(
    actor: Actor,
    client: ClientContext,
    username: &str,
    self_service: bool,
) -> AuditRecord {
    let detail = if self_service {
        format!("{username} (self)")
    } else {
        username.to_string()
    };
    process_wide(AuditEvent::OperatorPasswordChanged, actor, client, detail)
}

#[must_use]
pub fn operator_status_changed(
    actor: Actor,
    client: ClientContext,
    username: &str,
    enabled: bool,
) -> AuditRecord {
    let event = if enabled {
        AuditEvent::OperatorEnabled
    } else {
        AuditEvent::OperatorDisabled
    };
    process_wide(event, actor, client, username.to_string())
}

#[must_use]
pub fn operator_deleted(actor: Actor, client: ClientContext, username: &str) -> AuditRecord {
    process_wide(
        AuditEvent::OperatorDeleted,
        actor,
        client,
        username.to_string(),
    )
}

#[must_use]
pub fn operator_totp_enrolled(actor: Actor, client: ClientContext, username: &str) -> AuditRecord {
    process_wide(
        AuditEvent::OperatorTotpEnrolled,
        actor,
        client,
        username.to_string(),
    )
}

#[must_use]
pub fn operator_totp_disabled(
    actor: Actor,
    client: ClientContext,
    username: &str,
    by_admin: bool,
) -> AuditRecord {
    let detail = if by_admin {
        format!("{username} (operator reset)")
    } else {
        username.to_string()
    };
    process_wide(AuditEvent::OperatorTotpDisabled, actor, client, detail)
}

#[must_use]
pub fn operator_recovery_codes_regenerated(
    actor: Actor,
    client: ClientContext,
    username: &str,
) -> AuditRecord {
    process_wide(
        AuditEvent::OperatorRecoveryCodesRegenerated,
        actor,
        client,
        username.to_string(),
    )
}

// --- sessions --------------------------------------------------------------

/// Which sessions a `session_revoked` row covers.
#[derive(Debug, Clone)]
pub enum SessionScope {
    /// The operator ended their own current session (sign-out).
    OwnCurrent,
    /// The operator ended one other session of their own.
    OwnOther,
    /// Every session the named operator held (a `revoke --all`, or the implicit
    /// revoke a password / role / disable change carries).
    AllOf(String),
    /// One named session of the named operator.
    OneOf(String),
    /// Every session on the server (`admin session revoke --all`).
    Everyone,
}

/// One `session_revoked` row. `count` is how many sessions actually went.
///
/// The count is not decoration: on the two plural scopes the detail alone
/// cannot tell "all sessions of alice" over forty live cookies from the same
/// sentence over none, and an operator reading the trail after an incident is
/// asking exactly that. `nonce_cleanup_completed` and `audit_pruned` already
/// carry theirs for the same reason. It is elided on the singular scopes, where
/// it is always one and saying so would be noise.
#[must_use]
pub fn session_revoked(
    actor: Actor,
    client: ClientContext,
    scope: SessionScope,
    count: u64,
) -> AuditRecord {
    let detail = match scope {
        SessionScope::OwnCurrent => "own current session".to_string(),
        SessionScope::OwnOther => "own session".to_string(),
        SessionScope::AllOf(username) => {
            format!("all sessions of {username} ({count} session(s))")
        }
        SessionScope::OneOf(username) => format!("one session of {username}"),
        SessionScope::Everyone => format!("every session on the server ({count} session(s))"),
    };
    process_wide(AuditEvent::SessionRevoked, actor, client, detail)
}

// --- background queue and housekeeping ------------------------------------

#[must_use]
pub fn job_cancelled(actor: Actor, client: ClientContext, kind: &str, id: &str) -> AuditRecord {
    process_wide(
        AuditEvent::JobCancelled,
        actor,
        client,
        format!("{kind} job {id}"),
    )
}

#[must_use]
pub fn job_advanced(actor: Actor, client: ClientContext, id: &str, revived: bool) -> AuditRecord {
    process_wide(
        AuditEvent::JobAdvanced,
        actor,
        client,
        format!("job {id} {}", if revived { "revived" } else { "nudged" }),
    )
}

#[must_use]
pub fn nonce_cleanup_completed(actor: Actor, client: ClientContext, removed: u64) -> AuditRecord {
    process_wide(
        AuditEvent::NonceCleanupCompleted,
        actor,
        client,
        format!("{removed} nonce(s) removed"),
    )
}

#[must_use]
pub fn audit_pruned(
    actor: Actor,
    client: ClientContext,
    removed: u64,
    older_than_days: u64,
) -> AuditRecord {
    process_wide(
        AuditEvent::AuditPruned,
        actor,
        client,
        format!("{removed} row(s) older than {older_than_days} day(s) removed"),
    )
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use acme_proxy_store::db::Database;

    fn cli() -> (Actor, ClientContext) {
        (Actor::cli(), ClientContext::default())
    }

    #[test]
    fn a_process_wide_action_carries_no_profile_and_no_subject() {
        let (actor, client) = cli();
        let record = operator_status_changed(actor, client, "alice", false);
        assert_eq!(record.event, AuditEvent::OperatorDisabled);
        assert_eq!(record.profile, "");
        assert!(record.account_id.is_none());
        assert!(record.order_id.is_none());
        assert_eq!(record.detail.as_deref(), Some("alice"));
        assert_eq!(record.actor.kind.as_str(), "cli");
    }

    #[tokio::test]
    async fn an_account_action_keeps_the_account_id_and_its_profile() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let account = acme_proxy_store::testutil::account_seen_from(
            &[9u8, 9, 9],
            &ClientContext::default(),
            &database,
        )
        .await;
        let (actor, client) = cli();
        let record = account_contact_updated(actor, client, &account, &account.contact);
        assert_eq!(record.event, AuditEvent::AccountContactUpdated);
        assert_eq!(record.profile, "default");
        assert_eq!(
            record.account_id.as_deref(),
            Some(account.id.to_string().as_str())
        );
        assert_eq!(
            record.detail.as_deref(),
            Some("contact = [mailto:a@example.com]")
        );
    }

    /// `eab delete` writes a row per account it changed, each carrying its own
    /// subject, then the credential's — whose detail names the label and says
    /// what became of the accounts.
    #[tokio::test]
    async fn an_eab_delete_records_each_account_then_the_credential() {
        use acme_proxy_store::eab::BoundAccounts;
        use acme_proxy_store::eab::DeletedEab;
        use acme_proxy_store::eab::Eab;

        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let account = acme_proxy_store::testutil::account_seen_from(
            &[8u8],
            &ClientContext::default(),
            &database,
        )
        .await;
        let eab = Eab::create(
            Some("team".to_string()),
            Some("default".to_string()),
            &database,
        )
        .await
        .unwrap();
        let kid = eab.kid;
        let deleted = DeletedEab {
            eab,
            accounts: BoundAccounts::Delete,
            deactivated: Vec::new(),
            deleted: vec![(account, 4)],
            remaining: 0,
        };

        let (actor, client) = cli();
        let records = eab_deleted_records(actor, client, &deleted);
        assert_eq!(
            records
                .iter()
                .map(|record| record.event)
                .collect::<Vec<_>>(),
            [AuditEvent::AccountDeleted, AuditEvent::EabDeleted]
        );
        assert_eq!(records[0].detail.as_deref(), Some("4 order(s) cascaded"));
        assert_eq!(records[1].profile, "default");
        assert_eq!(
            records[1].detail.as_deref(),
            Some(format!("kid {kid}, label \"team\", 1 account(s) deleted").as_str())
        );

        let kept = DeletedEab {
            accounts: BoundAccounts::Deactivate,
            deleted: Vec::new(),
            remaining: 2,
            ..deleted
        };
        let (actor, client) = cli();
        let records = eab_deleted_records(actor, client, &kept);
        assert_eq!(records.len(), 1);
        assert!(
            records[0]
                .detail
                .as_deref()
                .unwrap()
                .ends_with("0 account(s) deactivated, 2 kept")
        );
    }

    #[test]
    fn status_and_totp_helpers_pick_the_right_variant() {
        let (actor, client) = cli();
        assert_eq!(
            operator_status_changed(actor.clone(), client.clone(), "a", true).event,
            AuditEvent::OperatorEnabled
        );
        assert_eq!(
            operator_totp_disabled(actor, client, "a", true).event,
            AuditEvent::OperatorTotpDisabled
        );
    }

    #[test]
    fn the_session_scopes_each_read_distinctly() {
        let (actor, client) = cli();
        let one = session_revoked(
            actor.clone(),
            client.clone(),
            SessionScope::OneOf("a".into()),
            1,
        );
        let all = session_revoked(actor, client, SessionScope::AllOf("a".into()), 7);
        assert_ne!(one.detail, all.detail);
    }
}
