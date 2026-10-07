//! The configured policy applied to one request: the filter's identifier
//! stage, and the problem a failed challenge validation maps to.
//!
//! The filter engine itself is `acme_proxy_policy`; what lives here is the two
//! places the ACME protocol meets it — the identifiers an order or a CSR asks
//! for, and the EAB credential that authorized the account asking. A refusal
//! is a `Problem` the client reads, and a policy that could not be evaluated
//! is a `500`: "denied" and "nobody decided" are different answers.

use std::net::IpAddr;

use tracing::error;

use acme_proxy_core::error::Problem;
use acme_proxy_core::identifier::Identifier;
use acme_proxy_net::challenge::ChallengeError;
use acme_proxy_policy::filter::EabIdentity;
use acme_proxy_policy::filter::FilterPolicy;
use acme_proxy_policy::filter::IdentifierContext;
use acme_proxy_policy::filter::IdentifierStage;
use acme_proxy_policy::filter::Outcome;
use acme_proxy_store::account::Account;
use acme_proxy_store::db::Database;

/// Runs the policy's identifier stage and maps a refusal to the ACME error the
/// sub-stage calls for.
pub(crate) async fn check_identifiers(
    filter: &FilterPolicy,
    client_ip: Option<IpAddr>,
    account_id: &str,
    profile: &str,
    stage: IdentifierStage,
    identifiers: &[Identifier],
    database: &Database,
) -> Result<(), Problem> {
    // Two indexed reads, and only when some check actually asks about the
    // credential — see `FilterPolicy::needs_eab`. A policy without an `eab`
    // check pays nothing for the field existing.
    let eab = if filter.needs_eab() {
        resolve_eab(account_id, profile, database).await?
    } else {
        None
    };

    let context = IdentifierContext {
        client_ip,
        account_id,
        stage,
        identifiers,
        eab,
    };

    match filter.check_identifiers(&context).await {
        Outcome::Allow => Ok(()),
        Outcome::Deny(detail) => Err(match stage {
            IdentifierStage::NewOrder => Problem::rejected_identifier(detail),
            IdentifierStage::Csr => Problem::bad_csr(detail),
        }),
        Outcome::Undecided(_) => Err(Problem::server_internal("Request filtering failed")),
    }
}

/// Resolves the external account binding an account registered under.
///
/// `None` means the account used no EAB — a refusal for any `eab` check, and
/// the only reading that makes sense for a question about *which* credential
/// authorised it. A database failure is a 500 instead, because "we could not
/// look" must never be reported as "there is none".
async fn resolve_eab(
    account_id: &str,
    profile: &str,
    database: &Database,
) -> Result<Option<EabIdentity>, Problem> {
    let account = Account::find_by_id(profile, account_id, database)
        .await
        .map_err(|error| {
            error!(event = "account_lookup_failed", outcome = "failure", account_id, error = %error);
            Problem::server_internal("Database error")
        })?;

    let Some(kid) = account.and_then(|account| account.eab_kid) else {
        return Ok(None);
    };

    // Deliberately the unscoped lookup: the credential authorised this account
    // when it was created, and re-checking the profile scope now would make a
    // later narrowing of that scope silently rewrite history.
    let key = acme_proxy_store::eab::Eab::find_any_by_kid(kid.to_string().as_str(), database)
        .await
        .map_err(|error| {
            error!(event = "eab_lookup_failed", outcome = "failure", kid = %kid, error = %error);
            Problem::server_internal("Database error")
        })?;

    Ok(key.map(|key| EabIdentity {
        kid: key.kid.to_string(),
        label: key.label,
        active: key.status == "active",
    }))
}

/// Maps a failed validation of a `typ` challenge for `identifier` to the ACME
/// error that describes it, with the detail the client may see
/// ([`ChallengeError::client_detail`]).
pub(crate) fn challenge_problem(error: &ChallengeError, typ: &str, identifier: &str) -> Problem {
    let detail = error.client_detail(typ, identifier).into_owned();
    match error {
        ChallengeError::Connection(_) => Problem::connection(detail),
        ChallengeError::Dns(_) => Problem::dns(detail),
        ChallengeError::IncorrectResponse(_) => Problem::incorrect_response(detail),
        ChallengeError::Tls(_) => Problem::tls(detail),
        ChallengeError::Unauthorized(_) => Problem::access_denied(detail),
        ChallengeError::Internal(_) => Problem::server_internal("Challenge validation failed"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The credential an account registered under resolves while it exists —
    /// revoked included, which is what keeps label rules matching — and to
    /// nothing once it is deleted, which every `eab` check refuses. That is
    /// what `eab delete` warns about when it keeps the accounts.
    #[tokio::test]
    async fn an_account_whose_credential_was_deleted_resolves_to_no_credential() {
        use acme_proxy_store::eab::BoundAccounts;
        use acme_proxy_store::eab::Eab;

        let database = std::sync::Arc::new(Database::connect_in_memory().await.unwrap());
        let eab = Eab::create(Some("tenant-a".to_string()), None, &database)
            .await
            .unwrap();
        let (mut account, _) = Account::find_or_create(
            "default",
            &[9u8],
            vec![],
            &acme_proxy_core::audit::ClientContext::default(),
            &database,
        )
        .await
        .unwrap();
        account.set_eab_kid(eab.kid, &database).await.unwrap();
        let id = account.id.to_string();

        Eab::revoke(&eab.kid.to_string(), &database).await.unwrap();
        let revoked = resolve_eab(&id, "default", &database)
            .await
            .unwrap()
            .expect("a revoked credential still resolves");
        assert_eq!(
            (revoked.label.as_deref(), revoked.active),
            (Some("tenant-a"), false)
        );

        Eab::delete(&eab.kid.to_string(), BoundAccounts::Keep, &database)
            .await
            .unwrap();
        assert!(
            resolve_eab(&id, "default", &database)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn challenge_errors_map_to_their_acme_problem_types() {
        let cases = [
            (
                ChallengeError::Connection("refused".into()),
                "urn:ietf:params:acme:error:connection",
                400,
            ),
            (
                ChallengeError::Dns("no record".into()),
                "urn:ietf:params:acme:error:dns",
                400,
            ),
            (
                ChallengeError::IncorrectResponse("wrong value".into()),
                "urn:ietf:params:acme:error:incorrectResponse",
                403,
            ),
            (
                ChallengeError::Tls("no alpn".into()),
                "urn:ietf:params:acme:error:tls",
                400,
            ),
            (
                ChallengeError::Unauthorized("wrong body".into()),
                "urn:ietf:params:acme:error:unauthorized",
                403,
            ),
        ];

        for (error, typ, status) in cases {
            let value = challenge_problem(&error, "dns-01", "example.com").to_value();
            assert_eq!(value["type"], typ);
            assert_eq!(value["status"], status);
            assert_eq!(value["detail"], error.detail());
        }

        let internal = challenge_problem(
            &ChallengeError::Internal("no validator".into()),
            "dns-01",
            "example.com",
        );
        let value = internal.to_value();
        assert_eq!(value["type"], "urn:ietf:params:acme:error:serverInternal");
        assert_eq!(value["status"], 500);
        assert!(!value["detail"].as_str().unwrap().contains("no validator"));
    }

    /// `http-01` follows redirects wherever they point, so what it learned
    /// about the hosts it reached — a status, a length, a socket error, the
    /// next `Location` — is the server's to log, never the client's to read.
    /// The kind still reaches the client, as the problem type.
    #[test]
    fn an_http_01_failure_tells_the_client_its_kind_and_nothing_it_probed() {
        for (error, typ) in [
            (
                ChallengeError::Unauthorized(
                    "http://10.0.0.5:8080/.well-known/acme-challenge/t responded with HTTP 401"
                        .into(),
                ),
                "urn:ietf:params:acme:error:unauthorized",
            ),
            (
                ChallengeError::Connection("tcp connect to 10.0.0.5:80: Connection refused".into()),
                "urn:ietf:params:acme:error:connection",
            ),
        ] {
            let value = challenge_problem(&error, "http-01", "app.example.com").to_value();
            assert_eq!(value["type"], typ);
            let detail = value["detail"].as_str().unwrap();
            assert!(detail.contains("app.example.com"), "{detail}");
            for leaked in ["10.0.0.5", "401", "refused", "8080"] {
                assert!(!detail.contains(leaked), "{leaked} leaked: {detail}");
            }
        }
    }
}
