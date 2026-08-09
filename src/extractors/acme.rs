use std::time::Duration;

use axum::extract::{FromRef, FromRequest, Request};
use axum::http::StatusCode;
use base64::prelude::*;
use serde::de::DeserializeOwned;
use tracing::{Span, debug, error, instrument, warn};

use crate::AppState;
use crate::error::Problem;
use crate::sqlite::account::Account;
use crate::sqlite::nonce::Nonce;

pub use crate::extractors::jws::*;
pub use crate::extractors::signature::*;

/// ACME request wrapper containing validated JWS data.
pub struct AcmeRequest<T> {
    pub header: ProtectedHeader,
    pub payload: T,
    pub pubkey: Vec<u8>,
    pub account: Option<Account>,
}

/// The media type RFC 8555 §6.2 requires on every ACME request body.
const JOSE_JSON: &str = "application/jose+json";

/// Whether a `Content-Type` header value names [`JOSE_JSON`].
///
/// Compares the *essence* only: parameters (`; charset=utf-8`) are tolerated,
/// since a client is free to send them, and the type/subtype are matched
/// case-insensitively per RFC 9110 §8.3.1. A missing header is not a match —
/// §6.2 requires the type to be present, not merely not-contradicted.
fn is_jose_json(content_type: Option<&str>) -> bool {
    content_type.is_some_and(|value| {
        let essence = value.split(';').next().unwrap_or_default().trim();
        essence.eq_ignore_ascii_case(JOSE_JSON)
    })
}

/// Parses a flattened JWS request, verifies its signature, and returns the
/// verified `(header, pubkey, account, payload_b64)`.
// `alg` and `account_id` are declared empty and filled in below, once the
// protected header has parsed and the `kid` has resolved. Without the
// declaration `Span::current().record(…)` writes to a field this span does not
// have and is silently dropped — which is what used to happen, leaving a
// `kid`-authenticated request unattributable to any account.
#[instrument(
    name = "verify_jws",
    skip_all,
    fields(
        path = %req.uri().path(),
        alg = tracing::field::Empty,
        account_id = tracing::field::Empty,
    )
)]
async fn verify_jws<S>(
    req: Request,
    state: &S,
) -> Result<(ProtectedHeader, Vec<u8>, Option<Account>, String), Problem>
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    let app = AppState::from_ref(state);
    let request_path = req.uri().path().to_string();
    // Read before the body is consumed below, and kept for the `last_seen_*`
    // stamp at the very end of this function.
    let request_context = crate::audit::RequestContext::from_request(&req);
    debug!(event = "jws_request_received", path = %request_path);

    // RFC 8555 §6.2: an ACME request body is a flattened JWS and so "must have
    // the Content-Type header field set to `application/jose+json`. If a
    // request does not meet this requirement, then the server MUST return a
    // response with status code 415". Checking it here rather than in each
    // handler is the same reasoning as the `url` and nonce checks below: a new
    // signed route cannot forget it.
    let content_type = req
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok());
    if !is_jose_json(content_type) {
        warn!(event = "jws_bad_content_type", content_type = ?content_type, path = %request_path);
        return Err(Problem::unsupported_media_type(
            "Content-Type must be application/jose+json",
        ));
    }

    let body_str = String::from_request(req, state)
        .await
        .map_err(|rejection| {
            // A body over `server.max_body_bytes` is not a malformed JWS — it is a
            // request the server declined to read at all, and a client told "your
            // JWS is malformed" would rebuild a JWS that is not the problem. axum
            // reports the limit through the rejection's own status.
            if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
                warn!(event = "jws_body_too_large", path = %request_path);
                return Problem::payload_too_large("Request body exceeds the configured limit");
            }
            warn!(event = "jws_body_read_failed", path = %request_path);
            Problem::malformed("Cannot read HTTP Body")
        })?;

    let jws: AcmeJwsRequest = serde_json::from_str(&body_str).map_err(|_| {
        warn!(event = "jws_json_parse_failed", body_length = body_str.len(), path = %request_path);
        Problem::malformed("JSON JWS format invalid")
    })?;

    let protected_bytes = BASE64_URL_SAFE_NO_PAD.decode(&jws.protected).map_err(|_| {
        warn!(event = "jws_protected_decode_failed", protected_length = jws.protected.len(), path = %request_path);
        Problem::malformed("Base64 protected invalid")
    })?;

    let header: ProtectedHeader = serde_json::from_slice(&protected_bytes).map_err(|_| {
        warn!(event = "jws_header_parse_failed", protected_length = protected_bytes.len(), path = %request_path);
        Problem::malformed("JSON protected invalid")
    })?;

    Span::current().record("alg", header.alg.as_str());

    // RFC 7515 §4.1.11: a recipient that does not understand every extension
    // named in `crit` MUST reject the JWS. This server understands none, so
    // any `crit` at all — even an empty array, which §4.1.11 also forbids — is
    // a rejection.
    if let Some(crit) = &header.crit {
        warn!(event = "jws_crit_header_present", extensions = ?crit, url = %header.url);
        return Err(Problem::malformed(
            "Unsupported critical JWS header extension",
        ));
    }

    // §6.4, checked here rather than after the signature: it needs nothing but
    // the header, and doing it first means a JWS not addressed to this endpoint
    // never reaches the database at all. The signature still has to verify
    // before anything is *acted* on — this only reorders two refusals.
    //
    // `request_path` is what the profile's own router saw, i.e. with the
    // `/profile/<name>` mount point already stripped by `Router::nest` — so
    // pairing it with the profile's base URL reconstructs exactly the URL the
    // client was given, and a JWS signed for another endpoint fails here.
    let expected_url = format!("{}{request_path}", app.profile.base_url);
    if header.url != expected_url {
        warn!(event = "jws_url_mismatch", url = %header.url, expected = %expected_url);
        return Err(Problem::malformed("URL invalid"));
    }

    let signing_input = format!("{}.{}", jws.protected, jws.payload);

    let mut signer_account: Option<Account> = None;
    let pubkey = match (&header.jwk, &header.kid) {
        (Some(_), Some(_)) => {
            warn!(event = "jwk_and_kid_both_present", url = %header.url, algorithm = %header.alg);
            return Err(Problem::malformed("jwk and kid are mutually exclusive"));
        }
        (Some(_), None) => {
            debug!(event = "verifying_jwk_signature", algorithm = %header.alg, url = %header.url);
            verify_signature_and_get_der(&header, &signing_input, &jws.signature)
                .map_err(map_signature_error)?
        }
        (None, Some(kid)) => {
            debug!(event = "verifying_kid_signature", algorithm = %header.alg, kid = %kid);
            // The account URL is the one *this* endpoint minted, prefix and
            // all: a `kid` naming another profile does not match here, and the
            // lookup below is scoped to this profile besides.
            let base = &app.profile.base_url;
            let id = kid
                .strip_prefix(&format!("{base}/acct/"))
                .ok_or_else(|| {
                    warn!(event = "jws_kid_prefix_mismatch", kid = %kid, expected_prefix = %format!("{base}/acct/"));
                    Problem::malformed("kid invalid")
                })?;

            Span::current().record("account_id", id);

            let account = Account::find_by_id(&app.profile.name, id, &app.database)
                .await
                .map_err(|error| {
                    error!(event = "account_lookup_during_kid_verification", account_id = %id, error = %error);
                    Problem::server_internal("Account lookup failed")
                })?
                .ok_or_else(|| Problem::account_does_not_exist("Unknown account"))?;

            verify_signature_with_spki(
                &header.alg,
                &account.pubkey,
                &signing_input,
                &jws.signature,
            )
            .map_err(map_signature_error)?;

            let pubkey = account.pubkey.clone();
            signer_account = Some(account);
            pubkey
        }
        (None, None) => {
            warn!(event = "missing_jwk_and_kid", url = %header.url, algorithm = %header.alg);
            return Err(Problem::malformed("missing jwk or kid"));
        }
    };

    let ttl = Duration::from_secs(app.config.nonce.ttl_seconds);
    match Nonce::verify(header.nonce.clone(), &app.database, ttl).await {
        Ok(true) => {}
        Ok(false) => {
            // Unknown, already consumed or past `nonce.ttl_seconds` — the three
            // are indistinguishable by design, since a consumed nonce is
            // deleted. This is the anti-replay refusal, so it is worth a line:
            // a client stuck replaying is a client that will never issue.
            warn!(
                event = "nonce_replayed",
                nonce = %crate::sqlite::nonce::fingerprint(&header.nonce),
                path = %request_path
            );
            return Err(Problem::bad_nonce("Nonce invalid"));
        }
        Err(error) => {
            // The nonce itself never reaches a log: until it is consumed it is
            // a bearer credential, and this arm is the one where it was *not*
            // consumed. See `Nonce::fingerprint`.
            error!(
                event = "nonce_verification_failed",
                nonce = %crate::sqlite::nonce::fingerprint(&header.nonce),
                error = %error
            );
            return Err(Problem::server_internal("Nonce verification failed"));
        }
    }

    // The account's `last_seen_*` stamp, here rather than in a handler because
    // this is the one place every `kid`-authenticated request funnels through —
    // the same reasoning that hoisted the media-type, `crit`, `url` and nonce
    // checks into this function. After the nonce check, so a replayed or
    // expired request never moves the mark: "last used" has to mean a request
    // the server actually accepted.
    if let Some(account) = signer_account.as_mut() {
        touch_account(account, &request_context, &app).await;
    }

    debug!(
        event = "jws_request_validated",
        algorithm = %header.alg,
        url = %header.url,
        signature_type = match (&header.jwk, &header.kid) {
            (Some(_), None) => "jwk",
            (None, Some(_)) => "kid",
            _ => "unknown",
        },
        signature_size = jws.signature.len()
    );

    Ok((header, pubkey, signer_account, jws.payload))
}

/// Advances `account.last_seen_*`, if the throttle says it is worth a write.
///
/// Three deliberate properties:
///
/// - **The address is decided before the lookup.** `needs_touch` takes the
///   canonicalized address and nothing else, so a request that will be
///   throttled never pays for a PTR query — which is most of them.
/// - **A failure is a warning, not a rejection.** These columns are
///   traceability; a client whose issuance failed because the server could not
///   write down where it came from would be a worse server, not a safer one.
/// - **Canonicalized first**, like every other address this crate stores: the
///   dual-stack `[::]:3000` bind sees an IPv4 client as `::ffff:…`, and the same
///   client arriving over IPv4 and IPv6 must not read as two addresses.
async fn touch_account(
    account: &mut Account,
    request: &crate::audit::RequestContext,
    app: &AppState,
) {
    let ip = request
        .ip
        .map(crate::filter::canonical)
        .map(|ip| ip.to_string());
    if !account.needs_touch(crate::sqlite::nonce::now_secs(), ip.as_deref()) {
        return;
    }
    let client = app.audit.client(request).await;
    if let Err(error) = account.touch(&client, &app.database).await {
        warn!(
            event = "account_touch_failed",
            account_id = %account.id,
            error = %error
        );
    }
}

impl<S, T> FromRequest<S> for AcmeRequest<T>
where
    S: Send + Sync,
    AppState: FromRef<S>,
    T: DeserializeOwned,
{
    type Rejection = Problem;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let (header, pubkey, account, payload_b64) = verify_jws(req, state).await?;

        let payload_bytes = BASE64_URL_SAFE_NO_PAD.decode(&payload_b64).map_err(|_| {
            warn!(
                event = "jws_payload_decode_failed",
                payload_length = payload_b64.len()
            );
            Problem::malformed("Base64 payload invalid")
        })?;

        let payload: T = serde_json::from_slice(&payload_bytes).map_err(|_| {
            warn!(
                event = "jws_payload_parse_failed",
                payload_length = payload_bytes.len()
            );
            Problem::malformed("Payload JSON invalid for this endpoint")
        })?;

        Ok(AcmeRequest {
            header,
            payload,
            pubkey,
            account,
        })
    }
}

/// A verified ACME **POST-as-GET** request (RFC 8555 §6.3).
pub struct AcmePostAsGet {
    pub header: ProtectedHeader,
    pub pubkey: Vec<u8>,
    pub account: Option<Account>,
}

impl<S> FromRequest<S> for AcmePostAsGet
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = Problem;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let (header, pubkey, account, payload_b64) = verify_jws(req, state).await?;

        if !payload_b64.is_empty() {
            warn!(
                event = "post_as_get_payload_not_empty",
                payload_length = payload_b64.len(),
                url = %header.url
            );
            return Err(Problem::malformed("POST-as-GET payload must be empty"));
        }

        Ok(AcmePostAsGet {
            header,
            pubkey,
            account,
        })
    }
}

/// A verified ACME POST whose payload may be **either** a document or empty.
///
/// The shape RFC 8555 §7.5.2 forces on the authorization resource: one URL
/// answers both a POST-as-GET (read the authorization) and a
/// `{"status": "deactivated"}` POST (relinquish it). [`AcmeRequest<T>`] cannot
/// serve it — an empty payload is not valid JSON for any `T` — and
/// [`AcmePostAsGet`] rejects the deactivation outright, so the handler needs to
/// see which of the two arrived.
pub struct AcmeOptionalPayload<T> {
    pub header: ProtectedHeader,
    /// `None` for a POST-as-GET, `Some` for a payload-carrying POST.
    pub payload: Option<T>,
    pub pubkey: Vec<u8>,
    pub account: Option<Account>,
}

impl<S, T> FromRequest<S> for AcmeOptionalPayload<T>
where
    S: Send + Sync,
    AppState: FromRef<S>,
    T: DeserializeOwned,
{
    type Rejection = Problem;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let (header, pubkey, account, payload_b64) = verify_jws(req, state).await?;

        let payload = if payload_b64.is_empty() {
            None
        } else {
            let payload_bytes = BASE64_URL_SAFE_NO_PAD.decode(&payload_b64).map_err(|_| {
                warn!(
                    event = "jws_payload_decode_failed",
                    payload_length = payload_b64.len()
                );
                Problem::malformed("Base64 payload invalid")
            })?;

            Some(serde_json::from_slice(&payload_bytes).map_err(|_| {
                warn!(
                    event = "jws_payload_parse_failed",
                    payload_length = payload_bytes.len()
                );
                Problem::malformed("Payload JSON invalid for this endpoint")
            })?)
        };

        Ok(AcmeOptionalPayload {
            header,
            payload,
            pubkey,
            account,
        })
    }
}

/// Maps a `SignatureError` to the `Problem` the extractor rejects with.
fn map_signature_error(error: SignatureError) -> Problem {
    match error {
        SignatureError::Malformed(detail) => {
            warn!(event = "signature_verification_malformed", detail = %detail);
            Problem::malformed(detail)
        }
        SignatureError::BadAlgorithm(detail) => {
            warn!(event = "signature_algorithm_unsupported", detail = %detail);
            Problem::bad_signature_algorithm(detail)
        }
        SignatureError::BadSignature(_) => {
            warn!(event = "signature_verification_failed");
            Problem::unauthorized("Signature JWS invalid")
        }
        SignatureError::Encoding(detail) => {
            error!(event = "signature_encoding_error", detail = %detail);
            Problem::server_internal(detail)
        }
    }
}
