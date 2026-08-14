use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderValue, header},
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};
use tracing::{debug, error, info, instrument, warn};

use crate::AppState;
use crate::error::Problem;
use crate::signer::RenewalWindow;
use crate::sqlite::nonce::now_secs;
use crate::sqlite::order::Order;

/// One day, in seconds: how far the window returned for a revoked certificate
/// is shifted into the past.
const ONE_DAY_SECONDS: i64 = 86_400;

/// `Retry-After` for an ordinary certificate: six hours, RFC 9773 §4.2's own
/// example value. §4.3.1 leaves the choice to the server, trading client
/// responsiveness against load; six hours is what a client would also fall back
/// to on a long-term error (§4.3.3).
const DEFAULT_RETRY_AFTER: &str = "21600";

/// `Retry-After` for a revoked certificate: one minute, §4.3.2's own floor
/// ("values under one minute could be treated as if they were one minute").
/// The window is already in the past, so there is nothing to wait for.
const REVOKED_RETRY_AFTER: &str = "60";

/// The suggested renewal window for a certificate, in epoch seconds (RFC 9773 §4.2).
///
/// A revoked certificate must be replaced immediately, resulting in a window entirely
/// in the past: a client comparing the current time to this window is already in it.
/// Otherwise, the window covers the last third of the validity period (from 2/3 to 3/4),
/// which leaves time for several attempts before expiration.
#[must_use]
pub fn calculate_suggested_window(
    not_before: i64,
    not_after: i64,
    is_revoked: bool,
    now: i64,
) -> RenewalWindow {
    if is_revoked {
        return RenewalWindow::new(now - ONE_DAY_SECONDS, now);
    }
    let duration = not_after - not_before;
    RenewalWindow::new(
        not_before + (duration * 2 / 3),
        not_before + (duration * 3 / 4),
    )
}

/// Handles ACME Renewal Information (ARI) queries (RFC 9773).
///
/// Unauthenticated, by design: RFC 9773 §4.1 explicitly describes an unauthenticated
/// `GET`, as the certificate identifier itself is public.
#[instrument(name = "get_renewal_info", skip_all, fields(cert_id = %id))]
pub async fn get_renewal_info(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Response, Problem> {
    info!(
        event = "renewal_info_requested",
        outcome = "progress",
        cert_id = %id
    );

    // certID = base64url(AKI keyIdentifier) "." base64url(serial), RFC 9773 §4.1.
    // Both halves are decoded, not just the serial: an identifier whose AKI does
    // not name the issuer of the certificate it claims is not an identifier for
    // that certificate, and answering anyway would let a caller learn a window
    // for someone else's certificate that happens to share a serial.
    let cert_id = crate::cert::parse_ari_cert_id(&id).map_err(|error| {
        warn!(event = "renewal_info_invalid_id_format", outcome = "failure", cert_id = %id, error = %error);
        Problem::malformed(format!("Invalid certID: {error}"))
    })?;
    let serial_hex = cert_id.serial_hex();

    let order = Order::find_by_cert_serial(&state.profile.name, &serial_hex, &state.database)
        .await
        .map_err(|error| {
            warn!(event = "renewal_info_lookup_error", outcome = "failure", error = %error);
            Problem::server_internal("Database error looking up certificate")
        })?
        // RFC 9773 does not define a status code for an unknown certID; we keep
        // the 400 + `malformed` that this codebase returns for any other unknown
        // resource (see `load_owned_order`), rather than an isolated 404.
        .ok_or_else(|| {
            warn!(event = "renewal_info_not_found", outcome = "failure", cert_serial = %serial_hex);
            Problem::malformed("Unknown certificate")
        })?;

    let certificate_pem = order.certificate.as_ref().ok_or_else(|| {
        debug!(event = "renewal_info_no_certificate", outcome = "success", order_id = %order.id);
        Problem::malformed("Order does not have a certificate")
    })?;

    let leaf_der = crate::cert::leaf_der_from_chain(certificate_pem).map_err(|error| {
        error!(event = "renewal_info_cert_parse_failed", outcome = "failure", error = %error);
        Problem::server_internal("Stored certificate is unparsable")
    })?;

    // Now that the certificate is in hand, hold the AKI half to account. A
    // certificate issued before this server's local CA emitted the extension has
    // no AKI to compare against — there, "cannot check" is not "reject", or
    // every certificate issued by an older build would become unqueryable.
    match crate::cert::ari_cert_id_parts(&leaf_der) {
        Ok((aki, _serial)) if aki != cert_id.aki => {
            warn!(event = "renewal_info_aki_mismatch", outcome = "failure", cert_id = %id, cert_serial = %serial_hex);
            return Err(Problem::malformed(
                "certID key identifier does not match the certificate",
            ));
        }
        Ok(_) => {}
        Err(error) => {
            debug!(
                event = "renewal_info_aki_unavailable",
                outcome = "advisory",
                cert_serial = %serial_hex,
                error = %error,
                "certificate carries no Authority Key Identifier; matching on serial alone"
            );
        }
    }

    let (not_before, not_after) = crate::cert::cert_validity(&leaf_der).map_err(|error| {
        error!(event = "renewal_info_cert_validity_parse_failed", outcome = "failure", error = %error);
        Problem::server_internal("Failed to parse certificate validity")
    })?;

    let now = now_secs();
    let revoked = order.revoked_at.is_some();

    // A revoked certificate needs replacing now, whatever anyone else thinks.
    // Checked before the backend is consulted rather than only on the fallback
    // paths: an upstream that has not yet noticed the revocation would otherwise
    // hand back a future window and talk the client out of renewing.
    let window = if revoked {
        calculate_suggested_window(not_before, not_after, true, now)
    } else {
        // A backend delegating to an upstream CA can ask *it* when to renew, which
        // beats any local guess — the upstream is the one that knows about its own
        // rate limits and planned revocations. `local_ca` keeps the trait's default
        // "no opinion", and an upstream that is unreachable or has none must not
        // fail the request, so both fall through to the local computation.
        match state.profile.signer.renewal_info(&leaf_der).await {
            Ok(Some(window)) => window,
            Ok(None) => calculate_suggested_window(not_before, not_after, false, now),
            Err(error) => {
                warn!(event = "renewal_info_upstream_failed", outcome = "failure", error = %error);
                calculate_suggested_window(not_before, not_after, false, now)
            }
        }
    };

    // §4.2: "A RenewalInfo object in which the end timestamp equals or precedes
    // the start timestamp is invalid. Servers MUST NOT serve such a response."
    // Enforced here rather than in each producer, so a backend cannot violate it
    // through us — a degenerate certificate (notAfter <= notBefore) reaches the
    // local computation just as easily as a misbehaving upstream does.
    if window.end <= window.start {
        error!(
            event = "renewal_info_invalid_window",
            outcome = "failure",
            cert_serial = %serial_hex,
            start = window.start,
            end = window.end,
        );
        return Err(Problem::server_internal(
            "Computed renewal window is invalid",
        ));
    }

    let mut suggested = serde_json::Map::new();
    suggested.insert(
        "start".to_string(),
        json!(crate::sqlite::order::rfc3339(window.start)),
    );
    suggested.insert(
        "end".to_string(),
        json!(crate::sqlite::order::rfc3339(window.end)),
    );

    let mut body = serde_json::Map::new();
    body.insert("suggestedWindow".to_string(), Value::Object(suggested));
    // §4.2, optional: "Clients SHOULD provide this URL to their operator, if
    // present." Only a delegating backend ever has one.
    if let Some(url) = window.explanation_url {
        body.insert("explanationURL".to_string(), Value::String(url));
    }

    let mut response = Json(Value::Object(body)).into_response();

    // RFC 9773 §4.3: this is "the desired (i.e., both requested minimum and
    // maximum) amount of time to wait", not merely a floor. A revoked
    // certificate's window is already in the past, so telling that client to
    // sleep a day before looking again would be actively unhelpful.
    let retry_after = if revoked {
        REVOKED_RETRY_AFTER
    } else {
        DEFAULT_RETRY_AFTER
    };
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static(retry_after));

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_suggested_window_covers_the_last_third_of_the_validity() {
        let window = calculate_suggested_window(1000, 4000, false, 5000);
        assert_eq!(window.start, 1000 + (3000 * 2 / 3));
        assert_eq!(window.end, 1000 + (3000 * 3 / 4));
        assert!(window.start < window.end, "the window must be non-empty");
        assert!(
            window.explanation_url.is_none(),
            "a locally computed window has nothing to explain"
        );
    }

    #[test]
    fn a_revoked_certificate_gets_a_window_entirely_in_the_past() {
        let now = 2000;
        let window = calculate_suggested_window(1000, 4000, true, now);
        assert_eq!(window.start, now - ONE_DAY_SECONDS);
        assert_eq!(window.end, now);
        assert!(
            window.end <= now,
            "a revoked certificate must be replaced immediately"
        );
    }

    /// Revocation overrides validity: a window calculated for a certificate
    /// still far from its expiration must nonetheless shift into the past
    /// once it is revoked.
    #[test]
    fn revocation_overrides_the_validity_based_window() {
        let now = 2_000_000;
        let fresh = calculate_suggested_window(1_000_000, 9_000_000, false, now);
        let revoked = calculate_suggested_window(1_000_000, 9_000_000, true, now);

        assert!(
            fresh.start > now,
            "without revocation, the window is in the future"
        );
        assert!(revoked.start < now && revoked.end <= now);
    }
}
