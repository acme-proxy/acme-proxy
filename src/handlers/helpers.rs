use std::net::IpAddr;
use std::sync::Arc;

use rcgen::{CertificateSigningRequestParams, DnType, DnValue, SanType};
use rustls_pki_types::CertificateSigningRequestDer;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tracing::{error, instrument, warn};

use crate::challenge::ChallengeError;
use crate::error::Problem;
use crate::filter::{FilterChain, FilterError, IdentifierContext, IdentifierStage};
use crate::sqlite::{
    account::Account,
    authz::{Authorization, Challenge},
    db::Database,
    nonce::now_secs,
    order::{Identifier, Order},
};

/// Runs the filter chain's identifier hook and maps a refusal to the ACME error
/// the stage calls for.
#[instrument(name = "check_identifiers", skip_all)]
pub(crate) async fn check_identifiers(
    filter: &FilterChain,
    client_ip: Option<IpAddr>,
    account_id: &str,
    stage: IdentifierStage,
    identifiers: &[Identifier],
) -> Result<(), Problem> {
    let context = IdentifierContext {
        client_ip,
        account_id,
        stage,
        identifiers,
    };

    match filter.check_identifiers(&context).await {
        Ok(()) => Ok(()),
        Err(FilterError::Denied(detail)) => Err(match stage {
            IdentifierStage::NewOrder => Problem::rejected_identifier(detail),
            IdentifierStage::Csr => Problem::bad_csr(detail),
        }),
        Err(FilterError::Internal(_)) => Err(Problem::server_internal("Request filtering failed")),
    }
}

/// Maps a failed challenge validation to the ACME error that describes it.
pub(crate) fn challenge_problem(error: &ChallengeError) -> Problem {
    match error {
        ChallengeError::Connection(detail) => Problem::connection(detail.clone()),
        ChallengeError::Dns(detail) => Problem::dns(detail.clone()),
        ChallengeError::IncorrectResponse(detail) => Problem::incorrect_response(detail.clone()),
        ChallengeError::Tls(detail) => Problem::tls(detail.clone()),
        ChallengeError::Unauthorized(detail) => Problem::access_denied(detail.clone()),
        ChallengeError::Internal(_) => Problem::server_internal("Challenge validation failed"),
    }
}

/// Parses a PKCS#10 CSR, which also verifies its own self-signature.
///
/// Separated from [`csr_identifiers`] because `post_finalize` performs two checks
/// on the same CSR: parsing it once avoids reparsing it.
pub(crate) fn parse_csr(csr_der: &[u8]) -> Result<CertificateSigningRequestParams, Problem> {
    let der = CertificateSigningRequestDer::from(csr_der.to_vec());
    CertificateSigningRequestParams::from_der(&der).map_err(|error| {
        warn!(event = "csr_parse_failed", error = %error);
        Problem::bad_csr("CSR is unparsable")
    })
}

/// RFC 8555 §7.4: "The CSR MUST indicate the exact same set of requested
/// identifiers as the initial newOrder request."
///
/// This check lives **here**, in the handler, and not in a backend.
/// `LocalCa::issue` has always done it, but it is the only backend doing so:
/// `custom` passes the CSR to an operator script which is not told to verify it,
/// and `acme_proxy` relays it to an upstream CA which only sees *this* server's
/// account and doesn't know which names the local client has proven.
/// With either of them, an account authorized for one name could get a certificate
/// for any other name. The backend check remains as defense in depth — `admin::ops`
/// and `cli::order` call `issue` directly, so a backend must remain secure on its
/// own — but this check makes the guarantee independent of the backend.
///
/// Raw comparison, without renormalizing the CSR side: the order identifiers
/// have already been normalized by `post_new_order`, and normalizing here
/// would allow signing a leaf bearing `EXAMPLE.COM.` when the check compared
/// `example.com`. This is also what keeps this check and the one in `LocalCa::issue`
/// in agreement byte for byte.
pub(crate) fn check_csr_matches_order(
    csr: &CertificateSigningRequestParams,
    identifiers: &[Identifier],
) -> Result<(), Problem> {
    // A SAN that is not a DNS name would not be seen by the set comparison
    // below, and would therefore travel uninspected all the way into the
    // signed leaf.
    if let Some(other) = csr
        .params
        .subject_alt_names
        .iter()
        .find(|san| !matches!(san, SanType::DnsName(_)))
    {
        warn!(event = "csr_non_dns_san", san = ?other);
        return Err(Problem::bad_csr(
            "CSR carries a subject alternative name that is not a DNS name",
        ));
    }

    let csr_dns: std::collections::BTreeSet<&str> = csr
        .params
        .subject_alt_names
        .iter()
        .filter_map(|san| match san {
            SanType::DnsName(name) => Some(name.as_str()),
            _ => None,
        })
        .collect();
    let want_dns: std::collections::BTreeSet<&str> = identifiers
        .iter()
        .filter(|id| id.typ == "dns")
        .map(|id| id.value.as_str())
        .collect();

    if csr_dns != want_dns {
        warn!(event = "csr_identifier_mismatch", csr = ?csr_dns, order = ?want_dns);
        return Err(Problem::bad_csr(
            "CSR does not request the order's identifiers",
        ));
    }

    // `CertificateSigningRequestParams::from_der` copies the entire distinguished name
    // from the CSR into `params`, and `signed_by` writes it into the leaf: a CN
    // naming a domain the order never authorized ends up asserted by
    // a certificate that this CA signed. Verifiers ignore the CN since
    // RFC 2818 was replaced, but "ignored by most" is not "unasserted".
    //
    // Only CNs *shaped like a DNS name* are checked. A CN is also, very
    // ordinarily, a human label — rcgen puts "rcgen self signed
    // cert" by default — and this is exactly why `filter::identifiers`
    // already excludes `cn` from its `allow` rules (`SUBJECT_ONLY_TYPES`) while
    // leaving it reachable by `deny`. Refusing any label would break legitimate
    // clients without protecting anything: what is dangerous is a CN
    // that an old verifier could read as a hostname.
    //
    // `LocalCa::issue` goes further and empties the whole distinguished name; this check
    // is what covers backends which transmit the CSR as-is
    // (`custom`, `acme_proxy`).
    if let Some(common_name) = csr.params.distinguished_name.get(&DnType::CommonName)
        && let Some(text) = dn_text(common_name)
    {
        let candidate = normalize_dns_name(&text);
        if looks_like_dns_name(&candidate) && !want_dns.contains(candidate.as_str()) {
            warn!(event = "csr_common_name_mismatch", common_name = %candidate);
            return Err(Problem::bad_csr(
                "CSR common name is a domain the order does not cover",
            ));
        }
    }

    Ok(())
}

/// Whether a subject `CommonName` reads as a host name rather than a human
/// label — the distinction [`check_csr_matches_order`] uses to decide whether a
/// CN is a name being asserted or just descriptive text.
fn looks_like_dns_name(value: &str) -> bool {
    !value.is_empty()
        && value.contains('.')
        && !value.chars().any(|c| c.is_ascii_whitespace())
        && well_formed_name(value)
}

/// Projects everything a CSR asks to have certified into the shared
/// [`Identifier`] shape, so one policy list covers all of it.
pub(crate) fn csr_identifiers(csr: &CertificateSigningRequestParams) -> Vec<Identifier> {
    let mut identifiers: Vec<Identifier> = csr
        .params
        .subject_alt_names
        .iter()
        .map(|san| match san {
            SanType::DnsName(name) => Identifier::dns(normalize_dns_name(name.as_str())),
            SanType::IpAddress(ip) => Identifier::new("ip", ip.to_canonical().to_string()),
            SanType::Rfc822Name(name) => Identifier::new("email", name.as_str().to_string()),
            SanType::URI(uri) => Identifier::new("uri", uri.as_str().to_string()),
            other => Identifier::new("other", format!("{other:?}")),
        })
        .collect();

    if let Some(common_name) = csr.params.distinguished_name.get(&DnType::CommonName) {
        identifiers.push(match dn_text(common_name) {
            Some(value) => Identifier::new("cn", normalize_dns_name(&value)),
            None => Identifier::new("other", format!("{common_name:?}")),
        });
    }

    identifiers
}

/// Canonicalizes a DNS name for comparison: lowercased, with one trailing dot
/// removed.
#[must_use]
pub fn normalize_dns_name(value: &str) -> String {
    let trimmed = value.strip_suffix('.').unwrap_or(value);
    trimmed.to_ascii_lowercase()
}

/// Whether an identifier names every host under a domain (RFC 8555 §7.1.3).
#[must_use]
pub fn is_wildcard(value: &str) -> bool {
    value.starts_with("*.")
}

/// The longest a DNS name may be, in presentation form (RFC 1035 §2.3.4's
/// 255-octet wire limit less the root label and the length octet of the first).
const MAX_DNS_NAME: usize = 253;

/// The longest a single DNS label may be (RFC 1035 §2.3.4).
const MAX_DNS_LABEL: usize = 63;

/// Whether a `dns` identifier is a shape this server can act on.
///
/// Two rules, and the second is load-bearing beyond mere tidiness.
///
/// The wildcard rule (§7.1.3): a `*` is legal only as a single leading `*.`.
///
/// The syntax rule: what is left has to actually be a DNS name — bounded
/// length, non-empty labels drawn from letters, digits, `-` and `_`, with no
/// label starting or ending in `-`. Without it an identifier may carry `,`,
/// ` `, `@`, `/`, `#` or a control character, and two subsystems read the
/// resulting string as something other than one opaque name:
///
/// - `filter::custom` joins the identifiers with `,` into
///   `ACME_FILTER_IDENTIFIERS`, so a name *containing* a comma reads to an
///   operator script as two names.
/// - `challenge::http_01` builds `http://{name}/.well-known/…` and hands it to
///   `Url::parse`, which resolves `internal.corp/` to the host `internal.corp`
///   and `a@internal.corp` to userinfo plus that host — neither of which the
///   anchored `deny` regex `internal\.corp` matches. With `challenge.bypass`
///   on, where `[filter]` is the only access control there is, that is a
///   deny-list bypass.
///
/// `_` is deliberately allowed: this server exists to serve internal networks,
/// where underscore labels are ordinary. The point is to reject delimiters and
/// control characters, not to enforce a public CA's hostname policy.
#[must_use]
pub fn well_formed_name(value: &str) -> bool {
    let name = match value.strip_prefix("*.") {
        Some(rest) => rest,
        None => value,
    };
    // Any remaining `*` is a wildcard somewhere it is not allowed.
    !name.contains('*') && is_dns_name(name)
}

/// Whether `name` is a syntactically valid DNS name in presentation form.
fn is_dns_name(name: &str) -> bool {
    if name.is_empty() || name.len() > MAX_DNS_NAME {
        return false;
    }
    // One trailing dot is the root label and is normalized away before this is
    // ever compared; anything else empty is a malformed name.
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.is_empty() {
        return false;
    }
    name.split('.').all(is_dns_label)
}

/// Whether one dot-separated component is a valid label.
fn is_dns_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= MAX_DNS_LABEL
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Validates an account's `contact` URLs (RFC 8555 §7.3).
///
/// §7.3: "The server SHOULD validate that the contact URLs in the `contact`
/// field are valid and supported by the server. If the server validates contact
/// URLs, it MUST support the `mailto` scheme." This server supports `mailto:`
/// and nothing else — there is no other scheme it could act on — so anything
/// else is `unsupportedContact`.
///
/// Within `mailto:`, §7.3 names two shapes to reject: "Clients MUST NOT provide
/// a `mailto` URL in the `contact` field that contains `hfields` [RFC6068] or
/// more than one `addr-spec` in the `to` component. If a server encounters a
/// `mailto` contact URL that does not meet these criteria, then it SHOULD
/// reject it as invalid." Both are `invalidContact`; the distinction from
/// `unsupportedContact` is deliberate, since only one of the two tells the
/// client to try a different scheme.
///
/// Deliberately *not* a deliverability check: whether mail reaches the address
/// is not something a syntax check can answer, and refusing a valid-but-unusual
/// local-part would lock an operator out of their own account.
pub(crate) fn validate_contacts(contacts: &[String]) -> Result<(), Problem> {
    match contact_shape_error(contacts) {
        None => Ok(()),
        Some(rejection) if rejection.unsupported => {
            Err(Problem::unsupported_contact(rejection.detail))
        }
        Some(rejection) => Err(Problem::invalid_contact(rejection.detail)),
    }
}

/// A contact RFC 8555 §7.3 refuses, and which of its two refusals applies.
pub(crate) struct ContactRejection {
    /// `true` maps to `unsupportedContact`, `false` to `invalidContact`. The
    /// distinction is deliberate: only one of the two tells the client to try
    /// a different scheme.
    pub unsupported: bool,
    pub detail: String,
}

/// The shape check behind [`validate_contacts`], returning the reason rather
/// than a [`Problem`].
///
/// Split out because `Problem`'s fields are private, so the web admin — which
/// answers in its own error shape and not in `application/problem+json` —
/// could not read the detail back out of one. Sharing the check rather than
/// writing a second one is what keeps `PATCH /api/accounts/{id}` from
/// accepting a contact `newAccount` would have refused.
pub(crate) fn contact_shape_error(contacts: &[String]) -> Option<ContactRejection> {
    fn unsupported(detail: String) -> Option<ContactRejection> {
        Some(ContactRejection {
            unsupported: true,
            detail,
        })
    }
    fn invalid(detail: String) -> Option<ContactRejection> {
        Some(ContactRejection {
            unsupported: false,
            detail,
        })
    }

    for contact in contacts {
        let Some(rest) = contact.strip_prefix("mailto:") else {
            let scheme = contact.split_once(':').map_or("(none)", |(s, _)| s);
            warn!(event = "contact_scheme_unsupported", scheme = %scheme);
            return unsupported(format!(
                "Contact {contact} uses an unsupported scheme; only mailto: is supported"
            ));
        };

        // A control character is never part of an address, and this value does
        // not stay inside a JSON document: it is rendered into the `notify`
        // subsystem's templates, which are `.j2` precisely so auto-escaping is
        // *off*. A `mailto:a@b.test\nBcc: …` would otherwise be accepted,
        // stored, and echoed into a message body verbatim.
        if rest.chars().any(|c| c.is_control()) {
            warn!(event = "contact_has_control_characters");
            return invalid(format!(
                "Contact {contact:?} carries a control character, which is not part of an address"
            ));
        }

        // RFC 6068 §2: `hfields` is everything after a `?`.
        if rest.contains('?') {
            warn!(event = "contact_has_hfields");
            return invalid(format!(
                "Contact {contact} carries hfields, which RFC 8555 §7.3 forbids"
            ));
        }

        // RFC 6068 §2: multiple addresses in the `to` component are
        // comma-separated.
        if rest.contains(',') {
            warn!(event = "contact_has_multiple_addresses");
            return invalid(format!(
                "Contact {contact} names more than one address; RFC 8555 §7.3 allows one"
            ));
        }

        // A `mailto:` with nothing to mail, or no domain to mail it to, is not
        // an address anyone could reach.
        let Some((local, domain)) = rest.rsplit_once('@') else {
            warn!(event = "contact_not_an_address");
            return invalid(format!("Contact {contact} is not an email address"));
        };
        if local.is_empty() || domain.is_empty() || !domain.contains('.') {
            warn!(event = "contact_address_incomplete");
            return invalid(format!("Contact {contact} is not a complete email address"));
        }
    }

    None
}

/// The text of a distinguished-name value, when rcgen exposes it as such.
pub(crate) fn dn_text(value: &DnValue) -> Option<String> {
    match value {
        DnValue::Utf8String(text) => Some(text.clone()),
        DnValue::Ia5String(text) => Some(text.as_str().to_string()),
        DnValue::PrintableString(text) => Some(text.as_str().to_string()),
        DnValue::TeletexString(text) => Some(text.as_str().to_string()),
        _ => None,
    }
}

/// Resolves the account that signed the request, within the endpoint it
/// reached: an account registered at another profile is simply unknown here.
#[instrument(name = "signer_account", skip_all)]
pub(crate) async fn signer_account(
    cached: Option<Account>,
    profile: &str,
    pubkey: &[u8],
    database: &Arc<Database>,
) -> Result<Account, Problem> {
    let account = match cached {
        Some(account) => account,
        None => Account::find_by_pubkey(profile, pubkey, database)
            .await
            .map_err(|error| {
                error!(event = "account_lookup_failed", error = %error);
                Problem::server_internal("Account lookup failed")
            })?
            .ok_or_else(|| Problem::account_does_not_exist("Unknown account"))?,
    };

    if account.status == "deactivated" {
        warn!(event = "deactivated_account_request", account_id = %account.id);
        return Err(Problem::unauthorized("Account is deactivated"));
    }
    Ok(account)
}

/// Loads order `id` and verifies it belongs to the account that signed the request.
#[instrument(name = "load_owned_order", skip_all, fields(order_id = %id, account_id = %account.id))]
pub(crate) async fn load_owned_order(
    id: &str,
    account: &Account,
    database: &Arc<Database>,
) -> Result<Order, Problem> {
    let order = Order::find_by_id(id, database)
        .await
        .map_err(|error| {
            error!(event = "order_lookup_failed", order_id = %id, error = %error);
            Problem::server_internal("Order lookup failed")
        })?
        .ok_or_else(|| Problem::malformed("Unknown order"))?;

    // An order belongs to the endpoint it was placed at. Refusing it as
    // *unknown* rather than unauthorized is deliberate: the two answers differ,
    // so anything else would let one endpoint's client probe another's for
    // which order ids exist.
    if order.profile != account.profile {
        warn!(
            event = "order_profile_mismatch",
            order_id = %id,
            order_profile = %order.profile,
            request_profile = %account.profile
        );
        return Err(Problem::malformed("Unknown order"));
    }

    if order.account_id != account.id {
        warn!(event = "order_ownership_mismatch", order_id = %id, account_id = %account.id);
        return Err(Problem::unauthorized(
            "Order belongs to a different account",
        ));
    }

    if order.status != "valid" && order.expires <= now_secs() {
        warn!(event = "order_expired", order_id = %id, expires = order.expires);
        return Err(Problem::malformed("Order has expired"));
    }
    Ok(order)
}

/// Loads authorization `id` and the order it belongs to, verifying ownership.
#[instrument(name = "load_owned_authz", skip_all, fields(authz_id = %id))]
pub(crate) async fn load_owned_authz(
    id: &str,
    account: &Account,
    database: &Arc<Database>,
) -> Result<(Authorization, Order), Problem> {
    let authz = Authorization::find_by_id(id, database)
        .await
        .map_err(|error| {
            error!(event = "authz_lookup_failed", authz_id = %id, error = %error);
            Problem::server_internal("Authorization lookup failed")
        })?
        .ok_or_else(|| Problem::malformed("Unknown authorization"))?;

    let order = load_owned_order(&authz.order_id, account, database).await?;
    Ok((authz, order))
}

/// Loads challenge `id`, its authorization, and its order, verifying ownership.
#[instrument(name = "load_owned_challenge", skip_all, fields(challenge_id = %id))]
pub(crate) async fn load_owned_challenge(
    id: &str,
    account: &Account,
    database: &Arc<Database>,
) -> Result<(Challenge, Authorization, Order), Problem> {
    let challenge = Challenge::find_by_id(id, database)
        .await
        .map_err(|error| {
            error!(event = "challenge_lookup_failed", challenge_id = %id, error = %error);
            Problem::server_internal("Challenge lookup failed")
        })?
        .ok_or_else(|| Problem::malformed("Unknown challenge"))?;

    let (authz, order) = load_owned_authz(&challenge.authz_id, account, database).await?;
    Ok((challenge, authz, order))
}

/// Fetches an order's authorization ids.
#[instrument(name = "order_authz_ids", skip_all, fields(order_id = %order_id))]
pub(crate) async fn order_authz_ids(
    order_id: &str,
    database: &Arc<Database>,
) -> Result<Vec<String>, Problem> {
    Ok(Authorization::find_by_order(order_id, database)
        .await
        .map_err(|error| {
            error!(event = "authz_list_failed", order_id = %order_id, error = %error);
            Problem::server_internal("Authorization lookup failed")
        })?
        .into_iter()
        .map(|authz| authz.id)
        .collect())
}

/// Parses an RFC3339 datetime string into epoch seconds.
pub(crate) fn parse_rfc3339(field: &str, value: &str) -> Result<i64, Problem> {
    OffsetDateTime::parse(value, &Rfc3339)
        .map(time::OffsetDateTime::unix_timestamp)
        .map_err(|_| {
            warn!(event = "order_datetime_invalid", field = %field, value = %value);
            Problem::malformed("Invalid notBefore/notAfter datetime")
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_shapes_are_recognised_and_the_rest_refused() {
        assert!(is_wildcard("*.example.com"));
        assert!(well_formed_name("*.example.com"));

        assert!(!is_wildcard("example.com"));
        assert!(well_formed_name("example.com"));

        for bad in [
            "*example.com",
            "*.*.example.com",
            "a.*.example.com",
            "*",
            "*.",
        ] {
            assert!(!well_formed_name(bad), "{bad} must not be well formed");
        }
        assert!(!is_wildcard("*example.com"));
    }

    /// The rule that keeps a `dns` identifier one opaque name.
    ///
    /// Each rejected value below is not merely untidy: `filter::custom` joins
    /// identifiers with `,` and `challenge::http_01` feeds the name to
    /// `Url::parse`, so a delimiter here means one subsystem reads a different
    /// name than the one being certified.
    #[test]
    fn a_dns_identifier_that_is_not_a_dns_name_is_refused() {
        for good in [
            "example.com",
            "a.example.com",
            "EXAMPLE.com",
            "host-1.example.com",
            // Underscore labels are ordinary on the internal networks this
            // server exists to serve, and are deliberately allowed.
            "_acme.example.com",
            "single-label",
            "1.2.3.4",
            "*.sub.example.com",
        ] {
            assert!(well_formed_name(good), "{good} must be well formed");
        }

        for bad in [
            // The delimiter cases, each with a subsystem that misreads it.
            "a.example.com,b.example.com",
            "internal.corp/",
            "user@internal.corp",
            "example.com#frag",
            "example.com?q=1",
            "example .com",
            "example.com:8080",
            // Control characters: a log-injection and template vector.
            "example.com\n",
            "example.com\r\nX",
            "example\t.com",
            // Malformed label shapes.
            "",
            ".",
            "..",
            "a..b",
            ".example.com",
            "-example.com",
            "example-.com",
            "a.-b.com",
        ] {
            assert!(!well_formed_name(bad), "{bad:?} must not be well formed");
        }
    }

    #[test]
    fn a_dns_identifier_longer_than_the_protocol_allows_is_refused() {
        let label = "a".repeat(MAX_DNS_LABEL);
        assert!(well_formed_name(&format!("{label}.example.com")));

        let too_long_label = "a".repeat(MAX_DNS_LABEL + 1);
        assert!(!well_formed_name(&format!("{too_long_label}.example.com")));

        // 253 characters exactly, then one more.
        let name = std::iter::repeat_n(label.as_str(), 4)
            .collect::<Vec<_>>()
            .join(".");
        assert_eq!(name.len(), 255);
        assert!(!well_formed_name(&name));

        let fits = format!("{}.com", &name[..MAX_DNS_NAME - 4]);
        assert_eq!(fits.len(), MAX_DNS_NAME);
        assert!(well_formed_name(&fits));
    }

    /// A trailing dot is the root label; `normalize_dns_name` strips it, and
    /// this must not reject a name that arrives before that happens.
    #[test]
    fn a_trailing_root_label_is_accepted_but_a_bare_dot_is_not() {
        assert!(well_formed_name("example.com."));
        assert!(!well_formed_name("example.com.."));
        assert!(!well_formed_name("."));
    }

    /// A control character in a contact reaches the `notify` templates, which
    /// are `.j2` precisely so auto-escaping is off.
    #[test]
    fn a_contact_carrying_a_control_character_is_refused() {
        for bad in [
            "mailto:alice@example.com\nBcc: attacker@evil.test",
            "mailto:alice@example.com\r\n",
            "mailto:al\tice@example.com",
            "mailto:alice@example.com\u{0}",
        ] {
            let rejection = contact_shape_error(&[bad.to_string()])
                .unwrap_or_else(|| panic!("{bad:?} must be refused"));
            // `invalidContact`, not `unsupportedContact`: the scheme is right,
            // the address is not.
            assert!(!rejection.unsupported, "{bad:?}");
        }

        assert!(contact_shape_error(&["mailto:alice@example.com".to_string()]).is_none());
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
            let value = challenge_problem(&error).to_value();
            assert_eq!(value["type"], typ);
            assert_eq!(value["status"], status);
            assert_eq!(value["detail"], error.detail());
        }

        let internal = challenge_problem(&ChallengeError::Internal("no validator".into()));
        let value = internal.to_value();
        assert_eq!(value["type"], "urn:ietf:params:acme:error:serverInternal");
        assert_eq!(value["status"], 500);
        assert!(!value["detail"].as_str().unwrap().contains("no validator"));
    }

    fn csr_with(sans: Vec<SanType>, common_name: Option<&str>) -> Vec<u8> {
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::default();
        params.subject_alt_names = sans;
        params.distinguished_name = rcgen::DistinguishedName::new();
        if let Some(name) = common_name {
            params.distinguished_name.push(DnType::CommonName, name);
        }
        params.serialize_request(&key_pair).unwrap().der().to_vec()
    }

    fn find<'a>(identifiers: &'a [Identifier], typ: &str) -> Vec<&'a str> {
        identifiers
            .iter()
            .filter(|id| id.typ == typ)
            .map(|id| id.value.as_str())
            .collect()
    }

    #[test]
    fn csr_identifiers_projects_every_san_type() {
        let der = csr_with(
            vec![
                SanType::DnsName("host.example.com".try_into().unwrap()),
                SanType::IpAddress("10.0.0.1".parse().unwrap()),
                SanType::Rfc822Name("someone@example.com".try_into().unwrap()),
                SanType::URI("https://example.com/x".try_into().unwrap()),
            ],
            None,
        );

        let identifiers = csr_identifiers(&parse_csr(&der).unwrap());
        assert_eq!(find(&identifiers, "dns"), vec!["host.example.com"]);
        assert_eq!(find(&identifiers, "ip"), vec!["10.0.0.1"]);
        assert_eq!(find(&identifiers, "email"), vec!["someone@example.com"]);
        assert_eq!(find(&identifiers, "uri"), vec!["https://example.com/x"]);
    }

    #[test]
    fn csr_identifiers_renders_ipv6_addresses() {
        let der = csr_with(
            vec![SanType::IpAddress("2001:db8::1".parse().unwrap())],
            None,
        );
        assert_eq!(
            find(&csr_identifiers(&parse_csr(&der).unwrap()), "ip"),
            vec!["2001:db8::1"]
        );
    }

    #[test]
    fn csr_identifiers_includes_the_common_name() {
        let der = csr_with(
            vec![SanType::DnsName("ok.example.com".try_into().unwrap())],
            Some("secret.internal.example.com"),
        );

        let identifiers = csr_identifiers(&parse_csr(&der).unwrap());
        assert_eq!(find(&identifiers, "dns"), vec!["ok.example.com"]);
        assert_eq!(
            find(&identifiers, "cn"),
            vec!["secret.internal.example.com"]
        );
    }

    #[test]
    fn csr_identifiers_omits_an_absent_common_name() {
        let der = csr_with(
            vec![SanType::DnsName("ok.example.com".try_into().unwrap())],
            None,
        );
        assert!(find(&csr_identifiers(&parse_csr(&der).unwrap()), "cn").is_empty());
    }

    #[test]
    fn parse_csr_rejects_garbage() {
        assert!(parse_csr(&[0xde, 0xad, 0xbe, 0xef]).is_err());
    }

    use crate::testutil::dns_identifiers as dns;

    #[test]
    fn a_csr_matching_the_order_exactly_is_accepted() {
        let der = csr_with(
            vec![
                SanType::DnsName("a.example.com".try_into().unwrap()),
                SanType::DnsName("b.example.com".try_into().unwrap()),
            ],
            None,
        );
        // The order of SANs must not matter: the comparison is on
        // sets, not on lists.
        let identifiers = dns(&["b.example.com", "a.example.com"]);
        assert!(check_csr_matches_order(&parse_csr(&der).unwrap(), &identifiers).is_ok());
    }

    #[test]
    fn a_csr_naming_another_domain_is_refused() {
        let der = csr_with(
            vec![SanType::DnsName("victim.example".try_into().unwrap())],
            None,
        );
        let value = check_csr_matches_order(&parse_csr(&der).unwrap(), &dns(&["a.example.com"]))
            .unwrap_err()
            .to_value();
        assert_eq!(value["type"], "urn:ietf:params:acme:error:badCSR");
        assert_eq!(value["status"], 400);
    }

    #[test]
    fn a_csr_naming_more_than_the_order_is_refused() {
        // RFC 8555 §7.4 demande « the exact same set » : un sur-ensemble est un
        // refus, pas une intersection acceptable.
        let der = csr_with(
            vec![
                SanType::DnsName("a.example.com".try_into().unwrap()),
                SanType::DnsName("extra.example.com".try_into().unwrap()),
            ],
            None,
        );
        assert!(
            check_csr_matches_order(&parse_csr(&der).unwrap(), &dns(&["a.example.com"])).is_err()
        );
    }

    #[test]
    fn a_csr_naming_less_than_the_order_is_refused() {
        let der = csr_with(
            vec![SanType::DnsName("a.example.com".try_into().unwrap())],
            None,
        );
        assert!(
            check_csr_matches_order(
                &parse_csr(&der).unwrap(),
                &dns(&["a.example.com", "b.example.com"]),
            )
            .is_err()
        );
    }

    #[test]
    fn a_csr_smuggling_a_non_dns_san_is_refused() {
        // The DNS name is the one that was ordered; it is the IP address
        // smuggled in beside it that nothing else would ever look at.
        let der = csr_with(
            vec![
                SanType::DnsName("a.example.com".try_into().unwrap()),
                SanType::IpAddress("10.0.0.1".parse().unwrap()),
            ],
            None,
        );
        assert!(
            check_csr_matches_order(&parse_csr(&der).unwrap(), &dns(&["a.example.com"])).is_err()
        );
    }

    #[test]
    fn a_csr_whose_common_name_is_not_an_order_identifier_is_refused() {
        let der = csr_with(
            vec![SanType::DnsName("a.example.com".try_into().unwrap())],
            Some("victim.example"),
        );
        assert!(
            check_csr_matches_order(&parse_csr(&der).unwrap(), &dns(&["a.example.com"])).is_err()
        );
    }

    #[test]
    fn a_csr_whose_common_name_is_an_order_identifier_is_accepted() {
        let der = csr_with(
            vec![SanType::DnsName("a.example.com".try_into().unwrap())],
            Some("a.example.com"),
        );
        assert!(
            check_csr_matches_order(&parse_csr(&der).unwrap(), &dns(&["a.example.com"])).is_ok()
        );
    }

    #[test]
    fn a_common_name_that_is_a_human_label_is_left_alone() {
        // rcgen sets this one by default, and `filter::identifiers` excludes
        // `cn` from its `allow` rules for exactly this reason: it is not a name
        // the certificate covers, it is prose.
        for label in ["rcgen self signed cert", "ACME client", "no-dot-label"] {
            let der = csr_with(
                vec![SanType::DnsName("a.example.com".try_into().unwrap())],
                Some(label),
            );
            assert!(
                check_csr_matches_order(&parse_csr(&der).unwrap(), &dns(&["a.example.com"]))
                    .is_ok(),
                "{label} should not be read as a host name"
            );
        }
    }

    #[test]
    fn common_names_are_recognised_as_host_names_or_not() {
        assert!(looks_like_dns_name("a.example.com"));
        assert!(looks_like_dns_name("*.example.com"));

        assert!(!looks_like_dns_name(""));
        assert!(!looks_like_dns_name("localhost"));
        assert!(!looks_like_dns_name("rcgen self signed cert"));
        assert!(!looks_like_dns_name("a.*.example.com"));
    }

    #[test]
    fn a_wildcard_csr_matching_its_order_is_accepted() {
        // `post_new_order` a déjà refusé l'identifiant joker si `dns-01` n'est
        // pas activé ; ici l'égalité suffit à l'épingler à la commande.
        let der = csr_with(
            vec![SanType::DnsName("*.example.com".try_into().unwrap())],
            None,
        );
        assert!(
            check_csr_matches_order(&parse_csr(&der).unwrap(), &dns(&["*.example.com"])).is_ok()
        );
    }

    #[test]
    fn a_csr_differing_only_in_case_is_refused() {
        // Comparaison brute : renormaliser ici laisserait signer une feuille
        // portant la forme non normalisée qui n'a jamais été comparée.
        let der = csr_with(
            vec![SanType::DnsName("A.Example.COM".try_into().unwrap())],
            None,
        );
        assert!(
            check_csr_matches_order(&parse_csr(&der).unwrap(), &dns(&["a.example.com"])).is_err()
        );
    }

    #[test]
    fn dn_text_reads_the_string_encodings() {
        assert_eq!(
            dn_text(&DnValue::Utf8String("a.example.com".to_string())).as_deref(),
            Some("a.example.com")
        );
        assert_eq!(
            dn_text(&DnValue::Ia5String("b.example.com".try_into().unwrap())).as_deref(),
            Some("b.example.com")
        );
        assert_eq!(
            dn_text(&DnValue::PrintableString(
                "c.example.com".try_into().unwrap()
            ))
            .as_deref(),
            Some("c.example.com")
        );
        assert_eq!(
            dn_text(&DnValue::TeletexString("d.example.com".try_into().unwrap())).as_deref(),
            Some("d.example.com")
        );
    }

    #[test]
    fn an_unreadable_common_name_becomes_an_other_identifier() {
        let value = DnValue::BmpString("e.example.com".try_into().unwrap());
        assert!(dn_text(&value).is_none());
    }
}
