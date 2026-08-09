use std::borrow::Cow;

use axum::{
    Json,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};

/// An ACME error, rendered as an RFC 8555 §6.7 `application/problem+json`
/// document:
///
/// ```json
/// { "type": "urn:ietf:params:acme:error:malformed", "detail": "…", "status": 400 }
/// ```
///
/// This struct represents ACME protocol errors that are returned to clients
/// in the standardized RFC 8555 problem+json format. It implements the `IntoResponse`
/// trait to convert errors into proper HTTP responses.
///
/// ## ACME Protocol Compliance
///
/// Following RFC 8555, each error has:
/// - A `type` field with URN format identifying the error type
/// - A `detail` field with human-readable description
/// - A `status` field with HTTP status code
///
/// ## Error Types
///
/// - `malformed`: Request format issues (HTTP 400)
/// - `bad_nonce`: Invalid or expired nonce (HTTP 400)
/// - `unauthorized`: Signature verification failures (HTTP 401)
/// - `server_internal`: Internal server errors (HTTP 500)
/// - `account_does_not_exist`: Referenced account not found (HTTP 400)
/// - `order_not_ready`: Finalize attempted on a non-`ready` order (HTTP 403)
/// - `bad_csr`: Unacceptable finalize CSR (HTTP 400)
/// - `unsupported_identifier`: Unsupported newOrder identifier type (HTTP 400)
/// - `rejected_identifier`: Identifier refused by server policy (HTTP 403)
/// - `access_denied`: Request blocked by a filter (HTTP 403)
/// - `external_account_required`: newAccount missing a required EAB (HTTP 400)
/// - `already_revoked`: Certificate already revoked (HTTP 400)
/// - `bad_revocation_reason`: Unsupported `CRLReason` code (HTTP 400)
/// - `key_change_conflict`: keyChange new key belongs to another account (HTTP 409)
/// - `unsupported_media_type`: body was not `application/jose+json` (HTTP 415)
/// - `method_not_allowed`: resource read with the wrong method, e.g. a bare GET (HTTP 405)
/// - `not_found`: nothing routed at this path (HTTP 404)
///
/// ## Usage
///
/// Used both as the `AcmeRequest` extractor's rejection and as the error arm of
/// handler results, so every failure reaches the client in the shape ACME
/// clients expect.
///
/// ## Owned details
///
/// `detail` is a [`Cow<'static, str>`] rather than a `&'static str`: most
/// call sites pass a literal (borrowed, no allocation), but the `filter`
/// subsystem needs to name the offending value — "identifier evil.example.com
/// is denied by policy" — which can only be built at runtime.
#[derive(Debug)]
pub struct Problem {
    status: StatusCode,
    /// The `urn:ietf:params:acme:error:*` problem type.
    typ: &'static str,
    detail: Cow<'static, str>,
    /// The optional members, allocated only when one is actually used.
    ///
    /// Boxed because `Problem` is the `Err` of nearly every function in this
    /// codebase, so its size is paid on every call — and all three of these are
    /// empty for the great majority of problems, which are about the request
    /// rather than about a list of identifiers. Inline they push the struct past
    /// clippy's `result_large_err` threshold; behind an `Option<Box<_>>` the
    /// common path costs one pointer and no allocation.
    ext: Option<Box<ProblemExtensions>>,
}

/// The parts of an RFC 8555 problem document beyond RFC 7807's three fields.
#[derive(Debug, Default)]
struct ProblemExtensions {
    /// The identifier this problem is about (RFC 8555 §9.7.7), set only on a
    /// *subproblem*: §6.7.1 says the field "MUST NOT be present at the top
    /// level in ACME problem documents. It can only be present in subproblems."
    /// [`Problem::to_value`] enforces that by rendering it nowhere else.
    identifier: Option<Value>,
    /// Per-identifier failures (RFC 8555 §6.7.1).
    subproblems: Vec<Problem>,
    /// Type-specific members some error types carry — today only
    /// `badSignatureAlgorithm`'s `algorithms` (RFC 8555 §6.2).
    extra: serde_json::Map<String, Value>,
}

impl Problem {
    /// The shared constructor every named one funnels through, so a new field
    /// on the struct does not have to be threaded through twenty-odd literals.
    fn build(status: StatusCode, typ: &'static str, detail: impl Into<Cow<'static, str>>) -> Self {
        Self {
            status,
            typ,
            detail: detail.into(),
            ext: None,
        }
    }

    /// The extensions block, created on first use.
    fn ext_mut(&mut self) -> &mut ProblemExtensions {
        self.ext.get_or_insert_with(Box::default)
    }
    /// The request was unacceptable for some reason (bad JSON, base64, JWS
    /// shape, unexpected payload, wrong algorithm…). HTTP 400.
    pub fn malformed(detail: impl Into<Cow<'static, str>>) -> Self {
        Self::build(
            StatusCode::BAD_REQUEST,
            "urn:ietf:params:acme:error:malformed",
            detail,
        )
    }

    /// The client sent an unacceptable anti-replay nonce (unknown or expired).
    /// The client should retry with a fresh nonce. HTTP 400.
    pub fn bad_nonce(detail: impl Into<Cow<'static, str>>) -> Self {
        Self::build(
            StatusCode::BAD_REQUEST,
            "urn:ietf:params:acme:error:badNonce",
            detail,
        )
    }

    /// The client lacks authorization to perform the request — here, a JWS
    /// signature that fails verification. HTTP 401.
    pub fn unauthorized(detail: impl Into<Cow<'static, str>>) -> Self {
        Self::build(
            StatusCode::UNAUTHORIZED,
            "urn:ietf:params:acme:error:unauthorized",
            detail,
        )
    }

    /// The server experienced an internal failure (e.g. the database was
    /// unreachable). HTTP 500.
    pub fn server_internal(detail: impl Into<Cow<'static, str>>) -> Self {
        Self::build(
            StatusCode::INTERNAL_SERVER_ERROR,
            "urn:ietf:params:acme:error:serverInternal",
            detail,
        )
    }

    /// The request referenced an account that does not exist. HTTP 400.
    pub fn account_does_not_exist(detail: impl Into<Cow<'static, str>>) -> Self {
        Self::build(
            StatusCode::BAD_REQUEST,
            "urn:ietf:params:acme:error:accountDoesNotExist",
            detail,
        )
    }

    /// A finalize was attempted on an order that is not in the `ready` state
    /// (RFC 8555 §7.4). HTTP 403.
    pub fn order_not_ready(detail: impl Into<Cow<'static, str>>) -> Self {
        Self::build(
            StatusCode::FORBIDDEN,
            "urn:ietf:params:acme:error:orderNotReady",
            detail,
        )
    }

    /// The CSR in a finalize request was unacceptable (unparsable, its
    /// identifiers do not match the order, or a filter refused one of the
    /// names it requests). HTTP 400.
    pub fn bad_csr(detail: impl Into<Cow<'static, str>>) -> Self {
        Self::build(
            StatusCode::BAD_REQUEST,
            "urn:ietf:params:acme:error:badCSR",
            detail,
        )
    }

    /// A newOrder identifier used a type the server does not support (only
    /// `dns` is supported here). HTTP 400.
    pub fn unsupported_identifier(detail: impl Into<Cow<'static, str>>) -> Self {
        Self::build(
            StatusCode::BAD_REQUEST,
            "urn:ietf:params:acme:error:unsupportedIdentifier",
            detail,
        )
    }

    /// The server will not issue for an identifier it otherwise supports,
    /// because policy refuses it (RFC 8555 §6.7). Raised by the `filter`
    /// subsystem at newOrder. HTTP 403.
    pub fn rejected_identifier(detail: impl Into<Cow<'static, str>>) -> Self {
        Self::build(
            StatusCode::FORBIDDEN,
            "urn:ietf:params:acme:error:rejectedIdentifier",
            detail,
        )
    }

    /// The request was blocked by a connection-level filter (IP allowlist,
    /// reverse DNS…), or a challenge responder answered with something that is
    /// not the key authorization. HTTP 403.
    ///
    /// RFC 8555 has no dedicated "blocked by policy" code, so this reuses the
    /// `unauthorized` type — but with 403 rather than the 401 that
    /// [`Problem::unauthorized`] returns for a failed signature check, since
    /// no credential could make this request succeed. RFC 8555 §8.3's own
    /// example uses the same type for an `http-01` body mismatch.
    pub fn access_denied(detail: impl Into<Cow<'static, str>>) -> Self {
        Self::build(
            StatusCode::FORBIDDEN,
            "urn:ietf:params:acme:error:unauthorized",
            detail,
        )
    }

    /// The server could not reach the client's validation target — TCP refused,
    /// no route, a redirect chain that never terminated. HTTP 400.
    ///
    /// One of the four challenge-validation error types of RFC 8555 §6.7. The
    /// client can fix the situation and retry with a new order.
    pub fn connection(detail: impl Into<Cow<'static, str>>) -> Self {
        Self::build(
            StatusCode::BAD_REQUEST,
            "urn:ietf:params:acme:error:connection",
            detail,
        )
    }

    /// A DNS query the server needed failed or returned nothing (RFC 8555 §6.7).
    /// HTTP 400.
    ///
    /// Distinct from [`Problem::incorrect_response`]: this says the lookup did
    /// not produce an answer, not that the answer was wrong.
    pub fn dns(detail: impl Into<Cow<'static, str>>) -> Self {
        Self::build(
            StatusCode::BAD_REQUEST,
            "urn:ietf:params:acme:error:dns",
            detail,
        )
    }

    /// The validation target answered, but not with what the challenge requires
    /// — a TXT record that does not match, a certificate without the expected
    /// `acmeIdentifier` extension (RFC 8555 §6.7). HTTP 403.
    pub fn incorrect_response(detail: impl Into<Cow<'static, str>>) -> Self {
        Self::build(
            StatusCode::FORBIDDEN,
            "urn:ietf:params:acme:error:incorrectResponse",
            detail,
        )
    }

    /// A TLS-level failure while validating a `tls-alpn-01` challenge — no ALPN
    /// negotiated, a handshake alert, no certificate presented (RFC 8555 §6.7).
    /// HTTP 400.
    pub fn tls(detail: impl Into<Cow<'static, str>>) -> Self {
        Self::build(
            StatusCode::BAD_REQUEST,
            "urn:ietf:params:acme:error:tls",
            detail,
        )
    }

    /// The server requires External Account Binding (RFC 8555 §6.7 / §7.3.4)
    /// but the request did not include one. HTTP 400.
    pub fn external_account_required(detail: impl Into<Cow<'static, str>>) -> Self {
        Self::build(
            StatusCode::BAD_REQUEST,
            "urn:ietf:params:acme:error:externalAccountRequired",
            detail,
        )
    }

    /// The certificate identified by a `POST /revokeCert` request has already
    /// been revoked (RFC 8555 §7.6). HTTP 400.
    pub fn already_revoked(detail: impl Into<Cow<'static, str>>) -> Self {
        Self::build(
            StatusCode::BAD_REQUEST,
            "urn:ietf:params:acme:error:alreadyRevoked",
            detail,
        )
    }

    /// The `reason` a `POST /revokeCert` request gave is not one of the
    /// `CRLReason` codes RFC 8555 §7.6 permits (RFC 5280 §5.3.1, excluding the
    /// reserved code `7`). HTTP 400.
    pub fn bad_revocation_reason(detail: impl Into<Cow<'static, str>>) -> Self {
        Self::build(
            StatusCode::BAD_REQUEST,
            "urn:ietf:params:acme:error:badRevocationReason",
            detail,
        )
    }

    /// The new key in a `keyChange` (RFC 8555 §7.3.5) request is already
    /// associated with a different account. HTTP 409.
    ///
    /// RFC 8555 defines no dedicated error type for this case, so this
    /// reuses the `malformed` urn — mirroring how [`Problem::access_denied`]
    /// already reuses `unauthorized`'s urn under a different status. Unlike
    /// every other `Problem`, the caller also attaches a `Location` header
    /// naming the conflicting account (RFC 8555 §7.3.5), which requires
    /// building the `Response` by hand rather than through `IntoResponse`
    /// (see `to_value`).
    pub fn key_change_conflict(detail: impl Into<Cow<'static, str>>) -> Self {
        Self::build(
            StatusCode::CONFLICT,
            "urn:ietf:params:acme:error:malformed",
            detail,
        )
    }

    /// The request body did not carry `Content-Type: application/jose+json`.
    /// HTTP 415.
    ///
    /// RFC 8555 §6.2 makes the media type mandatory and names the status
    /// itself: "If a request does not meet this requirement, then the server
    /// MUST return a response with status code 415 (Unsupported Media Type)".
    /// It defines no error *type* for the case, so this reuses `malformed`'s
    /// urn under a different status — the same pattern as
    /// [`Problem::access_denied`] and [`Problem::key_change_conflict`].
    pub fn unsupported_media_type(detail: impl Into<Cow<'static, str>>) -> Self {
        Self::build(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "urn:ietf:params:acme:error:malformed",
            detail,
        )
    }

    /// The request body was larger than `server.max_body_bytes`. HTTP 413.
    ///
    /// Distinct from `malformed` on purpose: the body was never read, so
    /// nothing is known about whether it was a well-formed JWS, and telling a
    /// client its JWS is malformed would send it rebuilding the one thing that
    /// is not the problem. RFC 8555 defines no type for this, so it reuses
    /// `malformed`'s urn under its own status — the same pattern as
    /// [`Problem::unsupported_media_type`].
    pub fn payload_too_large(detail: impl Into<Cow<'static, str>>) -> Self {
        Self::build(
            StatusCode::PAYLOAD_TOO_LARGE,
            "urn:ietf:params:acme:error:malformed",
            detail,
        )
    }

    /// The server is at capacity and refused the request without doing any of
    /// the work. HTTP 503.
    ///
    /// Deliberately *not* `rateLimited`/429: that type says "you asked too
    /// often", which is a statement about the client, and here the client may
    /// have made its first request of the day. RFC 8555 defines no type for
    /// server-side saturation, so this reuses `serverInternal`'s urn under a
    /// different status — the same pattern as [`Problem::access_denied`],
    /// [`Problem::key_change_conflict`] and [`Problem::unsupported_media_type`].
    ///
    /// The caller attaches `Retry-After`; every ACME client already understands
    /// it from the rate-limit case.
    pub fn service_unavailable(detail: impl Into<Cow<'static, str>>) -> Self {
        Self::build(
            StatusCode::SERVICE_UNAVAILABLE,
            "urn:ietf:params:acme:error:serverInternal",
            detail,
        )
    }

    /// The resource exists but not for this HTTP method — in practice, a bare
    /// `GET` of a resource that RFC 8555 §6.3 requires be read with
    /// POST-as-GET. HTTP 405.
    ///
    /// §6.3 pins both halves: "if the server receives a GET request, it MUST
    /// return an error with status code 405 (Method Not Allowed) and type
    /// `malformed`". axum's own method-not-allowed response carries the right
    /// status but an empty body, so this supplies the problem document.
    pub fn method_not_allowed(detail: impl Into<Cow<'static, str>>) -> Self {
        Self::build(
            StatusCode::METHOD_NOT_ALLOWED,
            "urn:ietf:params:acme:error:malformed",
            detail,
        )
    }

    /// A newOrder named a predecessor certificate that another order already
    /// claims to replace (RFC 9773 §7.4). HTTP 409.
    ///
    /// The one status RFC 9773 pins by name: §5 says the server "MUST return an
    /// HTTP 409 (Conflict) with a problem document of type `alreadyReplaced`" —
    /// unlike the other §5 checks, which only say "SHOULD reject".
    pub fn already_replaced(detail: impl Into<Cow<'static, str>>) -> Self {
        Self::build(
            StatusCode::CONFLICT,
            "urn:ietf:params:acme:error:alreadyReplaced",
            detail,
        )
    }

    /// Several errors at once, each attributed to its own identifier
    /// (RFC 8555 §6.7.1). Pair with [`Problem::with_subproblems`].
    ///
    /// The status is the caller's to choose, since §6.7.1 puts no constraint on
    /// it and a compound of rejections (403) reads differently from a compound
    /// of malformed names (400).
    pub fn compound(status: StatusCode, detail: impl Into<Cow<'static, str>>) -> Self {
        Self::build(status, "urn:ietf:params:acme:error:compound", detail)
    }

    /// The JWS was signed with an algorithm this server does not support
    /// (RFC 8555 §6.2). HTTP 400.
    ///
    /// §6.2 requires the response to carry the supported list: "an
    /// `algorithms` field […] listing the JWS algorithms the server supports",
    /// so the client can retry with one instead of guessing. Attached here
    /// rather than left to the caller, since the list is a property of this
    /// server's verifier, not of the call site.
    pub fn bad_signature_algorithm(detail: impl Into<Cow<'static, str>>) -> Self {
        Self::build(
            StatusCode::BAD_REQUEST,
            "urn:ietf:params:acme:error:badSignatureAlgorithm",
            detail,
        )
        .with_extra("algorithms", json!(["ES256", "RS256"]))
    }

    /// A `contact` URL used a scheme this server does not support
    /// (RFC 8555 §7.3). HTTP 400.
    pub fn unsupported_contact(detail: impl Into<Cow<'static, str>>) -> Self {
        Self::build(
            StatusCode::BAD_REQUEST,
            "urn:ietf:params:acme:error:unsupportedContact",
            detail,
        )
    }

    /// A `contact` URL was of a supported scheme but not usable — a `mailto:`
    /// carrying `hfields` or more than one address (RFC 8555 §7.3). HTTP 400.
    pub fn invalid_contact(detail: impl Into<Cow<'static, str>>) -> Self {
        Self::build(
            StatusCode::BAD_REQUEST,
            "urn:ietf:params:acme:error:invalidContact",
            detail,
        )
    }

    /// The client must take an out-of-band action before the request can
    /// succeed — here, agreeing to the terms of service (RFC 8555 §7.3.3).
    /// HTTP 403.
    ///
    /// The caller attaches a `Link: <tos-url>;rel="terms-of-service"` header,
    /// as §6.7 requires for this type.
    pub fn user_action_required(detail: impl Into<Cow<'static, str>>) -> Self {
        Self::build(
            StatusCode::FORBIDDEN,
            "urn:ietf:params:acme:error:userActionRequired",
            detail,
        )
    }

    /// No resource is routed at the requested path. HTTP 404.
    ///
    /// RFC 8555 defines no type for this either; `malformed` keeps an unknown
    /// path answering in the `application/problem+json` shape every other
    /// failure uses, rather than axum's empty-bodied default.
    pub fn not_found(detail: impl Into<Cow<'static, str>>) -> Self {
        Self::build(
            StatusCode::NOT_FOUND,
            "urn:ietf:params:acme:error:malformed",
            detail,
        )
    }
}

impl Problem {
    /// The HTTP status this problem renders as.
    ///
    /// Exposed so a caller assembling a `compound` (RFC 8555 §6.7.1) can pick a
    /// status for the wrapper from the parts it is wrapping.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// Attaches the identifier this problem is about (RFC 8555 §9.7.7).
    ///
    /// Only meaningful on a problem destined to become a *subproblem*: §6.7.1
    /// forbids the field at the top level, and [`Problem::to_value`] drops it
    /// there, so calling this on a problem that is then returned directly is a
    /// no-op rather than a violation.
    #[must_use]
    pub fn with_identifier(mut self, identifier: &crate::sqlite::order::Identifier) -> Self {
        self.ext_mut().identifier = serde_json::to_value(identifier).ok();
        self
    }

    /// Attaches per-identifier failures (RFC 8555 §6.7.1).
    ///
    /// §6.7.1: "Subproblems need not all have the same type, and they do not
    /// need to match the top level type."
    #[must_use]
    pub fn with_subproblems(mut self, subproblems: Vec<Problem>) -> Self {
        self.ext_mut().subproblems = subproblems;
        self
    }

    /// Attaches a type-specific member, e.g. `badSignatureAlgorithm`'s
    /// `algorithms` list (RFC 8555 §6.2).
    #[must_use]
    pub fn with_extra(mut self, key: &str, value: Value) -> Self {
        self.ext_mut().extra.insert(key.to_string(), value);
        self
    }

    /// The RFC 8555 problem document as a JSON value (`{type, detail, status}`,
    /// plus `subproblems` and any type-specific members when present).
    ///
    /// Shared by [`IntoResponse`] (the response body) and callers that need to
    /// *persist* the same document — e.g. an order's `error` field on a failed
    /// finalize renders exactly what the client is told.
    ///
    /// `identifier` is deliberately absent: §6.7.1 makes it a subproblem-only
    /// field, and [`Problem::to_subproblem_value`] is where it appears.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let mut object = serde_json::Map::new();
        object.insert("type".to_string(), Value::String(self.typ.to_string()));
        object.insert("detail".to_string(), json!(self.detail));
        object.insert("status".to_string(), json!(self.status.as_u16()));

        if let Some(ext) = &self.ext {
            for (key, value) in &ext.extra {
                object.insert(key.clone(), value.clone());
            }

            if !ext.subproblems.is_empty() {
                object.insert(
                    "subproblems".to_string(),
                    Value::Array(
                        ext.subproblems
                            .iter()
                            .map(Problem::to_subproblem_value)
                            .collect(),
                    ),
                );
            }
        }

        Value::Object(object)
    }

    /// This problem as it appears *inside* another's `subproblems` array
    /// (RFC 8555 §6.7.1): `type` and `detail`, plus the `identifier` it is
    /// about. No `status` — the HTTP status belongs to the response, and the
    /// RFC's own example omits it here.
    #[must_use]
    fn to_subproblem_value(&self) -> Value {
        let mut object = serde_json::Map::new();
        object.insert("type".to_string(), Value::String(self.typ.to_string()));
        object.insert("detail".to_string(), json!(self.detail));
        if let Some(identifier) = self.ext.as_ref().and_then(|ext| ext.identifier.as_ref()) {
            object.insert("identifier".to_string(), identifier.clone());
        }
        Value::Object(object)
    }
}

impl IntoResponse for Problem {
    fn into_response(self) -> Response {
        let body = Json(self.to_value());

        (
            self.status,
            [(header::CONTENT_TYPE, "application/problem+json")],
            body,
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    /// Renders a `Problem` and asserts its status, `content-type`, and the three
    /// JSON fields of the RFC 8555 problem document.
    async fn assert_problem(problem: Problem, expected_status: u16, expected_type: &str) {
        let response = problem.into_response();

        assert_eq!(response.status().as_u16(), expected_status);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/problem+json"),
        );

        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["type"], expected_type);
        assert_eq!(json["status"], expected_status);
        assert_eq!(json["detail"], "boom");
    }

    #[tokio::test]
    async fn malformed_renders_400_problem_json() {
        assert_problem(
            Problem::malformed("boom"),
            400,
            "urn:ietf:params:acme:error:malformed",
        )
        .await;
    }

    #[tokio::test]
    async fn bad_nonce_renders_400_problem_json() {
        assert_problem(
            Problem::bad_nonce("boom"),
            400,
            "urn:ietf:params:acme:error:badNonce",
        )
        .await;
    }

    #[tokio::test]
    async fn unauthorized_renders_401_problem_json() {
        assert_problem(
            Problem::unauthorized("boom"),
            401,
            "urn:ietf:params:acme:error:unauthorized",
        )
        .await;
    }

    #[tokio::test]
    async fn server_internal_renders_500_problem_json() {
        assert_problem(
            Problem::server_internal("boom"),
            500,
            "urn:ietf:params:acme:error:serverInternal",
        )
        .await;
    }

    #[tokio::test]
    async fn account_does_not_exist_renders_400_problem_json() {
        assert_problem(
            Problem::account_does_not_exist("boom"),
            400,
            "urn:ietf:params:acme:error:accountDoesNotExist",
        )
        .await;
    }

    #[tokio::test]
    async fn order_not_ready_renders_403_problem_json() {
        assert_problem(
            Problem::order_not_ready("boom"),
            403,
            "urn:ietf:params:acme:error:orderNotReady",
        )
        .await;
    }

    #[tokio::test]
    async fn bad_csr_renders_400_problem_json() {
        assert_problem(
            Problem::bad_csr("boom"),
            400,
            "urn:ietf:params:acme:error:badCSR",
        )
        .await;
    }

    #[tokio::test]
    async fn unsupported_identifier_renders_400_problem_json() {
        assert_problem(
            Problem::unsupported_identifier("boom"),
            400,
            "urn:ietf:params:acme:error:unsupportedIdentifier",
        )
        .await;
    }

    #[tokio::test]
    async fn rejected_identifier_renders_403_problem_json() {
        assert_problem(
            Problem::rejected_identifier("boom"),
            403,
            "urn:ietf:params:acme:error:rejectedIdentifier",
        )
        .await;
    }

    #[tokio::test]
    async fn access_denied_renders_403_problem_json() {
        assert_problem(
            Problem::access_denied("boom"),
            403,
            "urn:ietf:params:acme:error:unauthorized",
        )
        .await;
    }

    #[tokio::test]
    async fn connection_renders_400_problem_json() {
        assert_problem(
            Problem::connection("boom"),
            400,
            "urn:ietf:params:acme:error:connection",
        )
        .await;
    }

    #[tokio::test]
    async fn dns_renders_400_problem_json() {
        assert_problem(Problem::dns("boom"), 400, "urn:ietf:params:acme:error:dns").await;
    }

    #[tokio::test]
    async fn incorrect_response_renders_403_problem_json() {
        assert_problem(
            Problem::incorrect_response("boom"),
            403,
            "urn:ietf:params:acme:error:incorrectResponse",
        )
        .await;
    }

    #[tokio::test]
    async fn tls_renders_400_problem_json() {
        assert_problem(Problem::tls("boom"), 400, "urn:ietf:params:acme:error:tls").await;
    }

    #[tokio::test]
    async fn external_account_required_renders_400_problem_json() {
        assert_problem(
            Problem::external_account_required("boom"),
            400,
            "urn:ietf:params:acme:error:externalAccountRequired",
        )
        .await;
    }

    #[tokio::test]
    async fn already_revoked_renders_400_problem_json() {
        assert_problem(
            Problem::already_revoked("boom"),
            400,
            "urn:ietf:params:acme:error:alreadyRevoked",
        )
        .await;
    }

    #[tokio::test]
    async fn bad_revocation_reason_renders_400_problem_json() {
        assert_problem(
            Problem::bad_revocation_reason("boom"),
            400,
            "urn:ietf:params:acme:error:badRevocationReason",
        )
        .await;
    }

    #[tokio::test]
    async fn key_change_conflict_renders_409_problem_json() {
        assert_problem(
            Problem::key_change_conflict("boom"),
            409,
            "urn:ietf:params:acme:error:malformed",
        )
        .await;
    }

    #[test]
    fn to_value_matches_rendered_body() {
        let value = Problem::server_internal("boom").to_value();
        assert_eq!(value["type"], "urn:ietf:params:acme:error:serverInternal");
        assert_eq!(value["detail"], "boom");
        assert_eq!(value["status"], 500);
    }

    /// A `String` detail (what the filters build) renders like a literal one.
    #[test]
    fn owned_detail_is_accepted_and_rendered() {
        let name = "evil.example.com";
        let value = Problem::rejected_identifier(format!("identifier {name} is denied")).to_value();
        assert_eq!(value["detail"], "identifier evil.example.com is denied");
    }
}
