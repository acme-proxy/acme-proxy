use serde::{Deserialize, Serialize};

/// Represents a JSON Web Signature (JWS) request structure used in ACME protocol.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AcmeJwsRequest {
    pub protected: String,
    pub signature: String,
    pub payload: String,
}

/// Represents the JWK (JSON Web Key) structure used in ACME JWS headers.
#[derive(Deserialize, Debug, PartialEq)]
#[serde(tag = "kty")]
pub enum Jwk {
    /// RSA key type with modulus (n) and public exponent (e)
    RSA { n: String, e: String },
    /// Elliptic Curve key type with curve (crv) and coordinates (x, y)
    EC { crv: String, x: String, y: String },
}

/// Represents the protected header of an ACME JWS request.
///
/// Deliberately *not* `deny_unknown_fields`: RFC 8555 §6.2 enumerates the
/// fields it expects, but silently ignoring an extra member costs nothing and
/// refusing one would reject clients over a harmless addition. `crit` is the
/// exception — see the field below.
#[derive(Debug, Deserialize)]
pub struct ProtectedHeader {
    pub alg: String,
    pub jwk: Option<Jwk>,
    pub kid: Option<String>,
    pub nonce: String,
    pub url: String,
    /// Header extensions the sender marks as critical (RFC 7515 §4.1.11).
    ///
    /// This server implements no critical extension, so *every* value here is
    /// unrecognized and the JWS must be rejected — which is why the field is
    /// parsed at all: ignoring it would silently accept a request whose sender
    /// demanded we understand something we do not.
    pub crit: Option<Vec<String>>,
}
