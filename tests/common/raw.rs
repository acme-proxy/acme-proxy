//! A signed request assembled field by field, for tests that need to break
//! exactly one thing.
//!
//! The signers in the parent module only produce well-formed requests. This
//! builder starts from one and lets a test change a single protected header,
//! swap the payload for something that is not JSON, or sign with the wrong key,
//! while everything else stays valid.
//!
//! A request starts with an empty payload, which is what a POST-as-GET sends
//! (RFC 8555 §6.3).

use base64::prelude::*;
use serde_json::{Map, Value, json};

use super::{TestSigner, flattened_jws};

pub struct RawJws<'a> {
    signer: &'a dyn TestSigner,
    header: Map<String, Value>,
    payload_segment: String,
}

impl<'a> RawJws<'a> {
    /// A request that names its account by URL, the form every request except
    /// `newAccount` uses.
    pub fn with_kid(signer: &'a dyn TestSigner, kid: &str, url: &str, nonce: &str) -> Self {
        Self::new(
            signer,
            json!({ "alg": signer.alg(), "kid": kid, "nonce": nonce, "url": url }),
        )
    }

    /// A request that carries its public key, the form `newAccount` uses.
    pub fn with_jwk(signer: &'a dyn TestSigner, url: &str, nonce: &str) -> Self {
        Self::new(
            signer,
            json!({ "alg": signer.alg(), "jwk": signer.jwk(), "nonce": nonce, "url": url }),
        )
    }

    fn new(signer: &'a dyn TestSigner, header: Value) -> Self {
        let Value::Object(header) = header else {
            unreachable!("a protected header is built from an object literal");
        };

        Self {
            signer,
            header,
            payload_segment: String::new(),
        }
    }

    /// Sets a protected header, replacing any value it already had.
    #[must_use]
    pub fn header(mut self, name: &str, value: Value) -> Self {
        self.header.insert(name.to_string(), value);
        self
    }

    #[must_use]
    pub fn without_header(mut self, name: &str) -> Self {
        self.header.remove(name);
        self
    }

    #[must_use]
    pub fn json_payload(self, payload: &Value) -> Self {
        self.bytes_payload(&serde_json::to_vec(payload).unwrap())
    }

    /// Any bytes at all, base64url-encoded the way a payload segment is.
    #[must_use]
    pub fn bytes_payload(mut self, bytes: &[u8]) -> Self {
        self.payload_segment = BASE64_URL_SAFE_NO_PAD.encode(bytes);
        self
    }

    /// The payload segment exactly as given, so a test can send text that is
    /// not valid base64url.
    #[must_use]
    pub fn payload_segment(mut self, segment: &str) -> Self {
        self.payload_segment = segment.to_string();
        self
    }

    /// The request, correctly signed by the key it was created with.
    pub fn signed(&self) -> String {
        self.signed_by(self.signer)
    }

    /// The request, signed by a different key than the one it names.
    pub fn signed_by(&self, signer: &dyn TestSigner) -> String {
        let protected = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&self.header).unwrap());
        let input = format!("{protected}.{}", self.payload_segment);

        flattened_jws(
            &protected,
            &self.payload_segment,
            &signer.sign_input(input.as_bytes()),
        )
    }

    /// A signature that is well formed and made by the right key, but over a
    /// different message, so it cannot verify.
    pub fn with_bad_signature(&self) -> String {
        let protected = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&self.header).unwrap());
        let other_message = self.signer.sign_input(b"a different message");

        flattened_jws(&protected, &self.payload_segment, &other_message)
    }
}
