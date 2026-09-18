//! The ACME identifier (RFC 8555 §7.1.4) — the name an order, an
//! authorization, a filter check and a signer's CSR check all speak about.
//!
//! Its own module rather than beside the order row it is stored in, because
//! everything above the storage layer names it too: the problem documents'
//! `subproblems`, the filters, the audit trail's frozen identifier list.

use serde::{Deserialize, Serialize};

/// An ACME identifier (RFC 8555 §7.1.4). Only `dns` is supported here, but the
/// type is kept generic so the JSON round-trips whatever a client sent.
///
/// Stored inside the order's `identifiers` JSON array and echoed verbatim in the
/// order object. Reused by the signer to check a finalize CSR's SANs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identifier {
    #[serde(rename = "type")]
    pub typ: String,
    pub value: String,
}

impl Identifier {
    /// A `dns` identifier, which is every identifier this server issues for.
    ///
    /// Here rather than in a test helper because the struct had no constructor
    /// at all, and twelve modules had each grown their own `fn dns(&str)` to
    /// avoid writing the literal — the same accumulation that put `TempDir` in
    /// `testutil`, except these are one line each and belong in production,
    /// where the handlers building identifiers benefit too.
    #[must_use]
    pub fn dns(value: impl Into<String>) -> Self {
        Self::new("dns", value)
    }

    /// An identifier of any type. `typ` is kept a free string because RFC 8555
    /// §9.7.7 leaves the registry open and the order object echoes back
    /// whatever a client sent.
    #[must_use]
    pub fn new(typ: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            typ: typ.into(),
            value: value.into(),
        }
    }
}
