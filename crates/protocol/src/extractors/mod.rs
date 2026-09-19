//! Request extraction and JWS verification — the security core of the crate.
//!
//! [`acme`] holds the shared `verify_jws` routine and the three extractors
//! built on it: `AcmeRequest<T>` (a decoded payload), `AcmePostAsGet` (an empty
//! payload, per RFC 8555 §6.3) and `AcmeOptionalPayload<T>` (either, which the
//! authorization resource needs because one URL serves both a read and a
//! §7.5.2 deactivation).
//!
//! Hoisting the protocol checks here is deliberate: the media type, any `crit`
//! header, the signature, the JWS `url` (§6.4) and the nonce (§6.5) are all
//! verified before a handler runs, so the guarantees are structural rather than
//! a convention each handler has to observe.
//!
//! The wire types and the cryptography they run are [`acme_proxy_core::jws`].

pub mod acme;

pub use acme::*;
