//! Certificate bytes that arrive from outside, on two unauthenticated-ish
//! surfaces.
//!
//! `leaf_der_from_chain` parses a PEM chain a client posts to `revokeCert`, and
//! `cert_serial_and_spki` / `cert_validity` / `ari_cert_id` then walk the
//! resulting DER. `parse_ari_cert_id` is the one with no authentication in
//! front of it at all: RFC 9773 §4.1 has the client append the identifier to
//! `GET /renewalInfo/`, so it is a raw path segment.
//!
//! The previous `parse_csr` target called an infallible newtype constructor and
//! then `x509_parser::parse_x509_certificate` — a third-party parser, on bytes
//! that never reached this crate. It also did not compile, because neither
//! crate was a dependency of the fuzz package, which made the `fuzz` CI job red
//! on every push.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The DER walkers, straight off the wire.
    let _ = acme_proxy::cert::cert_serial_and_spki(data);
    let _ = acme_proxy::cert::cert_validity(data);
    let _ = acme_proxy::cert::ari_cert_id(data);
    let _ = acme_proxy::cert::ari_cert_id_parts(data);

    if let Ok(text) = std::str::from_utf8(data) {
        // A PEM chain as `revokeCert` receives it.
        let _ = acme_proxy::cert::leaf_der_from_chain(text);
        // And the unauthenticated path segment.
        let _ = acme_proxy::cert::parse_ari_cert_id(text);
    }
});
