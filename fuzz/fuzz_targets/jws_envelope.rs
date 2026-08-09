//! The JWS prefix every signed ACME request goes through.
//!
//! Reached **before authentication**: `verify_jws` deserializes the flattened
//! envelope, base64url-decodes the protected header, deserializes that, and
//! only then verifies a signature. Everything this target drives therefore runs
//! for any anonymous caller who can reach a profile's `POST` routes.
//!
//! The previous `parse_jws` target stopped at `serde_json::from_str` over a
//! three-`String` struct, which fuzzes `serde`, not this crate. This one
//! carries on into the decode and the embedded `jwk`, which is where the
//! hand-written parsing actually lives.

#![no_main]

use base64::prelude::*;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    let Ok(envelope) =
        serde_json::from_str::<acme_proxy::extractors::jws::AcmeJwsRequest>(text)
    else {
        return;
    };

    // The three base64url members, decoded exactly as the extractor decodes
    // them. A client chooses all three.
    let Ok(protected) = BASE64_URL_SAFE_NO_PAD.decode(&envelope.protected) else {
        return;
    };
    let _ = BASE64_URL_SAFE_NO_PAD.decode(&envelope.payload);
    let _ = BASE64_URL_SAFE_NO_PAD.decode(&envelope.signature);

    let Ok(header) =
        serde_json::from_slice::<acme_proxy::extractors::jws::ProtectedHeader>(&protected)
    else {
        return;
    };

    // The part worth reaching: an embedded `jwk` is re-encoded as DER SPKI by
    // hand (`simple_asn1`), from coordinates a client supplies. Short, long and
    // non-minimal integers all arrive here.
    let _ = acme_proxy::extractors::signature::verify_signature_and_get_der(
        &header,
        "signing input",
        &envelope.signature,
    );
});
