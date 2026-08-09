//! Hand-rolled DER walking over a `SubjectPublicKeyInfo`.
//!
//! `spki_to_jwk` and `jwk_thumbprint` parse `accounts.pubkey` — a column this
//! server wrote, but one whose contents a corrupted or tampered database row
//! decides. Both are reached on the authenticated request path, and both walk
//! `simple_asn1` output by hand with length checks and slicing. A panic here is
//! a request-path abort; a wrong answer is worse, because `jwk_thumbprint` is
//! what a key authorization is compared against.
//!
//! The property: never panic, whatever the bytes.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Both walk the same DER, and `spki_to_jwk` reaches `spki_parts` on the
    // way, so between them every branch of the parser is in scope.
    let _ = acme_proxy::extractors::signature::spki_to_jwk(data);
    let _ = acme_proxy::extractors::signature::jwk_thumbprint(data);

    // The verification entry point, on every algorithm it accepts. A caller
    // controls `alg` (it comes out of the JWS protected header), so the
    // OID-versus-`alg` cross-check is driven with the wrong pairing too.
    // `sig_b64` is base64url text a client sends, so it is driven with the
    // fuzzer's own bytes rather than a fixed valid signature.
    let signature = String::from_utf8_lossy(data);
    for alg in ["ES256", "RS256", "none", ""] {
        let _ = acme_proxy::extractors::signature::verify_signature_with_spki(
            alg,
            data,
            "signing input",
            &signature,
        );
    }
});
