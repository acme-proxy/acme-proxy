//! Identifier shape and normalization — the string a `newOrder` policy decision
//! is made about.
//!
//! `well_formed_name` is the gate that keeps a `dns` identifier one opaque
//! name. Two subsystems downstream read the value as structure rather than as a
//! name: `filter::custom` joins identifiers with `,` into an environment
//! variable, and `challenge::http_01` feeds the value to `Url::parse`. So a
//! value this accepts but that is not a DNS name is a filter bypass, which
//! makes the accept/reject boundary worth pushing on with arbitrary bytes —
//! including every non-ASCII and multi-byte sequence, where a naive index would
//! panic on a character boundary.
//!
//! Two properties, both asserted rather than merely "does not panic":
//!
//! 1. Normalization is idempotent — it runs before storage and again before
//!    comparison, so a second pass changing the answer would mean an
//!    authorization matching a name the order does not carry.
//! 2. Anything accepted is ASCII and free of the delimiters the downstream
//!    subsystems would misread.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(value) = std::str::from_utf8(data) else {
        return;
    };

    let normalized = acme_proxy::normalize_dns_name(value);
    assert_eq!(
        acme_proxy::normalize_dns_name(&normalized),
        normalized,
        "normalization must be idempotent: {value:?}"
    );

    let _ = acme_proxy::is_wildcard(value);

    if acme_proxy::well_formed_name(value) {
        assert!(
            value.is_ascii(),
            "a well-formed name must be ASCII: {value:?}"
        );
        for delimiter in [',', '/', '@', '#', '?', ':', ' '] {
            assert!(
                !value.contains(delimiter),
                "{delimiter:?} must never survive into an accepted name: {value:?}"
            );
        }
        assert!(
            !value.chars().any(char::is_control),
            "a control character must never survive: {value:?}"
        );
        // And normalization keeps it well formed, since the stored form is what
        // later comparisons run against.
        assert!(
            acme_proxy::well_formed_name(&normalized),
            "normalizing {value:?} produced the unacceptable {normalized:?}"
        );
    }
});
