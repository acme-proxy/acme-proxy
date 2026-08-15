//! What every issued leaf says about *this CA's own services* —
//! `cRLDistributionPoints` (RFC 5280 §4.2.1.13) and `authorityInfoAccess` /
//! `caIssuers` (§4.2.2.1).
//!
//! Both are operator-configured URLs ([`LocalCaConfig::crl_distribution_points`]
//! and [`LocalCaConfig::ca_issuer_urls`]), and both are empty by default, in
//! which case no extension is emitted at all and a leaf is byte-for-byte what
//! this CA issued before either key existed.
//!
//! Nothing derives these from `server.base_url`. The value is frozen into every
//! certificate signed while it is set — for `leaf_validity_days`, long after a
//! rename — and this server's own `/crl` sits inside a profile router, behind
//! that profile's filter chain, so an address-based policy refuses it to
//! exactly the relying parties the extension exists for. The operator names a
//! URL they know is reachable.
//!
//! Validation and DER encoding both happen **once, at startup**
//! ([`LeafPolicy::from_config`], called from `LocalCa::load_or_generate`): a bad
//! URL is a startup error rather than a 500 at finalize, and `issue` does no
//! ASN.1 work per request.

use anyhow::{anyhow, ensure};
use rcgen::{CrlDistributionPoint, CustomExtension};
use simple_asn1::{ASN1Block, ASN1Class, BigUint, OID};
use tracing::info;
use url::Url;

use crate::config::LocalCaConfig;

/// OIDs written into the AIA extension.
///
/// `fn` rather than `const` for the reason `extractors::signature`'s copy of
/// this pattern states: `simple_asn1`'s `oid!` builds an owned [`OID`], so there
/// is nothing to make a constant out of.
mod oids {
    use simple_asn1::{OID, oid};

    /// `id-pe-authorityInfoAccess` (RFC 5280 §4.2.2.1) — the extension itself.
    /// rcgen has no support for it, so it is written as a custom extension and
    /// this is the `extnID`.
    pub(super) const AUTHORITY_INFO_ACCESS: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 1, 1];

    /// `id-ad-caIssuers` (RFC 5280 §4.2.2.1) — "the issuer's certificate is
    /// over there". The sibling access method, `id-ad-ocsp`, is deliberately
    /// never written: this server runs no responder.
    pub(super) fn ca_issuers() -> OID {
        oid!(1, 3, 6, 1, 5, 5, 7, 48, 2)
    }
}

/// The extensions naming this CA's own services, validated and encoded.
///
/// [`Default`] is "say nothing", which is what every constructor that takes no
/// configuration (`LocalCa::generate_in_memory`) uses.
#[derive(Debug, Clone, Default)]
pub(super) struct LeafPolicy {
    /// One distribution point per configured *set* of URLs, which in practice
    /// means at most one: several URIs inside a single `DistributionPoint` mean
    /// "the same CRL, reachable at each of these" (§4.2.1.13), which is the
    /// truth here — there is one ledger and one CRL. Several
    /// `DistributionPoint`s would claim several different CRLs.
    crl_distribution_points: Vec<CrlDistributionPoint>,
    /// The whole `authorityInfoAccess` extension, or nothing.
    ///
    /// `Option`, not `Vec`: RFC 5280 §4.2 permits one instance of an extension
    /// OID per certificate, and a future OCSP pointer is another
    /// `AccessDescription` *inside* this one — not a second extension. A `Vec`
    /// here would make "push another" the obvious and wrong next move.
    authority_info_access: Option<CustomExtension>,
}

impl LeafPolicy {
    /// Validates and encodes both lists, or fails startup naming the key and
    /// the value that could not be used.
    pub(super) fn from_config(cfg: &LocalCaConfig) -> anyhow::Result<Self> {
        let crl_urls = check_urls(
            "signer.local_ca.crl_distribution_points",
            &cfg.crl_distribution_points,
        )?;
        let issuer_urls = check_urls("signer.local_ca.ca_issuer_urls", &cfg.ca_issuer_urls)?;

        if !crl_urls.is_empty() || !issuer_urls.is_empty() {
            // Worth a line at startup precisely because nothing later can
            // report on it: these URLs are immutable in every certificate they
            // are baked into, and a typo surfaces weeks later as a relying
            // party that cannot fetch a CRL, nowhere near its cause.
            info!(
                event = "local_ca_leaf_policy_configured",
                outcome = "success",
                crl_distribution_points = ?crl_urls,
                ca_issuer_urls = ?issuer_urls,
            );
        }

        Ok(Self {
            crl_distribution_points: if crl_urls.is_empty() {
                Vec::new()
            } else {
                vec![CrlDistributionPoint { uris: crl_urls }]
            },
            authority_info_access: authority_info_access(&issuer_urls)?,
        })
    }

    /// The `cRLDistributionPoints` value for [`rcgen::CertificateParams`].
    pub(super) fn crl_distribution_points(&self) -> Vec<CrlDistributionPoint> {
        self.crl_distribution_points.clone()
    }

    /// The custom extensions for [`rcgen::CertificateParams`] — the AIA, or
    /// none.
    pub(super) fn custom_extensions(&self) -> Vec<CustomExtension> {
        self.authority_info_access.iter().cloned().collect()
    }
}

/// Checks every URL a list holds, in order, and hands back the ones to write.
///
/// The strictness is deliberate: whatever survives here is signed into
/// certificates that outlive the mistake by `leaf_validity_days`.
fn check_urls(key: &str, values: &[String]) -> anyhow::Result<Vec<String>> {
    let mut checked = Vec::with_capacity(values.len());
    for value in values {
        ensure!(!value.is_empty(), "{key} holds an empty entry");

        // `anyhow!`, never `.context()`: every startup error in this crate is
        // rendered through `CliError(error.to_string())`, which keeps only the
        // outermost message.
        let url = Url::parse(value)
            .map_err(|error| anyhow!("{key} entry `{value}` is not a valid URL: {error}"))?;

        ensure!(
            matches!(url.scheme(), "http" | "https"),
            "{key} entry `{value}` must be http:// or https://: this server publishes \
             the CRL and its own certificate over HTTP and populates no directory, \
             so nothing would answer an ldap:// or ftp:// pointer"
        );
        // `http://` is not a mistake here and gets no warning: a relying party
        // fetching a *signed* CRL or CA certificate over TLS has to validate
        // that connection's certificate first, which is the loop this
        // extension exists to break.

        ensure!(
            url.username().is_empty() && url.password().is_none(),
            "{key} entry `{value}` carries credentials: they would be published \
             in every certificate this CA issues, for the life of each one"
        );

        // Refuse anything the URL parser had to change. Two ways a difference
        // arises and both end with a certificate pointing somewhere other than
        // what was configured: `Url` normalizes (`https://ca.example` gains its
        // `/`, control characters are stripped), and the environment-variable
        // list parser splits on `,` without trimming, so `a, b` yields a second
        // entry with a leading space that would be signed in verbatim.
        //
        // It also settles the encoding: `GeneralName.uniformResourceIdentifier`
        // is an IA5String, and `Url`'s serialization is always ASCII (a host is
        // punycoded, everything else percent-encoded), so a value equal to it
        // needs no separate ASCII check.
        ensure!(
            url.as_str() == value,
            "{key} entry `{value}` is not in normalized form: write it as `{url}`"
        );

        checked.push(value.clone());
    }
    Ok(checked)
}

/// Builds the whole `authorityInfoAccess` extension, or `None` when there is
/// nothing to point at.
///
/// The empty case must not produce an extension holding an empty SEQUENCE:
/// `AuthorityInfoAccessSyntax ::= SEQUENCE SIZE (1..MAX) OF AccessDescription`,
/// and rcgen writes this content into the `extnValue` verbatim, so a `30 00`
/// would ship a malformed certificate rather than an empty one.
fn authority_info_access(urls: &[String]) -> anyhow::Result<Option<CustomExtension>> {
    if urls.is_empty() {
        return Ok(None);
    }

    let descriptions = urls
        .iter()
        .map(|url| access_description(oids::ca_issuers(), url))
        .collect();
    let der = simple_asn1::to_der(&ASN1Block::Sequence(0, descriptions))
        .map_err(|error| anyhow!("encoding the authorityInfoAccess extension: {error}"))?;

    // Non-critical, which RFC 5280 §4.2.2.1 requires, and which
    // `from_oid_content` already is — spelled out rather than relied upon.
    let mut extension = CustomExtension::from_oid_content(oids::AUTHORITY_INFO_ACCESS, der);
    extension.set_criticality(false);
    Ok(Some(extension))
}

/// One `AccessDescription ::= SEQUENCE { accessMethod OBJECT IDENTIFIER,
/// accessLocation GeneralName }`.
///
/// Takes the method as an argument so an `id-ad-ocsp` pointer, if this server
/// ever grows a responder, is one more caller rather than a rewrite.
fn access_description(method: OID, uri: &str) -> ASN1Block {
    ASN1Block::Sequence(
        0,
        vec![
            ASN1Block::ObjectIdentifier(0, method),
            // `uniformResourceIdentifier [6] IA5String`, context-specific and
            // IMPLICIT — so the tag replaces the IA5String's own rather than
            // wrapping it, which is why this is a primitive `Unknown` block
            // (tag byte `0x86`) and not an `Explicit` one.
            ASN1Block::Unknown(
                ASN1Class::ContextSpecific,
                false,
                0,
                BigUint::from(6u8),
                uri.as_bytes().to_vec(),
            ),
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(crl: &[&str], issuers: &[&str]) -> LocalCaConfig {
        LocalCaConfig {
            crl_distribution_points: crl.iter().map(|s| s.to_string()).collect(),
            ca_issuer_urls: issuers.iter().map(|s| s.to_string()).collect(),
            ..LocalCaConfig::default()
        }
    }

    fn error(crl: &[&str], issuers: &[&str]) -> String {
        LeafPolicy::from_config(&config(crl, issuers))
            .expect_err("configuration should be refused")
            .to_string()
    }

    #[test]
    fn the_default_configuration_says_nothing_at_all() {
        let policy = LeafPolicy::from_config(&LocalCaConfig::default()).unwrap();

        assert!(policy.crl_distribution_points().is_empty());
        assert!(
            policy.custom_extensions().is_empty(),
            "an empty list must emit no extension, not an empty SEQUENCE"
        );
    }

    #[test]
    fn every_crl_url_lands_in_one_distribution_point() {
        let policy = LeafPolicy::from_config(&config(
            &["http://ca.example/ca.crl", "http://mirror.example/ca.crl"],
            &[],
        ))
        .unwrap();

        let points = policy.crl_distribution_points();
        assert_eq!(
            points.len(),
            1,
            "several URIs are one CRL reachable in several places, \
             not several different CRLs"
        );
        assert_eq!(
            points[0].uris,
            vec!["http://ca.example/ca.crl", "http://mirror.example/ca.crl"]
        );
        assert!(policy.custom_extensions().is_empty());
    }

    /// The short-form vector: every length fits in one byte.
    #[test]
    fn one_ca_issuer_url_encodes_to_the_expected_der() {
        let policy = LeafPolicy::from_config(&config(&[], &["http://ca.example/ca.crt"])).unwrap();

        let extensions = policy.custom_extensions();
        assert_eq!(extensions.len(), 1);
        let extension = &extensions[0];
        assert!(!extension.criticality(), "RFC 5280 §4.2.2.1: non-critical");
        assert_eq!(
            extension.oid_components().collect::<Vec<_>>(),
            vec![1, 3, 6, 1, 5, 5, 7, 1, 1]
        );

        let uri = b"http://ca.example/ca.crt";
        let mut expected = vec![
            0x30, 0x26, // AuthorityInfoAccessSyntax ::= SEQUENCE, 38 bytes
            0x30, 0x24, // AccessDescription ::= SEQUENCE, 36 bytes
            0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02, // id-ad-caIssuers
            0x86, 0x18, // [6] IMPLICIT IA5String, 24 bytes
        ];
        expected.extend_from_slice(uri);
        assert_eq!(extension.content(), expected.as_slice());
    }

    /// The long-form vector: two long URLs push the outer SEQUENCE past 127
    /// bytes, so its length is written `81 xx` — the branch a hand-rolled
    /// encoder gets wrong.
    #[test]
    fn several_ca_issuer_urls_encode_with_long_form_lengths() {
        let first = format!("http://ca.example/{}/ca.crt", "a".repeat(50));
        let second = format!("http://ca.example/{}/ca.crt", "b".repeat(50));
        let policy =
            LeafPolicy::from_config(&config(&[], &[first.as_str(), second.as_str()])).unwrap();

        let extensions = policy.custom_extensions();
        let content = extensions[0].content();

        // One AccessDescription per URL: 10 bytes of OID + 2 of tag/length +
        // the URI, wrapped in a 2-byte SEQUENCE header.
        let description_len = 2 + 10 + 2 + first.len();
        let total = 2 * description_len;
        assert!(total > 127, "the vector must exercise the long form");
        assert_eq!(
            &content[..3],
            &[0x30, 0x81, total as u8],
            "an outer SEQUENCE over 127 bytes takes a long-form length"
        );
        // Both URIs are present, each behind its own `[6]` tag.
        let uri_header = [0x86, first.len() as u8];
        assert_eq!(
            content.windows(2).filter(|w| *w == uri_header).count(),
            2,
            "each accessLocation is a primitive [6] tag carrying the URI"
        );
        assert!(content.windows(first.len()).any(|w| w == first.as_bytes()));
        assert!(
            content
                .windows(second.len())
                .any(|w| w == second.as_bytes())
        );
    }

    #[test]
    fn an_empty_entry_is_refused() {
        assert!(error(&[""], &[]).contains("holds an empty entry"));
    }

    #[test]
    fn an_unparsable_url_is_refused_naming_the_key_and_the_value() {
        let message = error(&["not a url"], &[]);
        assert!(
            message.contains("signer.local_ca.crl_distribution_points"),
            "{message}"
        );
        assert!(message.contains("not a url"), "{message}");
        assert!(message.contains("not a valid URL"), "{message}");
    }

    #[test]
    fn a_non_http_scheme_is_refused_saying_why() {
        let message = error(&[], &["ldap://ca.example/cn=ca"]);
        assert!(
            message.contains("signer.local_ca.ca_issuer_urls"),
            "{message}"
        );
        assert!(message.contains("must be http:// or https://"), "{message}");
        assert!(message.contains("populates no directory"), "{message}");
    }

    #[test]
    fn a_url_carrying_credentials_is_refused() {
        let message = error(&["https://operator:hunter2@ca.example/ca.crl"], &[]);
        assert!(message.contains("carries credentials"), "{message}");
        assert!(
            message.contains("every certificate this CA issues"),
            "{message}"
        );
    }

    /// The one an operator hits by accident: `ACME_PROXY_…=a,\u{20}b` splits
    /// without trimming, so the second entry arrives with a leading space.
    #[test]
    fn an_unnormalized_url_is_refused_quoting_the_normalized_form() {
        let message = error(&[" http://ca.example/ca.crl"], &[]);
        assert!(message.contains("not in normalized form"), "{message}");
        assert!(
            message.contains("write it as `http://ca.example/ca.crl`"),
            "{message}"
        );

        // A host with no path is the same refusal, since `Url` adds the `/`.
        let message = error(&[], &["https://ca.example"]);
        assert!(
            message.contains("write it as `https://ca.example/`"),
            "{message}"
        );
    }

    #[test]
    fn a_non_ascii_url_is_refused_by_the_normalization_rule() {
        // Percent-encoded on the way in, so this is the shape that reaches the
        // ASCII check with a non-ASCII byte still in the configured string.
        let message = error(&["http://ca.example/café.crl"], &[]);
        assert!(message.contains("not in normalized form"), "{message}");
    }
}
