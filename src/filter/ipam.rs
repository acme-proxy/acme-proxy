//! The `ipam` filter: the client's address must own the names it asks for.
//!
//! The other identifier filter, [`identifiers`](super::identifiers), answers
//! "may *anyone here* have this name certified?" from a static list. This one
//! answers the narrower question the list cannot express: may **this address**
//! have **this name** certified? The answer is not configured — it is read from
//! the [`ipam`](crate::ipam) inventory, which in a managed estate already
//! records it.
//!
//! Everything about *how* the answer is obtained lives in that subsystem: which
//! product, which queries, which sources are trusted, and the budget the whole
//! lookup runs under. What is here is the policy built on the answer, and it is
//! the same policy whichever inventory produced it — which is the point of the
//! split, and why the 403 an operator reads names their own product rather than
//! the one this filter was first written for.
//!
//! ## Matching is exact
//!
//! Case-insensitive and ignoring a trailing dot, but otherwise literal: no
//! suffix rule, no wildcard expansion. An entry `example.com` does **not**
//! permit `a.example.com`, and a request for `*.example.com` requires that
//! exact string in the inventory. This is the same choice
//! [`compile_anchored`](super::compile_anchored) makes for the regex-based
//! filters, for the same reason — a rule that quietly covers more than it says
//! is the bypass an allowlist exists to prevent.
//!
//! An `ip` identifier is permitted when it *is* the connecting address (a
//! machine may always certify the address it is talking from) or when it is
//! listed like any other name. A `cn` is skipped — see
//! [`super::SUBJECT_ONLY_TYPES`]. Any other type is refused: an IPAM has
//! nothing to say about an email address or a URI, and a filter whose job is to
//! confirm entitlement must refuse what it cannot confirm.
//!
//! ## Denied versus Internal
//!
//! "The inventory does not associate this name with this address" is a decision
//! about the client and denies the request. "It answered 500", "the token was
//! refused", "the lookup timed out" are not — the server failed to reach a
//! decision, so they become [`FilterError::Internal`] and surface as a 500 the
//! client can retry. The split is enforced by the types rather than by care
//! here: an [`IpamError`](crate::ipam::IpamError) cannot express a refusal, so
//! every one of them maps to `Internal` and there is no branch in which an
//! outage could fail open.

use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;
use tracing::debug;

use super::{Filter, FilterError, IdentifierContext, SUBJECT_ONLY_TYPES, canonical};
use crate::ipam::{AddressNames, IpamRegistry, normalize};

/// Requires every requested name to be one the inventory associates with the
/// client's address.
#[derive(Debug)]
pub struct IpamFilter {
    ipam: Arc<IpamRegistry>,
}

impl IpamFilter {
    /// Wraps the profile's configured inventory.
    #[must_use]
    pub fn new(ipam: Arc<IpamRegistry>) -> Self {
        Self { ipam }
    }

    /// The names the inventory holds, or the refusal its answer implies.
    async fn permitted_names(&self, client_ip: IpAddr) -> Result<AddressNames, FilterError> {
        let names = self
            .ipam
            .names_for(client_ip)
            .await
            .map_err(|error| FilterError::Internal(error.0))?;

        if !names.is_known() {
            return Err(FilterError::Denied(format!(
                "{} holds no record of {client_ip}",
                self.ipam.backend_name()
            )));
        }

        Ok(names)
    }
}

#[async_trait]
impl Filter for IpamFilter {
    fn name(&self) -> &'static str {
        "ipam"
    }

    async fn check_identifiers(&self, ctx: &IdentifierContext<'_>) -> Result<(), FilterError> {
        let client_ip = ctx.require_client_ip()?;
        let stage = ctx.stage.as_str();
        let backend = self.ipam.backend_name();

        // A CSR carrying nothing but a common name asks the inventory no
        // question, so it is not worth a round trip. Same reasoning as
        // `FilterChain::is_active`.
        if ctx.identifiers.iter().all(is_subject_only) {
            return Ok(());
        }

        let permitted = self.permitted_names(client_ip).await?;
        let names = permitted.names();

        for identifier in ctx.identifiers {
            if is_subject_only(identifier) {
                continue;
            }

            let typ = identifier.typ.to_ascii_lowercase();
            let value = normalize(&identifier.value);

            match typ.as_str() {
                "dns" => {
                    if !names.contains(&value) {
                        return Err(FilterError::Denied(format!(
                            "{stage} identifier {} is not among the names {backend} associates \
                             with {client_ip}",
                            identifier.value
                        )));
                    }
                }
                // A machine may always certify the address it is talking from;
                // any other address has to be listed like a name.
                "ip" => {
                    let is_client = value
                        .parse::<IpAddr>()
                        .is_ok_and(|ip| canonical(ip) == client_ip);
                    if !is_client && !names.contains(&value) {
                        return Err(FilterError::Denied(format!(
                            "{stage} identifier {} is neither {client_ip} nor a name {backend} \
                             associates with it",
                            identifier.value
                        )));
                    }
                }
                other => {
                    return Err(FilterError::Denied(format!(
                        "{stage} requests a {other} identifier, which {backend} cannot confirm \
                         for {client_ip}"
                    )));
                }
            }
        }

        debug!(
            event = "filter_ipam_accepted",
            backend,
            client_ip = %client_ip,
            stage,
            identifiers = ctx.identifiers.len(),
        );
        Ok(())
    }
}

/// Whether this identifier is subject metadata this filter leaves alone.
fn is_subject_only(identifier: &crate::sqlite::order::Identifier) -> bool {
    SUBJECT_ONLY_TYPES.contains(&identifier.typ.to_ascii_lowercase().as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter::{ConnectionContext, IdentifierStage};
    use crate::ipam::{Ipam, IpamError};
    use crate::sqlite::order::Identifier;
    use crate::testutil::identifiers as ids;
    use axum::http::Method;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    /// An inventory answering from a canned set, never touching the network.
    struct StubIpam {
        names: Option<Vec<&'static str>>,
        error: Option<&'static str>,
        calls: AtomicUsize,
    }

    impl StubIpam {
        /// A recorded address owning `names`.
        fn owning(names: &[&'static str]) -> Self {
            Self {
                names: Some(names.to_vec()),
                error: None,
                calls: AtomicUsize::new(0),
            }
        }

        /// An address the inventory has never heard of.
        fn unknown() -> Self {
            Self {
                names: None,
                error: None,
                calls: AtomicUsize::new(0),
            }
        }

        fn failing(error: &'static str) -> Self {
            Self {
                names: None,
                error: Some(error),
                calls: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait]
    impl Ipam for StubIpam {
        fn name(&self) -> &'static str {
            "StubIPAM"
        }

        async fn names_for(&self, _ip: IpAddr) -> Result<AddressNames, IpamError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if let Some(error) = self.error {
                return Err(IpamError(error.to_string()));
            }
            match &self.names {
                None => Ok(AddressNames::Unknown),
                Some(names) => {
                    let mut answer = AddressNames::known();
                    for name in names {
                        answer.insert(name);
                    }
                    Ok(answer)
                }
            }
        }
    }

    fn filter_over(stub: Arc<StubIpam>) -> IpamFilter {
        IpamFilter::new(Arc::new(IpamRegistry::new(stub, Duration::from_secs(5))))
    }

    fn filter(stub: StubIpam) -> IpamFilter {
        filter_over(Arc::new(stub))
    }

    async fn check_from(
        filter: &IpamFilter,
        ip: Option<&str>,
        identifiers: &[Identifier],
    ) -> Result<(), FilterError> {
        filter
            .check_identifiers(&IdentifierContext {
                client_ip: ip.map(|ip| ip.parse().unwrap()),
                account_id: "acct-1",
                stage: IdentifierStage::NewOrder,
                identifiers,
            })
            .await
    }

    async fn check(filter: &IpamFilter, identifiers: &[Identifier]) -> Result<(), FilterError> {
        check_from(filter, Some("10.0.0.5"), identifiers).await
    }

    fn assert_denied(error: FilterError, needle: &str) {
        match error {
            FilterError::Denied(detail) => {
                assert!(detail.contains(needle), "{detail:?} lacks {needle:?}");
            }
            other => panic!("expected Denied, got {other:?}"),
        }
    }

    fn assert_internal(error: FilterError, needle: &str) {
        match error {
            FilterError::Internal(detail) => {
                assert!(detail.contains(needle), "{detail:?} lacks {needle:?}");
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    // ------------------------------------------------------- the happy paths

    #[tokio::test]
    async fn a_listed_name_is_permitted() {
        let filter = filter(StubIpam::owning(&["host.example.com"]));

        check(&filter, &ids(&[("dns", "host.example.com")]))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn matching_ignores_case_and_a_trailing_dot() {
        let filter = filter(StubIpam::owning(&["host.example.com"]));

        check(&filter, &ids(&[("dns", "HOST.example.com.")]))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn every_requested_name_must_be_permitted() {
        let filter = filter(StubIpam::owning(&["a.example.com", "b.example.com"]));

        check(
            &filter,
            &ids(&[("dns", "a.example.com"), ("dns", "b.example.com")]),
        )
        .await
        .unwrap();

        let error = check(
            &filter,
            &ids(&[("dns", "a.example.com"), ("dns", "c.example.com")]),
        )
        .await
        .unwrap_err();
        assert_denied(error, "c.example.com");
    }

    #[tokio::test]
    async fn an_ipv4_mapped_client_is_canonicalized_before_the_lookup() {
        let filter = filter(StubIpam::owning(&["host.example.com"]));

        check_from(
            &filter,
            Some("::ffff:10.0.0.5"),
            &ids(&[("dns", "host.example.com")]),
        )
        .await
        .unwrap();
    }

    // ------------------------------------------------------------- refusals

    /// The refusal names the identifier, the stage and the product, so an
    /// operator reading a 403 knows which inventory to go and edit.
    #[tokio::test]
    async fn an_unlisted_name_is_denied_naming_it_the_stage_and_the_backend() {
        let filter = filter(StubIpam::owning(&["host.example.com"]));

        let error = check(&filter, &ids(&[("dns", "evil.example.com")]))
            .await
            .unwrap_err();
        assert_denied(error, "newOrder identifier evil.example.com");

        let error = check(&filter, &ids(&[("dns", "evil.example.com")]))
            .await
            .unwrap_err();
        assert_denied(error, "StubIPAM associates with 10.0.0.5");
    }

    /// An address the inventory has never heard of is worded differently from
    /// one recorded and entitled to nothing — the reason `AddressNames` is an
    /// enum rather than a set that may be empty.
    #[tokio::test]
    async fn an_unrecorded_address_is_denied_saying_so() {
        let filter = filter(StubIpam::unknown());

        let error = check(&filter, &ids(&[("dns", "host.example.com")]))
            .await
            .unwrap_err();
        assert_denied(error, "StubIPAM holds no record of 10.0.0.5");
    }

    #[tokio::test]
    async fn a_recorded_address_owning_nothing_is_denied_per_name() {
        let filter = filter(StubIpam::owning(&[]));

        let error = check(&filter, &ids(&[("dns", "host.example.com")]))
            .await
            .unwrap_err();
        assert_denied(error, "is not among the names");
    }

    #[tokio::test]
    async fn a_missing_client_address_is_denied() {
        let filter = filter(StubIpam::owning(&["host.example.com"]));

        let error = check_from(&filter, None, &ids(&[("dns", "host.example.com")]))
            .await
            .unwrap_err();
        assert_denied(error, "client address unavailable");
    }

    // --------------------------------------------------- Internal, not Denied

    /// The property the whole `IpamError`/`AddressNames` split exists for: an
    /// outage must stop issuance with a retryable 500, never fail open and
    /// never look like a permanent refusal.
    #[tokio::test]
    async fn a_failed_lookup_is_internal_not_a_denial() {
        let filter = filter(StubIpam::failing("HTTP 500"));

        let error = check(&filter, &ids(&[("dns", "host.example.com")]))
            .await
            .unwrap_err();
        assert_internal(error, "HTTP 500");
    }

    /// The registry's budget surfaces here as an ordinary `Internal`.
    #[tokio::test]
    async fn a_wedged_inventory_times_out_rather_than_hanging() {
        struct Hanging;
        #[async_trait]
        impl Ipam for Hanging {
            fn name(&self) -> &'static str {
                "StubIPAM"
            }
            async fn names_for(&self, _ip: IpAddr) -> Result<AddressNames, IpamError> {
                tokio::time::sleep(Duration::from_secs(3600)).await;
                unreachable!("the registry's budget expires first")
            }
        }

        let filter = IpamFilter::new(Arc::new(IpamRegistry::new(
            Arc::new(Hanging),
            Duration::from_millis(10),
        )));

        let error = check(&filter, &ids(&[("dns", "host.example.com")]))
            .await
            .unwrap_err();
        assert_internal(error, "timed out after 10ms");
    }

    // -------------------------------------------------------------- wildcards

    #[tokio::test]
    async fn a_wildcard_needs_the_literal_entry() {
        let filter = filter(StubIpam::owning(&["example.com"]));

        let error = check(&filter, &ids(&[("dns", "*.example.com")]))
            .await
            .unwrap_err();
        assert_denied(error, "*.example.com");
    }

    #[tokio::test]
    async fn a_literal_wildcard_entry_permits_the_wildcard() {
        let filter = filter(StubIpam::owning(&["*.example.com"]));

        check(&filter, &ids(&[("dns", "*.example.com")]))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_wildcard_entry_does_not_expand_to_subdomains() {
        let filter = filter(StubIpam::owning(&["*.example.com"]));

        let error = check(&filter, &ids(&[("dns", "a.example.com")]))
            .await
            .unwrap_err();
        assert_denied(error, "a.example.com");
    }

    // ------------------------------------------------------ identifier types

    #[tokio::test]
    async fn the_connecting_address_may_always_be_certified() {
        let filter = filter(StubIpam::owning(&["host.example.com"]));

        check(&filter, &ids(&[("ip", "10.0.0.5")])).await.unwrap();
    }

    #[tokio::test]
    async fn another_address_is_denied_unless_listed() {
        let filter = filter(StubIpam::owning(&["host.example.com"]));

        let error = check(&filter, &ids(&[("ip", "10.0.0.9")]))
            .await
            .unwrap_err();
        assert_denied(error, "10.0.0.9");
    }

    #[tokio::test]
    async fn another_address_may_be_listed_like_any_other_name() {
        let filter = filter(StubIpam::owning(&["10.0.0.9"]));

        check(&filter, &ids(&[("ip", "10.0.0.9")])).await.unwrap();
    }

    #[tokio::test]
    async fn a_common_name_is_left_alone() {
        let filter = filter(StubIpam::owning(&["host.example.com"]));

        check(
            &filter,
            &ids(&[
                ("dns", "host.example.com"),
                ("cn", "rcgen self signed cert"),
            ]),
        )
        .await
        .unwrap();
    }

    /// No round trip at all for a CSR carrying nothing but a common name.
    #[tokio::test]
    async fn a_request_of_common_names_alone_asks_the_inventory_nothing() {
        let stub = Arc::new(StubIpam::failing("must not be called"));
        let filter = filter_over(stub.clone());

        check(&filter, &ids(&[("cn", "some label")])).await.unwrap();
        assert_eq!(stub.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_type_an_inventory_cannot_speak_to_is_denied() {
        let filter = filter(StubIpam::owning(&["host.example.com"]));

        for typ in ["email", "uri", "other"] {
            let error = check(&filter, &ids(&[(typ, "whatever")]))
                .await
                .unwrap_err();
            assert_denied(error, &format!("requests a {typ} identifier"));
        }
    }

    // ------------------------------------------------------ startup + wiring

    #[test]
    fn reports_its_config_name() {
        assert_eq!(filter(StubIpam::unknown()).name(), "ipam");
    }

    #[tokio::test]
    async fn does_not_inspect_connections() {
        let stub = Arc::new(StubIpam::failing("must not be called"));
        let filter = filter_over(stub.clone());

        filter
            .check_connection(&ConnectionContext {
                client_ip: Some("203.0.113.9".parse().unwrap()),
                method: &Method::POST,
                path: "/newOrder",
            })
            .await
            .unwrap();
        assert_eq!(stub.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn the_debug_impl_names_the_backend() {
        let rendered = format!("{:?}", filter(StubIpam::unknown()));
        assert!(rendered.contains("StubIPAM"), "{rendered}");
    }
}
