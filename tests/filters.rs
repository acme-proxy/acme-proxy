//! Covers the request-filtering subsystem end-to-end through the real router:
//! the connection-level middleware (IP allowlist, exempt paths, trusted-proxy
//! handling, a filter that fails to decide) and the identifier hook at both the
//! newOrder and finalize stages (including a CSR that smuggles an IP SAN or
//! hides its target in the common name).
//!
//! Client addresses are supplied by inserting the `ConnectInfo` extension that
//! `axum::serve` would add, so the suite still drives the router with `oneshot`
//! and binds no socket.

use std::sync::Arc;

use std::collections::BTreeMap;

use acme_proxy::config::{
    CheckConfig, Config, DnsConfig, FilterConfig, IpamConfig, NetboxConfig, PhpIpamConfig,
    RuleConfig,
};
use acme_proxy::filter::policy::{Check, StageSet, Verdict};
use acme_proxy::filter::{self, IdentifierContext, IdentifierStage};
use acme_proxy::signer::local_ca::LocalCa;
use async_trait::async_trait;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use serde_json::{Value, json};

mod common;
use common::{
    EcSigner, RejectingCheck, TestSigner, body_json, default_challenges, fetch_nonce_from,
    make_csr, make_csr_with_sans, no_notifications, p, policy_of, policy_with, post_from,
    send_from, test_app_full, test_app_with_filter,
};

const NEW_ACCOUNT_URL: &str = "http://localhost:3000/profile/default/newAccount";
const NEW_ORDER_URL: &str = "http://localhost:3000/profile/default/newOrder";

/// The address every test uses unless it is specifically testing rejection.
const ALLOWED: &str = "192.168.1.5:40000";
const BLOCKED: &str = "203.0.113.9:40000";

/// The shared resolver `Profile::build_all` would hand the filter chain. These
/// tests reach loopback by IP literal, which `dns::connect` short-circuits, so
/// the system configuration is never actually consulted.
fn test_resolver() -> Arc<dyn acme_proxy::dns::Resolver> {
    Arc::new(acme_proxy::dns::HickoryResolver::from_system_uncached().unwrap())
}

// ---------------------------------------------------------------- helpers

/// Builds an app from a `[filter]` configuration, exactly as `from_config`
/// would at startup.
async fn app_with_config(filter: FilterConfig) -> Router {
    app_with_ipam(filter, &IpamConfig::default()).await
}

/// The same, with an `[ipam]` section — the two are built together at startup,
/// `[ipam]` first, exactly as `Profile::build_all` does it.
async fn app_with_ipam(filter: FilterConfig, ipam: &IpamConfig) -> Router {
    let inventory = acme_proxy::ipam::from_config(
        ipam,
        test_resolver(),
        std::sync::Arc::new(acme_proxy::proxy::OutboundProxies::direct()),
    )
    .expect("ipam config should build");
    let chain = filter::from_config(&filter, &DnsConfig::default(), inventory)
        .expect("filter config should build");
    let signer = Arc::new(LocalCa::generate_in_memory("ecdsa-p256", 90).unwrap());
    test_app_full(
        Config::default(),
        signer,
        chain,
        default_challenges(),
        no_notifications(),
    )
    .await
    .0
}

/// Which stages a check type decides at, so [`policy_config`] can group the
/// checks into one rule per stage the way the policy engine itself does.
fn stages_of(kind: &str) -> StageSet {
    match kind {
        "allowed_ip" | "custom" => StageSet::both(),
        "reverse_dns" => StageSet::connection_only(),
        _ => StageSet::identifiers_only(),
    }
}

/// A `[filter]` config where **every** named check must pass.
///
/// One rule per stage, each a conjunction of the checks that can decide there
/// — the all-must-pass shape most of this suite wants, without a rule table
/// per test. Tests exercising the *policy* (`or`, `not`, `warn`, `message`)
/// write their own configuration.
fn policy_config(checks: &[(&str, CheckConfig)]) -> FilterConfig {
    let mut rules = Vec::new();
    let mut rule = BTreeMap::new();

    for (stage, label) in [
        (acme_proxy::filter::Stage::Connection, "connection"),
        (acme_proxy::filter::Stage::Identifiers, "identifiers"),
    ] {
        let names: Vec<&str> = checks
            .iter()
            .filter(|(_, config)| stages_of(&config.r#type).contains(stage))
            .map(|(name, _)| *name)
            .collect();
        if names.is_empty() {
            continue;
        }
        let rule_name = format!("all-{label}");
        rules.push(rule_name.clone());
        rule.insert(
            rule_name,
            RuleConfig {
                when: names.join(" and "),
                then: "allow".to_string(),
                ..RuleConfig::default()
            },
        );
    }

    FilterConfig {
        rules,
        rule,
        check: checks
            .iter()
            .map(|(name, config)| ((*name).to_string(), config.clone()))
            .collect(),
        ..FilterConfig::default()
    }
}

fn strings(values: &[&str]) -> Vec<String> {
    values
        .iter()
        .map(std::string::ToString::to_string)
        .collect()
}

/// A `[filter]` config with only an IP allowlist for `192.168.1.0/24`.
fn ip_allowlist_config() -> FilterConfig {
    ip_config(&["192.168.1.0/24"], &[])
}

/// A `[filter]` config with only an `allowed_ip` check, with the given lists.
fn ip_config(allow: &[&str], deny: &[&str]) -> FilterConfig {
    policy_config(&[(
        "net",
        CheckConfig {
            r#type: "allowed_ip".to_string(),
            allow: strings(allow),
            deny: strings(deny),
            ..CheckConfig::default()
        },
    )])
}

/// A `[filter]` config with only an identifier list, written as regexes —
/// which is what this suite's patterns are.
fn identifiers_config(allow: &[&str], deny: &[&str]) -> FilterConfig {
    policy_config(&[(
        "names",
        CheckConfig {
            r#type: "identifiers".to_string(),
            allow_regex: strings(allow),
            deny_regex: strings(deny),
            ..CheckConfig::default()
        },
    )])
}

async fn assert_problem(res: Response, status: StatusCode, typ: &str) -> Value {
    assert_eq!(res.status(), status);
    let problem = body_json(res).await;
    assert_eq!(problem["type"], typ);
    problem
}

/// Registers an account from `peer` and returns its account URL (the `kid`).
async fn register(app: &Router, signer: &EcSigner, peer: &str) -> String {
    let nonce = fetch_nonce_from(app, peer).await;
    let payload = json!({ "termsOfServiceAgreed": true });
    let res = post_from(
        app,
        &p("/newAccount"),
        signer.sign(NEW_ACCOUNT_URL, &nonce, &payload),
        peer,
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED);
    res.headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .expect("newAccount must set a Location header")
        .to_string()
}

/// Creates an order for `dns`, returning the response untouched.
async fn new_order(app: &Router, signer: &EcSigner, account_url: &str, dns: &str) -> Response {
    let nonce = fetch_nonce_from(app, ALLOWED).await;
    let payload = json!({ "identifiers": [{ "type": "dns", "value": dns }] });
    let body = signer.sign_kid(account_url, NEW_ORDER_URL, &nonce, &payload);
    post_from(app, &p("/newOrder"), body, ALLOWED).await
}

async fn post_as_get(app: &Router, signer: &EcSigner, account_url: &str, url: &str) -> Value {
    let path = url.strip_prefix(common::HOST).unwrap();
    let nonce = fetch_nonce_from(app, ALLOWED).await;
    let body = signer.sign_kid_empty(account_url, url, &nonce);
    let res = post_from(app, path, body, ALLOWED).await;
    assert_eq!(res.status(), StatusCode::OK);
    body_json(res).await
}

/// Drives every challenge of an order to `valid` so the order becomes `ready`.
async fn drive_to_ready(app: &Router, signer: &EcSigner, account_url: &str, order_url: &str) {
    let order = post_as_get(app, signer, account_url, order_url).await;
    let authz_urls: Vec<String> = order["authorizations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();

    for authz_url in authz_urls {
        let authz = post_as_get(app, signer, account_url, &authz_url).await;
        let challenge_url = authz["challenges"][0]["url"].as_str().unwrap().to_string();
        let path = challenge_url.strip_prefix(common::HOST).unwrap();
        let nonce = fetch_nonce_from(app, ALLOWED).await;
        let body = signer.sign_kid(account_url, &challenge_url, &nonce, &json!({}));
        let res = post_from(app, path, body, ALLOWED).await;
        assert_eq!(res.status(), StatusCode::OK);
    }
}

/// Registers, orders `dns`, and drives it to `ready`. Returns the finalize URL.
async fn ready_order(app: &Router, signer: &EcSigner, dns: &str) -> (String, String) {
    let account_url = register(app, signer, ALLOWED).await;
    let res = new_order(app, signer, &account_url, dns).await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let order_url = res
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .to_string();
    drive_to_ready(app, signer, &account_url, &order_url).await;
    (account_url, format!("{order_url}/finalize"))
}

/// Finalizes with a caller-supplied base64url CSR.
async fn finalize(
    app: &Router,
    signer: &EcSigner,
    account_url: &str,
    finalize_url: &str,
    csr: String,
) -> Response {
    let path = finalize_url.strip_prefix(common::HOST).unwrap();
    let nonce = fetch_nonce_from(app, ALLOWED).await;
    let body = signer.sign_kid(account_url, finalize_url, &nonce, &json!({ "csr": csr }));
    post_from(app, path, body, ALLOWED).await
}

// ------------------------------------------------- connection-level filters

#[tokio::test]
async fn an_allowed_address_reaches_the_handler() {
    let app = app_with_config(ip_allowlist_config()).await;
    let res = send_from(
        &app,
        Request::get(p("/directory")).body(Body::empty()).unwrap(),
        ALLOWED,
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn a_blocked_address_gets_a_403_problem_document() {
    let app = app_with_config(ip_allowlist_config()).await;
    let res = send_from(
        &app,
        Request::get(p("/directory")).body(Body::empty()).unwrap(),
        BLOCKED,
    )
    .await;
    let problem = assert_problem(
        res,
        StatusCode::FORBIDDEN,
        "urn:ietf:params:acme:error:unauthorized",
    )
    .await;
    // The detail names the address, so an operator reading a client's log can
    // see which rule to change.
    assert!(
        problem["detail"].as_str().unwrap().contains("203.0.113.9"),
        "{problem}"
    );
}

/// Blocklist mode: no allow list at all, so everything is served except the
/// addresses explicitly refused.
#[tokio::test]
async fn a_deny_only_config_blocks_only_the_listed_addresses() {
    let app = app_with_config(ip_config(&[], &["203.0.113.0/24"])).await;

    let res = send_from(
        &app,
        Request::get(p("/directory")).body(Body::empty()).unwrap(),
        BLOCKED,
    )
    .await;
    let problem = assert_problem(
        res,
        StatusCode::FORBIDDEN,
        "urn:ietf:params:acme:error:unauthorized",
    )
    .await;
    assert!(
        problem["detail"]
            .as_str()
            .unwrap()
            .contains("203.0.113.9 is denied"),
        "{problem}"
    );

    // An address nobody listed is served — the whole point of blocklist mode.
    let res = send_from(
        &app,
        Request::get(p("/directory")).body(Body::empty()).unwrap(),
        ALLOWED,
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
}

/// `deny` wins over `allow`, so a subnet can be admitted with a hole in it.
#[tokio::test]
async fn deny_punches_a_hole_in_the_allow_list() {
    let app = app_with_config(ip_config(&["192.168.1.0/24"], &["192.168.1.5"])).await;

    // ALLOWED is 192.168.1.5 — inside the allowed subnet, but denied by name.
    let res = send_from(
        &app,
        Request::get(p("/directory")).body(Body::empty()).unwrap(),
        ALLOWED,
    )
    .await;
    let problem = assert_problem(
        res,
        StatusCode::FORBIDDEN,
        "urn:ietf:params:acme:error:unauthorized",
    )
    .await;
    assert!(
        problem["detail"]
            .as_str()
            .unwrap()
            .contains("192.168.1.5 is denied"),
        "{problem}"
    );

    // Its neighbour in the same subnet is still served.
    let res = send_from(
        &app,
        Request::get(p("/directory")).body(Body::empty()).unwrap(),
        "192.168.1.6:40000",
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
}

/// Enabling the filter with neither list populated would accept everything, so
/// it is caught at startup rather than running inert.
#[test]
fn enabling_the_ip_filter_with_no_lists_is_a_startup_error() {
    let error = filter::from_config(&ip_config(&[], &[]), &DnsConfig::default(), None)
        .unwrap_err()
        .to_string();
    assert!(error.contains("would accept every request"), "{error}");
}

/// The layer ordering guarantee: a refusal still hands the client a nonce, so
/// its next attempt fails on the real reason rather than on `badNonce`.
///
/// Driven with a POST, which is what RFC 8555 §6.5 asks for a nonce on — and
/// what makes this test about layer *ordering* (nonce outside filter) rather
/// than about the nonce middleware running at all. A GET would be refused a
/// nonce by the middleware itself, whatever the filter did.
#[tokio::test]
async fn a_rejection_still_carries_a_replay_nonce() {
    let app = app_with_config(ip_allowlist_config()).await;
    let res = send_from(
        &app,
        Request::post(p("/newAccount"))
            .header("content-type", "application/jose+json")
            .body(Body::from("{}"))
            .unwrap(),
        BLOCKED,
    )
    .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert!(
        res.headers().get("replay-nonce").is_some(),
        "a filtered-out response must still mint a nonce"
    );
}

/// `/health` is served by the *root* router, which no profile's policy ever
/// sees — which is why nothing has to be exempted for a health probe to keep
/// working from a blocked address.
#[tokio::test]
async fn a_server_level_route_is_reachable_from_a_blocked_address() {
    let app = app_with_config(ip_allowlist_config()).await;
    let res = send_from(
        &app,
        Request::get("/health").body(Body::empty()).unwrap(),
        BLOCKED,
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn a_profile_route_is_still_filtered() {
    let app = app_with_config(ip_allowlist_config()).await;
    let res = send_from(
        &app,
        Request::get(p("/newNonce")).body(Body::empty()).unwrap(),
        BLOCKED,
    )
    .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

/// Without `ConnectInfo` there is no peer address, and an allowlist must fail
/// closed rather than admit the request.
#[tokio::test]
async fn a_request_with_no_peer_address_is_refused() {
    use tower::ServiceExt;

    let app = app_with_config(ip_allowlist_config()).await;
    let res = app
        .oneshot(Request::get(p("/directory")).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_filter_that_cannot_decide_returns_500_not_403() {
    let chain = policy_with(Arc::new(RejectingCheck::failing()));
    let (app, _db) = test_app_with_filter(chain).await;

    let res = send_from(
        &app,
        Request::get(p("/directory")).body(Body::empty()).unwrap(),
        ALLOWED,
    )
    .await;
    assert_problem(
        res,
        StatusCode::INTERNAL_SERVER_ERROR,
        "urn:ietf:params:acme:error:serverInternal",
    )
    .await;
}

#[tokio::test]
async fn every_filter_must_pass() {
    // First filter allows, second refuses: the chain still denies.
    let chain = policy_of(vec![
        (
            "names".to_string(),
            Arc::new(RejectingCheck::identifiers()) as Arc<dyn Check>,
        ),
        ("net".to_string(), Arc::new(RejectingCheck::connections())),
    ]);
    let (app, _db) = test_app_with_filter(chain).await;

    let res = send_from(
        &app,
        Request::get(p("/directory")).body(Body::empty()).unwrap(),
        ALLOWED,
    )
    .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

// -------------------------------------------------------- forwarded headers

#[tokio::test]
async fn a_spoofed_forwarded_header_does_not_grant_access() {
    // No proxy is trusted, so the header is ignored and the real peer decides.
    let app = app_with_config(ip_allowlist_config()).await;
    let res = send_from(
        &app,
        Request::get(p("/directory"))
            .header("x-forwarded-for", "192.168.1.5")
            .body(Body::empty())
            .unwrap(),
        BLOCKED,
    )
    .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_trusted_proxy_can_forward_the_real_client() {
    let config = FilterConfig {
        trusted_proxies: vec!["10.9.9.9".to_string()],
        ..ip_allowlist_config()
    };
    let app = app_with_config(config).await;

    // Allowed client behind the proxy → through.
    let res = send_from(
        &app,
        Request::get(p("/directory"))
            .header("x-forwarded-for", "192.168.1.5")
            .body(Body::empty())
            .unwrap(),
        "10.9.9.9:40000",
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);

    // Blocked client behind the same proxy → refused. The proxy's own address
    // must not launder it through.
    let res = send_from(
        &app,
        Request::get(p("/directory"))
            .header("x-forwarded-for", "203.0.113.9")
            .body(Body::empty())
            .unwrap(),
        "10.9.9.9:40000",
    )
    .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

// -------------------------------------------------- identifiers at newOrder

/// The identifier hook has its own `Internal` → 500 mapping, in `newOrder`
/// rather than in the middleware. A filter that cannot decide must not be
/// reported to the client as a policy refusal: `rejectedIdentifier` says "we
/// will never issue this name", which is a different and permanent claim.
#[tokio::test]
async fn a_filter_that_cannot_decide_about_identifiers_returns_500() {
    let chain = policy_with(Arc::new(RejectingCheck::failing_identifiers()));
    let (app, _db) = test_app_with_filter(chain).await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer, ALLOWED).await;

    let res = new_order(&app, &signer, &account_url, "host.example.com").await;
    assert_problem(
        res,
        StatusCode::INTERNAL_SERVER_ERROR,
        "urn:ietf:params:acme:error:serverInternal",
    )
    .await;
}

#[tokio::test]
async fn a_permitted_identifier_creates_an_order() {
    let app = app_with_config(identifiers_config(&[r".*\.example\.com"], &[])).await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer, ALLOWED).await;

    let res = new_order(&app, &signer, &account_url, "host.example.com").await;
    assert_eq!(res.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn a_denied_identifier_is_rejected_at_new_order() {
    let app = app_with_config(identifiers_config(&[], &[r".*\.internal\.example\.com"])).await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer, ALLOWED).await;

    let res = new_order(&app, &signer, &account_url, "db.internal.example.com").await;
    let problem = assert_problem(
        res,
        StatusCode::FORBIDDEN,
        "urn:ietf:params:acme:error:rejectedIdentifier",
    )
    .await;
    assert!(
        problem["detail"]
            .as_str()
            .unwrap()
            .contains("db.internal.example.com"),
        "{problem}"
    );
}

#[tokio::test]
async fn an_identifier_outside_the_allow_list_is_rejected() {
    let app = app_with_config(identifiers_config(&[r".*\.example\.com"], &[])).await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer, ALLOWED).await;

    let res = new_order(&app, &signer, &account_url, "host.evil.net").await;
    assert_problem(
        res,
        StatusCode::FORBIDDEN,
        "urn:ietf:params:acme:error:rejectedIdentifier",
    )
    .await;
}

/// Patterns are anchored, so an allowlisted domain cannot be used as a prefix
/// of an attacker-controlled one.
#[tokio::test]
async fn a_lookalike_suffix_cannot_bypass_the_allow_list() {
    let app = app_with_config(identifiers_config(&[r"example\.com"], &[])).await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer, ALLOWED).await;

    let res = new_order(&app, &signer, &account_url, "example.com.evil.net").await;
    assert_problem(
        res,
        StatusCode::FORBIDDEN,
        "urn:ietf:params:acme:error:rejectedIdentifier",
    )
    .await;
}

// --------------------------------------------------- identifiers at finalize

#[tokio::test]
async fn a_permitted_csr_finalizes_normally() {
    let app = app_with_config(identifiers_config(&[r".*\.example\.com"], &[])).await;
    let signer = EcSigner::new();
    let (account_url, finalize_url) = ready_order(&app, &signer, "host.example.com").await;

    let res = finalize(
        &app,
        &signer,
        &account_url,
        &finalize_url,
        make_csr("host.example.com"),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let order = body_json(res).await;
    assert_eq!(order["status"], "valid");
}

/// Refuses one name, but only at the CSR stage — so an order can be created and
/// driven to `ready` before the policy bites. Proves the finalize hook really
/// runs, and that a refusal there maps to `badCSR` rather than
/// `rejectedIdentifier`.
struct DenyAtCsr(&'static str);

#[async_trait]
impl Check for DenyAtCsr {
    fn kind(&self) -> &'static str {
        "deny-at-csr"
    }

    fn stages(&self) -> StageSet {
        StageSet::identifiers_only()
    }

    async fn check_identifiers(&self, ctx: &IdentifierContext<'_>) -> Verdict {
        if ctx.stage == IdentifierStage::Csr && ctx.identifiers.iter().any(|id| id.value == self.0)
        {
            return Verdict::Fail(format!("{} refused at CSR stage", self.0));
        }
        Verdict::Pass
    }
}

#[tokio::test]
async fn a_denied_csr_name_is_rejected_at_finalize_as_bad_csr() {
    let chain = policy_with(Arc::new(DenyAtCsr("host.example.com")));
    let (app, _db) = test_app_with_filter(chain).await;
    let signer = EcSigner::new();

    // newOrder is untouched by this filter, so the order reaches `ready`.
    let (account_url, finalize_url) = ready_order(&app, &signer, "host.example.com").await;

    let res = finalize(
        &app,
        &signer,
        &account_url,
        &finalize_url,
        make_csr("host.example.com"),
    )
    .await;
    let problem = assert_problem(
        res,
        StatusCode::BAD_REQUEST,
        "urn:ietf:params:acme:error:badCSR",
    )
    .await;
    assert!(
        problem["detail"]
            .as_str()
            .unwrap()
            .contains("refused at CSR stage"),
        "{problem}"
    );
}

/// A CSR whose DNS SAN matches the order but which also asks for an IP address.
/// The default `allowed_types` refuses it before the signer is reached.
#[tokio::test]
async fn a_csr_smuggling_an_ip_san_is_rejected() {
    let app = app_with_config(identifiers_config(&[], &[])).await;
    let signer = EcSigner::new();
    let (account_url, finalize_url) = ready_order(&app, &signer, "host.example.com").await;

    let csr = make_csr_with_sans(
        "host.example.com",
        vec![rcgen::SanType::IpAddress("10.0.0.1".parse().unwrap())],
    );
    let res = finalize(&app, &signer, &account_url, &finalize_url, csr).await;
    let problem = assert_problem(
        res,
        StatusCode::BAD_REQUEST,
        "urn:ietf:params:acme:error:badCSR",
    )
    .await;
    // The refusal must be about the smuggled *address*, not about the DNS name
    // that was legitimately ordered.
    //
    // This is now refused by `post_finalize` itself rather than by the filter
    // chain, which is why the detail names the SAN kind rather than the address:
    // an order can only ever carry `dns` identifiers, so a non-DNS SAN asks for
    // something no order could have authorized, and that has to hold whether or
    // not an operator configured a filter. The filter's own projection of
    // `ip`/`email`/`uri` SANs is still covered by the unit tests in
    // `src/filter/identifiers.rs` and `csr_identifiers`.
    let detail = problem["detail"].as_str().unwrap();
    assert!(
        detail.contains("not a DNS name"),
        "detail should name the refused SAN kind, got {detail:?}"
    );
}

/// The bypass this closes: a benign SAN with the real target hidden in the
/// subject's common name.
///
/// Now caught by `post_finalize` before the filter chain is consulted — a
/// DNS-shaped common name naming a domain the order does not cover is refused
/// whether or not a filter is configured, which is the stronger property. The
/// filter's own reach over `cn` is exercised by
/// `a_denied_common_name_within_the_order_is_still_refused_by_the_filter` below.
#[tokio::test]
async fn a_csr_hiding_a_denied_name_in_the_common_name_is_rejected() {
    let app = app_with_config(identifiers_config(&[], &[r".*\.internal\.example\.com"])).await;
    let signer = EcSigner::new();
    let (account_url, finalize_url) = ready_order(&app, &signer, "host.example.com").await;

    let key_pair = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["host.example.com".to_string()]).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "db.internal.example.com");
    let csr_der = params.serialize_request(&key_pair).unwrap();
    use base64::prelude::*;
    let csr = BASE64_URL_SAFE_NO_PAD.encode(csr_der.der());

    let res = finalize(&app, &signer, &account_url, &finalize_url, csr).await;
    let problem = assert_problem(
        res,
        StatusCode::BAD_REQUEST,
        "urn:ietf:params:acme:error:badCSR",
    )
    .await;
    assert!(
        problem["detail"]
            .as_str()
            .unwrap()
            .contains("common name is a domain the order does not cover"),
        "{problem}"
    );
}

/// The filter's `cn` reach, on a CSR that `post_finalize` has already accepted.
///
/// A bare short hostname carries no dot, so the handler's order-binding check
/// reads it as a human label and lets it through — exactly as intended, since
/// refusing every label would break clients whose CN is descriptive text. The
/// refusal here can therefore only come from the filter's `deny` list, which
/// reaches `cn` even though `allow` deliberately does not
/// (`SUBJECT_ONLY_TYPES`). This is what remains of the `cn` hook's reach once
/// DNS-shaped names are settled before the chain runs.
#[tokio::test]
async fn a_denied_common_name_label_is_still_refused_by_the_filter() {
    let app = app_with_config(identifiers_config(&[], &[r"internal-.*"])).await;
    let signer = EcSigner::new();
    let (account_url, finalize_url) = ready_order(&app, &signer, "host.example.com").await;

    let key_pair = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["host.example.com".to_string()]).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "internal-db");
    let csr_der = params.serialize_request(&key_pair).unwrap();
    use base64::prelude::*;
    let csr = BASE64_URL_SAFE_NO_PAD.encode(csr_der.der());

    let res = finalize(&app, &signer, &account_url, &finalize_url, csr).await;
    let problem = assert_problem(
        res,
        StatusCode::BAD_REQUEST,
        "urn:ietf:params:acme:error:badCSR",
    )
    .await;
    assert!(
        problem["detail"].as_str().unwrap().contains("internal-db"),
        "{problem}"
    );
}

#[tokio::test]
async fn an_unparsable_csr_is_rejected_before_the_signer() {
    use base64::prelude::*;

    let app = app_with_config(identifiers_config(&[], &[])).await;
    let signer = EcSigner::new();
    let (account_url, finalize_url) = ready_order(&app, &signer, "host.example.com").await;

    let csr = BASE64_URL_SAFE_NO_PAD.encode([0xde, 0xad, 0xbe, 0xef]);
    let res = finalize(&app, &signer, &account_url, &finalize_url, csr).await;
    assert_problem(
        res,
        StatusCode::BAD_REQUEST,
        "urn:ietf:params:acme:error:badCSR",
    )
    .await;
}

// ------------------------------------------------------------ default state

/// The whole subsystem is inert unless configured, so an unconfigured server
/// behaves exactly as it did before it existed.
#[tokio::test]
async fn the_default_configuration_filters_nothing() {
    let app = app_with_config(FilterConfig::default()).await;
    let signer = EcSigner::new();

    // No ConnectInfo at all, and an order for an arbitrary name: both fine.
    let account_url = register(&app, &signer, BLOCKED).await;
    let res = new_order(&app, &signer, &account_url, "anything.example.org").await;
    assert_eq!(res.status(), StatusCode::CREATED);
}

// ------------------------------------------------------------ custom filter

#[tokio::test]
async fn a_custom_script_filter_enforces_policy_end_to_end() {
    use std::fs;

    let dir = std::env::temp_dir().join(format!("acme-proxy-test-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&dir).unwrap();
    let script_path = dir.join("filter.sh");

    let script_content = r#"#!/bin/sh
if [ "$ACME_FILTER_IDENTIFIERS" = "forbidden.example.com" ]; then
    echo "domain forbidden by custom script"
    exit 1
fi
exit 0
"#;
    fs::write(&script_path, script_content).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&script_path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    let filter_cfg = policy_config(&[(
        "main",
        CheckConfig {
            r#type: "custom".to_string(),
            script_path: script_path.to_str().unwrap().to_string(),
            ..CheckConfig::default()
        },
    )]);

    let app = app_with_config(filter_cfg).await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer, ALLOWED).await;

    // Allowed domain succeeds
    let res_ok = new_order(&app, &signer, &account_url, "allowed.example.com").await;
    assert_eq!(res_ok.status(), StatusCode::CREATED);

    // Forbidden domain fails
    let res_fail = new_order(&app, &signer, &account_url, "forbidden.example.com").await;
    assert_problem(
        res_fail,
        StatusCode::FORBIDDEN,
        "urn:ietf:params:acme:error:rejectedIdentifier",
    )
    .await;

    let _ = fs::remove_dir_all(&dir);
}

/// `filter.custom` is a list: two independent scripts, each with its own
/// policy, both spliced into the same all-must-pass chain. Proves both
/// actually run (each refuses a different name the other would allow) rather
/// than only the first `[[filter.custom]]` entry taking effect.
#[tokio::test]
async fn two_custom_script_filters_both_run() {
    use std::fs;

    let dir = std::env::temp_dir().join(format!("acme-proxy-test-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&dir).unwrap();

    let write_script = |name: &str, forbidden: &str| -> std::path::PathBuf {
        let script_path = dir.join(name);
        let content = format!(
            "#!/bin/sh\nif [ \"$ACME_FILTER_IDENTIFIERS\" = \"{forbidden}\" ]; then\n    echo \"forbidden by {name}\"\n    exit 1\nfi\nexit 0\n"
        );
        fs::write(&script_path, content).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&script_path, fs::Permissions::from_mode(0o755)).unwrap();
        }
        script_path
    };

    let script_a = write_script("a.sh", "forbidden-by-a.example.com");
    let script_b = write_script("b.sh", "forbidden-by-b.example.com");

    let filter_cfg = policy_config(&[
        (
            "a",
            CheckConfig {
                r#type: "custom".to_string(),
                script_path: script_a.to_str().unwrap().to_string(),
                ..CheckConfig::default()
            },
        ),
        (
            "b",
            CheckConfig {
                r#type: "custom".to_string(),
                script_path: script_b.to_str().unwrap().to_string(),
                ..CheckConfig::default()
            },
        ),
    ]);

    let app = app_with_config(filter_cfg).await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer, ALLOWED).await;

    // Neither script objects.
    let res_ok = new_order(&app, &signer, &account_url, "allowed.example.com").await;
    assert_eq!(res_ok.status(), StatusCode::CREATED);

    // Refused by the first script.
    let res_a = new_order(&app, &signer, &account_url, "forbidden-by-a.example.com").await;
    assert_problem(
        res_a,
        StatusCode::FORBIDDEN,
        "urn:ietf:params:acme:error:rejectedIdentifier",
    )
    .await;

    // Refused by the second script — proves it runs too, not just the first.
    let res_b = new_order(&app, &signer, &account_url, "forbidden-by-b.example.com").await;
    assert_problem(
        res_b,
        StatusCode::FORBIDDEN,
        "urn:ietf:params:acme:error:rejectedIdentifier",
    )
    .await;

    let _ = fs::remove_dir_all(&dir);
}

// -------------------------------------------------------------- ipam filter

/// An inventory stub on a loopback socket, answering the address query the
/// backend makes.
///
/// A real socket rather than a trait stub on purpose: the unit tests already
/// pin the policy against a stub, so what is left to prove here is that the
/// filter built by `from_config` — real HTTP client included — refuses and
/// admits the right orders through the real router.
mod netbox_stub {
    use serde_json::{Value, json};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Serves the same JSON body to every request until dropped.
    pub struct Stub {
        pub port: u16,
        _task: tokio::task::JoinHandle<()>,
    }

    /// Serves `status` and `body` to every request.
    pub async fn serve(status: &'static str, body: Value) -> Stub {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let body = body.to_string();
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n{body}",
            body.len()
        );

        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let response = response.clone();
                tokio::spawn(async move {
                    let mut buffer = vec![0u8; 4096];
                    let _ = stream.read(&mut buffer).await;
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        });

        Stub { port, _task: task }
    }

    /// The answer for an address owning exactly `names`.
    pub fn owns(names: &[&str]) -> Value {
        json!({
            "count": 1,
            "results": [{
                "id": 12,
                "address": "192.168.1.5/24",
                "dns_name": "",
                "custom_fields": { "acme_allowed_names": names },
            }]
        })
    }
}

/// The `[filter]` half: only `ipam`, whichever backend is behind it.
fn ipam_filter_config() -> FilterConfig {
    policy_config(&[(
        "inventory",
        CheckConfig {
            r#type: "ipam".to_string(),
            ..CheckConfig::default()
        },
    )])
}

/// An `[ipam]` config pointing the NetBox backend at a loopback stub.
fn netbox_config(port: u16) -> IpamConfig {
    IpamConfig {
        backend: "netbox".to_string(),
        netbox: NetboxConfig {
            url: format!("http://127.0.0.1:{port}"),
            token: "t0ken".to_string(),
            ..NetboxConfig::default()
        },
        ..IpamConfig::default()
    }
}

/// The whole app for a NetBox stub on `port`.
async fn netbox_app(port: u16) -> Router {
    app_with_ipam(ipam_filter_config(), &netbox_config(port)).await
}

#[tokio::test]
async fn a_name_netbox_associates_with_the_client_is_ordered() {
    let stub = netbox_stub::serve("200 OK", netbox_stub::owns(&["allowed.example.com"])).await;
    let app = netbox_app(stub.port).await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer, ALLOWED).await;

    let res = new_order(&app, &signer, &account_url, "allowed.example.com").await;
    assert_eq!(res.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn a_name_netbox_does_not_associate_with_the_client_is_rejected() {
    let stub = netbox_stub::serve("200 OK", netbox_stub::owns(&["allowed.example.com"])).await;
    let app = netbox_app(stub.port).await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer, ALLOWED).await;

    let res = new_order(&app, &signer, &account_url, "other.example.com").await;
    let problem = assert_problem(
        res,
        StatusCode::FORBIDDEN,
        "urn:ietf:params:acme:error:rejectedIdentifier",
    )
    .await;
    // The detail names the refused name, the address it was refused for, and
    // the product that refused it — which is what an operator needs to find the
    // NetBox object to fix.
    let detail = problem["detail"].as_str().unwrap();
    assert!(detail.contains("other.example.com"), "{problem}");
    assert!(detail.contains("192.168.1.5"), "{problem}");
    assert!(detail.contains("NetBox"), "{problem}");
}

/// The CSR hook runs too, so a second name smuggled into the CSR after an order
/// for a permitted one is refused there — as `badCSR`, not
/// `rejectedIdentifier`, since the stage decides which error applies.
#[tokio::test]
async fn a_csr_name_netbox_refuses_is_rejected_at_finalize() {
    let stub = netbox_stub::serve("200 OK", netbox_stub::owns(&["allowed.example.com"])).await;
    let app = netbox_app(stub.port).await;
    let signer = EcSigner::new();

    // newOrder passes: the order is for a name NetBox does associate with the
    // client. The CSR then asks for one it does not.
    let (account_url, finalize_url) = ready_order(&app, &signer, "allowed.example.com").await;

    let csr = make_csr_with_sans(
        "allowed.example.com",
        vec![rcgen::SanType::DnsName(
            "other.example.com".try_into().unwrap(),
        )],
    );
    let res = finalize(&app, &signer, &account_url, &finalize_url, csr).await;

    let problem = assert_problem(
        res,
        StatusCode::BAD_REQUEST,
        "urn:ietf:params:acme:error:badCSR",
    )
    .await;
    // The refusal now comes from `post_finalize`'s order binding rather than
    // from NetBox: a CSR naming anything the order does not is settled before
    // the filter chain runs, so NetBox is never asked about `other.example.com`
    // in the first place. That the NetBox hook still *runs* at finalize — and
    // still lets a matching CSR through — is what
    // `a_common_name_is_not_held_to_the_netbox_list` below covers.
    let detail = problem["detail"].as_str().unwrap();
    assert!(
        detail.contains("does not request the order's identifiers"),
        "{problem}"
    );
}

/// A CSR whose common name is not a NetBox-declared name still finalizes: a
/// `cn` is subject metadata, and `rcgen`'s own default puts a human label there.
#[tokio::test]
async fn a_common_name_is_not_held_to_the_netbox_list() {
    let stub = netbox_stub::serve("200 OK", netbox_stub::owns(&["allowed.example.com"])).await;
    let app = netbox_app(stub.port).await;
    let signer = EcSigner::new();

    let (account_url, finalize_url) = ready_order(&app, &signer, "allowed.example.com").await;

    let res = finalize(
        &app,
        &signer,
        &account_url,
        &finalize_url,
        make_csr("allowed.example.com"),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
}

/// An unreachable NetBox must fail the order as a retryable server error, never
/// as a refusal — the property that keeps an outage from looking permanent, and
/// keeps it from failing open either.
#[tokio::test]
async fn an_unreachable_netbox_is_a_server_error_not_a_denial() {
    // Bind then drop, so the port is almost certainly free and unbound.
    let port = {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap().port()
    };
    let app = netbox_app(port).await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer, ALLOWED).await;

    let res = new_order(&app, &signer, &account_url, "allowed.example.com").await;
    assert_problem(
        res,
        StatusCode::INTERNAL_SERVER_ERROR,
        "urn:ietf:params:acme:error:serverInternal",
    )
    .await;
}

/// Likewise a NetBox that answers, but with a refused token.
#[tokio::test]
async fn a_refused_netbox_token_is_a_server_error_not_a_denial() {
    let stub = netbox_stub::serve(
        "401 Unauthorized",
        serde_json::json!({ "detail": "Invalid token header." }),
    )
    .await;
    let app = netbox_app(stub.port).await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer, ALLOWED).await;

    let res = new_order(&app, &signer, &account_url, "allowed.example.com").await;
    assert_problem(
        res,
        StatusCode::INTERNAL_SERVER_ERROR,
        "urn:ietf:params:acme:error:serverInternal",
    )
    .await;
}

// ------------------------------------------------------- the same, phpIPAM

// The point of the `[ipam]` subsystem, exercised rather than asserted: the same
// filter, the same router, the same assertions — a different inventory speaking
// a different protocol, and nothing in `src/filter/` knows.

/// An `[ipam]` config pointing the phpIPAM backend at a loopback stub.
fn phpipam_config(port: u16) -> IpamConfig {
    IpamConfig {
        backend: "phpipam".to_string(),
        phpipam: PhpIpamConfig {
            url: format!("http://127.0.0.1:{port}"),
            token: "t0ken".to_string(),
            ..PhpIpamConfig::default()
        },
        ..IpamConfig::default()
    }
}

/// The whole app for a phpIPAM stub on `port`.
async fn phpipam_app(port: u16) -> Router {
    app_with_ipam(ipam_filter_config(), &phpipam_config(port)).await
}

/// phpIPAM's answer for an address owning `names` — a text column, so several
/// names arrive comma-separated rather than as a JSON array.
fn phpipam_owns(names: &str) -> Value {
    json!({
        "code": 200,
        "success": true,
        "data": [{
            "id": "12",
            "ip": "192.168.1.5",
            "hostname": "",
            "custom_acme_allowed_names": names,
        }]
    })
}

#[tokio::test]
async fn a_name_phpipam_associates_with_the_client_is_ordered() {
    let stub = netbox_stub::serve("200 OK", phpipam_owns("allowed.example.com")).await;
    let app = phpipam_app(stub.port).await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer, ALLOWED).await;

    let res = new_order(&app, &signer, &account_url, "allowed.example.com").await;
    assert_eq!(res.status(), StatusCode::CREATED);
}

/// The refusal is the same shape as NetBox's and names phpIPAM, which is the
/// whole reason the message interpolates `backend_name()`.
#[tokio::test]
async fn a_name_phpipam_does_not_associate_with_the_client_is_rejected() {
    let stub = netbox_stub::serve("200 OK", phpipam_owns("allowed.example.com")).await;
    let app = phpipam_app(stub.port).await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer, ALLOWED).await;

    let res = new_order(&app, &signer, &account_url, "other.example.com").await;
    let problem = assert_problem(
        res,
        StatusCode::FORBIDDEN,
        "urn:ietf:params:acme:error:rejectedIdentifier",
    )
    .await;
    let detail = problem["detail"].as_str().unwrap();
    assert!(detail.contains("other.example.com"), "{problem}");
    assert!(detail.contains("192.168.1.5"), "{problem}");
    assert!(detail.contains("phpIPAM"), "{problem}");
    assert!(!detail.contains("NetBox"), "{problem}");
}

/// phpIPAM's one genuinely different wire behaviour, through the whole stack: an
/// unknown address is a `404`, which must refuse the order rather than 500 it.
#[tokio::test]
async fn an_address_phpipam_has_never_heard_of_is_denied_not_a_server_error() {
    let stub = netbox_stub::serve(
        "404 Not Found",
        json!({ "code": 404, "success": false, "message": "No addresses found" }),
    )
    .await;
    let app = phpipam_app(stub.port).await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer, ALLOWED).await;

    let res = new_order(&app, &signer, &account_url, "allowed.example.com").await;
    let problem = assert_problem(
        res,
        StatusCode::FORBIDDEN,
        "urn:ietf:params:acme:error:rejectedIdentifier",
    )
    .await;
    let detail = problem["detail"].as_str().unwrap();
    assert!(
        detail.contains("holds no record of 192.168.1.5"),
        "{problem}"
    );
}

/// …while every other status is still an outage, so a broken phpIPAM stops
/// issuance rather than reading as "this address owns no names".
#[tokio::test]
async fn a_refused_phpipam_token_is_a_server_error_not_a_denial() {
    let stub = netbox_stub::serve(
        "401 Unauthorized",
        json!({ "code": 401, "message": "Invalid app code" }),
    )
    .await;
    let app = phpipam_app(stub.port).await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer, ALLOWED).await;

    let res = new_order(&app, &signer, &account_url, "allowed.example.com").await;
    assert_problem(
        res,
        StatusCode::INTERNAL_SERVER_ERROR,
        "urn:ietf:params:acme:error:serverInternal",
    )
    .await;
}
