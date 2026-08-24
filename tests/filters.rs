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
    CheckConfig, Config, CustomIpamConfig, DnsConfig, FilterConfig, IpamConfig, NetboxConfig,
    PhpIpamConfig, RuleConfig,
};
use acme_proxy::filter::policy::{Check, StageSet, Verdict};
use acme_proxy::filter::{self, IdentifierContext, IdentifierStage};
use acme_proxy::signer::local_ca::LocalCa;
use acme_proxy::sqlite::eab::Eab;
use async_trait::async_trait;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use serde_json::{Value, json};

mod common;
use common::{
    EcSigner, RejectingCheck, TempDir, TestSigner, body_json, build_eab, default_challenges,
    fetch_nonce_from, make_csr, make_csr_with_sans, no_notifications, p, policy_of, policy_with,
    post_from, send_from, test_app_full, test_app_with_filter, write_script,
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
        acme_proxy::http_client::Outbound::new(
            test_resolver(),
            std::sync::Arc::new(acme_proxy::proxy::OutboundProxies::direct()),
        ),
    )
    .expect("ipam config should build");
    let chain = filter::from_config(&filter, &DnsConfig::default(), inventory, true)
        .expect("filter config should build");
    let signer = Arc::new(LocalCa::generate_in_memory("ecdsa-p256", 90).unwrap());
    test_app_full(
        Config::default(),
        signer,
        chain,
        default_challenges(),
        no_notifications().await,
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
    let error = filter::from_config(&ip_config(&[], &[]), &DnsConfig::default(), None, true)
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
    // The `type` too: `Outcome::Deny` mapping to a different 403 —
    // `rejectedIdentifier` at the connection stage, say — would pass a bare
    // status check while meaning something else entirely to the client.
    assert_problem(
        res,
        StatusCode::FORBIDDEN,
        "urn:ietf:params:acme:error:unauthorized",
    )
    .await;
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
    // The `type` too: `Outcome::Deny` mapping to a different 403 —
    // `rejectedIdentifier` at the connection stage, say — would pass a bare
    // status check while meaning something else entirely to the client.
    assert_problem(
        res,
        StatusCode::FORBIDDEN,
        "urn:ietf:params:acme:error:unauthorized",
    )
    .await;
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
    // The `type` too: `Outcome::Deny` mapping to a different 403 —
    // `rejectedIdentifier` at the connection stage, say — would pass a bare
    // status check while meaning something else entirely to the client.
    assert_problem(
        res,
        StatusCode::FORBIDDEN,
        "urn:ietf:params:acme:error:unauthorized",
    )
    .await;
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

// -------------------------------------------- the same, an operator script

// The third run, and the one that settles what the other two could not: those
// share a `sources` vocabulary, a transport and a wire status code, so between
// them they never showed whether `Ipam` is a seam or a description of two REST
// clients. This backend has none of the three — its lookup is a forked process
// — and the assertions below are still the same assertions.

/// An `[ipam]` config pointing the `custom` backend at `script_path`.
fn custom_ipam_config(script_path: &str) -> IpamConfig {
    IpamConfig {
        backend: "custom".to_string(),
        custom: CustomIpamConfig {
            script_path: script_path.to_string(),
            ..CustomIpamConfig::default()
        },
        ..IpamConfig::default()
    }
}

/// The whole app for a script that answers for `192.168.1.5` — the address
/// `ALLOWED` connects from — and knows nothing about any other.
async fn custom_ipam_app(dir: &TempDir, name: &str, body: &str) -> Router {
    let script = write_script(dir, name, body);
    app_with_ipam(
        ipam_filter_config(),
        &custom_ipam_config(script.to_str().unwrap()),
    )
    .await
}

/// The inventory an operator would write in four lines of shell.
const OWNS_ALLOWED: &str = r#"#!/bin/sh
if [ "$ACME_IPAM_CLIENT_IP" = "192.168.1.5" ]; then
    echo allowed.example.com
    exit 0
fi
exit 3
"#;

#[tokio::test]
async fn a_name_the_script_lists_is_ordered() {
    let dir = TempDir::new("ipam-custom-it");
    let app = custom_ipam_app(&dir, "owns.sh", OWNS_ALLOWED).await;
    let signer = EcSigner::new();
    let account_url = register(&app, &signer, ALLOWED).await;

    let res = new_order(&app, &signer, &account_url, "allowed.example.com").await;
    assert_eq!(res.status(), StatusCode::CREATED);
}

/// The refusal names the script rather than either product, which is the whole
/// reason the message interpolates `backend_name()`.
#[tokio::test]
async fn a_name_the_script_does_not_list_is_rejected() {
    let dir = TempDir::new("ipam-custom-it");
    let app = custom_ipam_app(&dir, "owns.sh", OWNS_ALLOWED).await;
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
    assert!(detail.contains("the custom IPAM script"), "{problem}");
    assert!(!detail.contains("NetBox"), "{problem}");
    assert!(!detail.contains("phpIPAM"), "{problem}");
}

/// The reserved exit code through the whole stack: "no record of this address"
/// is a denial worded its own way, not a 500 — the same answer phpIPAM's `404`
/// reaches by a completely different route.
#[tokio::test]
async fn an_address_the_script_exits_three_for_is_denied_not_a_server_error() {
    let dir = TempDir::new("ipam-custom-it");
    let app = custom_ipam_app(&dir, "nothing.sh", "#!/bin/sh\nexit 3\n").await;
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

/// …while every other non-zero exit is still an outage, so a script that broke
/// stops issuance rather than reading as "this address owns no names". The
/// twin of `an_unreachable_netbox_is_a_server_error_not_a_denial`, and the
/// property the whole subsystem rests on.
#[tokio::test]
async fn a_script_that_fails_is_a_server_error_not_a_denial() {
    let dir = TempDir::new("ipam-custom-it");
    let app = custom_ipam_app(
        &dir,
        "broken.sh",
        "#!/bin/sh\necho 'cmdb unreachable'\nexit 1\n",
    )
    .await;
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

/// A script that is simply not there is the same answer: an operator typo in
/// `script_path` must not silently permit or silently refuse.
#[tokio::test]
async fn a_missing_script_is_a_server_error_not_a_denial() {
    let app = app_with_ipam(
        ipam_filter_config(),
        &custom_ipam_config("/nonexistent/ipam.sh"),
    )
    .await;
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

/// The hook runs at finalize too, and a CSR whose common name the script never
/// listed still issues — a `cn` is subject metadata, and `rcgen`'s own default
/// puts a human label there. The `custom` half of
/// `a_common_name_is_not_held_to_the_netbox_list`, and what shows the script is
/// asked at both stages rather than only at `newOrder`.
#[tokio::test]
async fn a_common_name_is_not_held_to_the_scripts_list() {
    let dir = TempDir::new("ipam-custom-it");
    let app = custom_ipam_app(&dir, "owns.sh", OWNS_ALLOWED).await;
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

// ------------------------------------------------------------ the eab check

/// A two-tenant policy: each EAB label is bound to its own name space, and
/// nothing else is permitted.
fn tenant_policy() -> FilterConfig {
    fn tenant(label: &str) -> CheckConfig {
        CheckConfig {
            r#type: "eab".to_string(),
            allow: strings(&[label]),
            ..CheckConfig::default()
        }
    }
    fn names(suffix: &str) -> CheckConfig {
        CheckConfig {
            r#type: "identifiers".to_string(),
            allow: strings(&[&format!("*.{suffix}")]),
            ..CheckConfig::default()
        }
    }

    FilterConfig {
        rules: strings(&["tenant-a", "tenant-b"]),
        rule: BTreeMap::from([
            (
                "tenant-a".to_string(),
                RuleConfig {
                    when: "is-tenant-a and tenant-a-names".to_string(),
                    then: "allow".to_string(),
                    ..RuleConfig::default()
                },
            ),
            (
                "tenant-b".to_string(),
                RuleConfig {
                    when: "is-tenant-b and tenant-b-names".to_string(),
                    then: "allow".to_string(),
                    ..RuleConfig::default()
                },
            ),
        ]),
        check: BTreeMap::from([
            ("is-tenant-a".to_string(), tenant("tenant-a")),
            ("is-tenant-b".to_string(), tenant("tenant-b")),
            ("tenant-a-names".to_string(), names("tenant-a.example.com")),
            ("tenant-b-names".to_string(), names("tenant-b.example.com")),
        ]),
        ..FilterConfig::default()
    }
}

/// Registers an account under an EAB credential, returning its `kid` URL.
async fn register_with_eab(app: &Router, signer: &EcSigner, kid: &str, secret: &[u8]) -> String {
    let nonce = fetch_nonce_from(app, ALLOWED).await;
    let eab = build_eab(kid, secret, NEW_ACCOUNT_URL, &signer.jwk());
    let payload = json!({ "termsOfServiceAgreed": true, "externalAccountBinding": eab });
    let res = post_from(
        app,
        &p("/newAccount"),
        signer.sign(NEW_ACCOUNT_URL, &nonce, &payload),
        ALLOWED,
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED);
    res.headers()
        .get("location")
        .and_then(|value| value.to_str().ok())
        .expect("newAccount must set a Location header")
        .to_string()
}

/// The multi-tenant story end to end: two credentials minted out of band, each
/// bound by a rule to its own name space, and neither able to reach the
/// other's. This is the policy an account-id check could not express, because
/// the ids do not exist until after the configuration would have to name them.
#[tokio::test]
async fn eab_labels_scope_each_tenant_to_its_own_names() {
    let mut config = Config::default();
    config.eab.enabled = true;

    let policy = filter::from_config(&tenant_policy(), &DnsConfig::default(), None, true)
        .expect("tenant policy should build");
    let ca = Arc::new(LocalCa::generate_in_memory("ecdsa-p256", 90).unwrap());
    let (app, db) = test_app_full(
        config,
        ca,
        policy,
        default_challenges(),
        no_notifications().await,
    )
    .await;

    let key_a = Eab::create(Some("tenant-a".to_string()), None, &db)
        .await
        .unwrap();
    let key_b = Eab::create(Some("tenant-b".to_string()), None, &db)
        .await
        .unwrap();

    let signer_a = EcSigner::new();
    let signer_b = EcSigner::new();
    let account_a = register_with_eab(&app, &signer_a, &key_a.kid, &key_a.secret).await;
    let account_b = register_with_eab(&app, &signer_b, &key_b.kid, &key_b.secret).await;

    // Each tenant may have its own names.
    for (account, signer, name) in [
        (&account_a, &signer_a, "web.tenant-a.example.com"),
        (&account_b, &signer_b, "web.tenant-b.example.com"),
    ] {
        let res = new_order(&app, signer, account, name).await;
        assert_eq!(res.status(), StatusCode::CREATED, "{name}");
    }

    // Neither may have the other's, even though the address is identical and
    // both credentials are perfectly valid.
    let res = new_order(&app, &signer_a, &account_a, "web.tenant-b.example.com").await;
    assert_problem(
        res,
        StatusCode::FORBIDDEN,
        "urn:ietf:params:acme:error:rejectedIdentifier",
    )
    .await;
}

/// The gate that keeps the credential lookup off every other deployment's
/// request path: with no `eab` check configured, the policy never asks.
#[tokio::test]
async fn a_policy_without_an_eab_check_resolves_no_credential() {
    let policy = filter::from_config(
        &identifiers_config(&[r".*\.example\.com"], &[]),
        &DnsConfig::default(),
        None,
        false,
    )
    .unwrap();
    assert!(!policy.needs_eab());

    // And one with an eab check does.
    let mut config = tenant_policy();
    config.rules = strings(&["tenant-a"]);
    let policy = filter::from_config(&config, &DnsConfig::default(), None, true).unwrap();
    assert!(policy.needs_eab());
}

// ---------------------------------------------------------------- path

/// The `path` check exists for one concrete trap, and this is it: **`/crl` is
/// served by the profile router**, so an address-based policy without a path
/// rule silently breaks revocation checking for every relying party outside the
/// allowlist — the parties the extension exists for.
///
/// `src/filter/path.rs` had seven unit tests and nothing above them; `grep
/// '"path"' tests/` returned nothing at all before this.
#[tokio::test]
async fn a_path_rule_lets_a_blocked_relying_party_still_fetch_the_crl() {
    // `net or crl-path`: an allowed address gets everything, and anyone at all
    // gets the CRL. Kleene `or`, evaluated at the connection stage where both
    // checks can decide.
    let mut rule = BTreeMap::new();
    rule.insert(
        "connection".to_string(),
        RuleConfig {
            when: "net or crl-path".to_string(),
            then: "allow".to_string(),
            ..RuleConfig::default()
        },
    );
    let config = FilterConfig {
        rules: vec!["connection".to_string()],
        rule,
        check: [
            (
                "net".to_string(),
                CheckConfig {
                    r#type: "allowed_ip".to_string(),
                    allow: strings(&["192.168.1.0/24"]),
                    ..CheckConfig::default()
                },
            ),
            (
                "crl-path".to_string(),
                CheckConfig {
                    r#type: "path".to_string(),
                    allow: strings(&["/crl"]),
                    ..CheckConfig::default()
                },
            ),
        ]
        .into_iter()
        .collect(),
        ..FilterConfig::default()
    };
    let app = app_with_config(config).await;

    // The blocked address may fetch the CRL...
    let res = send_from(
        &app,
        Request::get(p("/crl")).body(Body::empty()).unwrap(),
        BLOCKED,
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "the CRL must stay reachable");
    assert_eq!(
        res.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("application/pkix-crl"),
    );

    // ...and nothing else.
    let res = send_from(
        &app,
        Request::get(p("/directory")).body(Body::empty()).unwrap(),
        BLOCKED,
    )
    .await;
    assert_problem(
        res,
        StatusCode::FORBIDDEN,
        "urn:ietf:params:acme:error:unauthorized",
    )
    .await;

    // The allowed address is unaffected by the path rule.
    let res = send_from(
        &app,
        Request::get(p("/directory")).body(Body::empty()).unwrap(),
        ALLOWED,
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
}

/// A `path` glob covers **one segment**: one or more characters, none of them
/// a `/`.
///
/// Deliberately unlike the name checks' `*`, which stops at a `.` —
/// `path.rs` does not share `glob_to_pattern` for exactly this reason. The
/// documented example is `/renewalInfo/*`, which "covers every certificate id
/// and nothing deeper", and all three halves of that sentence are load-bearing:
/// a `*` that crossed `/` would make one entry an accidental allow-list for a
/// whole subtree, and one that matched empty would admit the bare prefix.
#[tokio::test]
async fn a_path_wildcard_covers_one_segment_and_no_more() {
    let mut rule = BTreeMap::new();
    rule.insert(
        "connection".to_string(),
        RuleConfig {
            when: "paths".to_string(),
            then: "allow".to_string(),
            ..RuleConfig::default()
        },
    );
    let config = FilterConfig {
        rules: vec!["connection".to_string()],
        rule,
        check: [(
            "paths".to_string(),
            CheckConfig {
                r#type: "path".to_string(),
                allow: strings(&["/renewalInfo/*"]),
                ..CheckConfig::default()
            },
        )]
        .into_iter()
        .collect(),
        ..FilterConfig::default()
    };
    let app = app_with_config(config).await;

    // One segment: allowed through the filter. What the handler then makes of
    // an unknown certID is its business — the assertion is only that the
    // policy did not refuse it.
    let res = send_from(
        &app,
        Request::get(p("/renewalInfo/some-cert-id"))
            .body(Body::empty())
            .unwrap(),
        BLOCKED,
    )
    .await;
    assert_ne!(
        res.status(),
        StatusCode::FORBIDDEN,
        "a single segment must match"
    );

    // Deeper: the `*` must not cross the separator.
    let res = send_from(
        &app,
        Request::get(p("/renewalInfo/some-cert-id/extra"))
            .body(Body::empty())
            .unwrap(),
        BLOCKED,
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "a path wildcard must not cross a slash"
    );

    // Empty: `*` is one *or more*, so the bare prefix is not covered.
    let res = send_from(
        &app,
        Request::get(p("/renewalInfo/"))
            .body(Body::empty())
            .unwrap(),
        BLOCKED,
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "a path wildcard matches one or more characters, never none"
    );
}

/// The path a `path` check sees is the **profile-stripped** one.
///
/// A rule written `/directory` has to match a request to
/// `/profile/default/directory`, or every path rule in a multi-profile
/// deployment would silently need the prefix baked in — and would then break
/// the moment the profile were renamed.
#[tokio::test]
async fn a_path_rule_matches_the_profile_stripped_path() {
    let mut rule = BTreeMap::new();
    rule.insert(
        "connection".to_string(),
        RuleConfig {
            when: "paths".to_string(),
            then: "allow".to_string(),
            ..RuleConfig::default()
        },
    );
    let config = FilterConfig {
        rules: vec!["connection".to_string()],
        rule,
        check: [(
            "paths".to_string(),
            CheckConfig {
                r#type: "path".to_string(),
                // Written without the `/profile/default` prefix.
                allow: strings(&["/directory"]),
                ..CheckConfig::default()
            },
        )]
        .into_iter()
        .collect(),
        ..FilterConfig::default()
    };
    let app = app_with_config(config).await;

    let res = send_from(
        &app,
        Request::get(p("/directory")).body(Body::empty()).unwrap(),
        BLOCKED,
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "a path rule is written against the path inside the profile"
    );

    let res = send_from(
        &app,
        Request::get(p("/newNonce")).body(Body::empty()).unwrap(),
        BLOCKED,
    )
    .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

// ------------------------------------------------------- rule message / mode

/// A `[filter]` config with one matching **deny** rule, which is the shape
/// `message` and `mode` actually apply to: both act on a rule whose condition
/// came back `Pass`, not on the `filter.default` that catches everything else.
fn deny_rule_config(message: &str, mode: &str, default: &str) -> FilterConfig {
    let mut rule = BTreeMap::new();
    rule.insert(
        "block".to_string(),
        RuleConfig {
            when: "bad".to_string(),
            then: "deny".to_string(),
            message: message.to_string(),
            mode: mode.to_string(),
        },
    );
    FilterConfig {
        rules: vec!["block".to_string()],
        rule,
        default: default.to_string(),
        check: [(
            "bad".to_string(),
            CheckConfig {
                r#type: "allowed_ip".to_string(),
                // Passes for exactly the address the rule then denies.
                allow: strings(&["203.0.113.9/32"]),
                ..CheckConfig::default()
            },
        )]
        .into_iter()
        .collect(),
        ..FilterConfig::default()
    }
}

/// An operator's `filter.rule.message` reaches the client **verbatim**, in
/// place of whichever check happened to fail.
///
/// This suite deliberately routes policy tests (`or`, `not`, `warn`) to
/// `src/filter/policy.rs`, but `message` is a wire-format concern: the words
/// have to survive `Outcome::Deny` → `Problem::access_denied` → the `detail`
/// member. And the *substitution* is the point — the default wording names the
/// rule, which is exactly what an operator writing a custom message replaces.
#[tokio::test]
async fn an_operator_message_replaces_the_default_refusal_in_the_403() {
    let app = app_with_config(deny_rule_config(
        "contact netops@example.com for access",
        "enforce",
        "allow",
    ))
    .await;

    let res = send_from(
        &app,
        Request::get(p("/directory")).body(Body::empty()).unwrap(),
        BLOCKED,
    )
    .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    let problem = body_json(res).await;
    let detail = problem["detail"].as_str().unwrap_or_default();

    assert!(
        detail.contains("contact netops@example.com for access"),
        "the operator's own words must reach the client: {detail}"
    );
    // ...and the wording it replaced must not also be there, or the
    // substitution bought nothing.
    assert!(
        !detail.contains("refused by policy rule"),
        "the operator's message replaces the default, it does not join it: {detail}"
    );
}

/// With no `message`, the refusal still names the rule that made it — so an
/// operator reading a client's report can find the line responsible.
#[tokio::test]
async fn a_rule_with_no_message_names_itself_in_the_403() {
    let app = app_with_config(deny_rule_config("", "enforce", "allow")).await;

    let res = send_from(
        &app,
        Request::get(p("/directory")).body(Body::empty()).unwrap(),
        BLOCKED,
    )
    .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    let detail = body_json(res).await["detail"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(detail.contains("block"), "{detail}");
}

/// `mode = "warn"` admits the request the same rule would otherwise refuse.
///
/// The dry-run lever, and the one an operator reaches for first when rolling a
/// policy out on a live endpoint — so it is worth proving through the router
/// and not only in the evaluator. Both halves are needed: a `warn` that
/// admitted everything would pass the second assertion on its own.
#[tokio::test]
async fn a_warn_mode_rule_admits_the_request_it_would_have_refused() {
    // Enforcing: the rule matches and refuses.
    let app = app_with_config(deny_rule_config("", "enforce", "allow")).await;
    let res = send_from(
        &app,
        Request::get(p("/directory")).body(Body::empty()).unwrap(),
        BLOCKED,
    )
    .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    // Warning: the same rule, the same address, admitted — the rule is skipped
    // and `filter.default` decides instead.
    let app = app_with_config(deny_rule_config("", "warn", "allow")).await;
    let res = send_from(
        &app,
        Request::get(p("/directory")).body(Body::empty()).unwrap(),
        BLOCKED,
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "a warn-mode rule must not decide"
    );
}
