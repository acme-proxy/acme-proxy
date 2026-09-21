//! `[admin.filter]`: who may reach the admin listener at all.
//!
//! The same policy engine as the ACME listener's `[filter]` — named checks,
//! ordered rules, `trusted_proxies` — built from its own section and evaluated
//! at the **connection stage only**, on every request this listener serves,
//! `/health` included. It exists for the deployment that cannot put a host
//! firewall in front of the port (a container runtime owns the host's
//! netfilter tables), and it is not a substitute for one where one is
//! available: a refused request here has still completed a TCP and, with
//! `admin.tls` on, a TLS handshake.
//!
//! ## Connection stage only
//!
//! Nothing on this listener ever names an identifier, so a rule that can only
//! decide at the identifier stage would never run — a rule the operator
//! believes in and the server ignores. [`build`] refuses one by name, and
//! refuses the check types that have no meaning without an ACME order
//! (`identifiers`, `eab`, `ipam`) before the engine gets to phrase the
//! refusal in profile terms.
//!
//! ## The client address
//!
//! [`ClientIp`] goes into the request extensions on every request, whether or
//! not a rule is configured, and [`AdminClientIp`](super::session::AdminClientIp)
//! prefers it to the socket peer. That is what lets
//! `admin.filter.trusted_proxies` fix the login limiter behind a reverse proxy:
//! without it every failed login counts against the proxy's address.
//!
//! No `#[instrument]` here, for the reason `middlewares::filter` gives: the
//! `client_ip` record must land on the `request` span itself.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::Request;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use tracing::{Span, field, warn};

use acme_proxy_core::client::{ClientIp, ProxyPolicy};
use acme_proxy_core::config::Config;
use acme_proxy_policy::filter::{ConnectionContext, Effect, FilterPolicy, Outcome, Stage};

use super::error::AdminError;
use super::pages::PageError;

/// Check types that decide only about an ACME order's names or account.
const IDENTIFIER_ONLY_TYPES: &[&str] = &["identifiers", "eab", "ipam"];

/// Builds the admin listener's policy from `admin.filter`, refusing anything
/// that could not decide here.
///
/// With no `rules`, the policy filters nothing but still carries
/// `trusted_proxies`, so the client address is resolved the same way whether
/// or not a rule is written. The engine's own builder is skipped in that case:
/// its "no rules" warning speaks of certificates, which this listener issues
/// none of.
pub fn build(config: &Config) -> anyhow::Result<Arc<FilterPolicy>> {
    let filter = &config.admin.filter;
    let prefix = |error: anyhow::Error| anyhow::anyhow!("admin.filter: {error}");

    if filter.rules.is_empty() {
        if let Some(name) = filter.rule.keys().next() {
            anyhow::bail!(
                "[admin.filter.rule.{name}] is configured but admin.filter.rules is empty; \
                 list the rules to evaluate, in order"
            );
        }
        let proxy =
            ProxyPolicy::new(&filter.trusted_proxies, &filter.forwarded_header).map_err(prefix)?;
        return Ok(Arc::new(FilterPolicy::new(
            Vec::new(),
            Vec::new(),
            Effect::Allow,
            proxy,
        )));
    }

    for (name, check) in &filter.check {
        let kind = check.r#type.trim();
        if IDENTIFIER_ONLY_TYPES.contains(&kind) {
            anyhow::bail!(
                "admin.filter.check.{name} is type = \"{kind}\", which decides about the \
                 names or account of an ACME order; the admin listener never sees one, so it \
                 could not decide anything. Use allowed_ip, path, reverse_dns or custom"
            );
        }
    }

    let policy = acme_proxy_policy::filter::build::build(filter, &config.dns, None, false)
        .map_err(prefix)?;

    if let Some(rule) = policy
        .rules()
        .iter()
        .find(|rule| !rule.stages.contains(Stage::Connection))
    {
        anyhow::bail!(
            "admin.filter.rule.{} is evaluated at the identifier stage only, which the admin \
             listener never reaches, so it would never run; drop the stages override on its \
             checks or drop the rule",
            rule.name
        );
    }

    Ok(Arc::new(policy))
}

/// Resolves the client address and runs the connection stage.
pub async fn admin_filter_middleware(
    State(policy): State<Arc<FilterPolicy>>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip());

    let client_ip = policy.proxy().resolve(peer, request.headers());
    request.extensions_mut().insert(ClientIp(client_ip));
    if let Some(ip) = client_ip {
        Span::current().record("client_ip", field::display(ip));
    }

    let path = request.uri().path().to_string();
    let context = ConnectionContext {
        client_ip,
        method: request.method(),
        path: &path,
    };

    match policy.check_connection(&context).await {
        Outcome::Allow => next.run(request).await,
        outcome => refusal(&outcome, client_ip, &path),
    }
}

/// A refusal in the shape the path's caller reads: JSON under `/api`, the HTML
/// error page everywhere else.
///
/// A deny is a `403`; an unknown is the server's own failure, a `500` with a
/// generic body, since the specifics are already in the policy's log line.
fn refusal(outcome: &Outcome, client_ip: Option<std::net::IpAddr>, path: &str) -> Response {
    let error = match outcome {
        Outcome::Deny(detail) => {
            warn!(event = "filter_request_blocked", outcome = "failure", listener = "admin", client_ip = ?client_ip, path, %detail);
            AdminError::access_denied(detail.clone())
        }
        Outcome::Undecided(_) | Outcome::Allow => AdminError::internal(),
    };

    if path == "/api" || path.starts_with("/api/") {
        error.into_response()
    } else {
        PageError::from(error).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{StatusCode, header};
    use axum::{Router, middleware, routing::get};
    use tower::ServiceExt;

    use acme_proxy_core::config::{CheckConfig, RuleConfig};

    fn config_with(check: CheckConfig) -> Config {
        let mut config = Config::default();
        let filter = &mut config.admin.filter;
        filter.rules = vec!["mgmt".to_string()];
        filter.check.insert("net".to_string(), check);
        filter.rule.insert(
            "mgmt".to_string(),
            RuleConfig {
                when: "net".to_string(),
                then: "allow".to_string(),
                ..RuleConfig::default()
            },
        );
        config
    }

    fn allowed_ip(allow: &[&str]) -> CheckConfig {
        CheckConfig {
            r#type: "allowed_ip".to_string(),
            allow: allow.iter().map(ToString::to_string).collect(),
            ..CheckConfig::default()
        }
    }

    fn app(config: &Config) -> Router {
        let policy = build(config).expect("policy must build");
        Router::new()
            .route("/api/x", get(|| async { "ok" }))
            .route("/ui/x", get(|| async { "ok" }))
            .route(
                "/ip",
                get(|parts: axum::http::request::Parts| async move {
                    format!("{:?}", parts.extensions.get::<ClientIp>())
                }),
            )
            .layer(middleware::from_fn_with_state(
                policy,
                admin_filter_middleware,
            ))
    }

    fn request(uri: &str, peer: [u8; 4], forwarded: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder().uri(uri);
        if let Some(value) = forwarded {
            builder = builder.header("x-forwarded-for", value);
        }
        let mut request = builder.body(Body::empty()).unwrap();
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from((peer, 4711))));
        request
    }

    async fn body(response: Response) -> String {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn no_rules_serves_everyone() {
        let app = app(&Config::default());
        let response = app
            .oneshot(request("/api/x", [203, 0, 113, 5], None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn an_allowed_address_is_served() {
        let app = app(&config_with(allowed_ip(&["10.0.0.0/8"])));
        let response = app
            .oneshot(request("/api/x", [10, 1, 2, 3], None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn a_refusal_under_api_is_json() {
        let app = app(&config_with(allowed_ip(&["10.0.0.0/8"])));
        let response = app
            .oneshot(request("/api/x", [203, 0, 113, 5], None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let json: serde_json::Value = serde_json::from_str(&body(response).await).unwrap();
        assert_eq!(json["error"], "access_denied");
    }

    #[tokio::test]
    async fn a_refusal_elsewhere_is_an_html_page() {
        let app = app(&config_with(allowed_ip(&["10.0.0.0/8"])));
        let response = app
            .oneshot(request("/ui/x", [203, 0, 113, 5], None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let content_type = response.headers()[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .to_string();
        assert!(content_type.starts_with("text/html"), "{content_type}");
        assert!(body(response).await.contains("access_denied"));
    }

    /// The deployment this section exists for: a reverse proxy in the same
    /// compose file, and the real client only in its header.
    #[tokio::test]
    async fn a_trusted_proxys_forwarded_client_is_the_one_checked() {
        let mut config = config_with(allowed_ip(&["198.51.100.0/24"]));
        config.admin.filter.trusted_proxies = vec!["172.16.0.0/12".to_string()];
        let app = app(&config);

        let allowed = app
            .clone()
            .oneshot(request("/api/x", [172, 18, 0, 2], Some("198.51.100.9")))
            .await
            .unwrap();
        assert_eq!(allowed.status(), StatusCode::OK);

        let refused = app
            .oneshot(request("/api/x", [172, 18, 0, 2], Some("203.0.113.5")))
            .await
            .unwrap();
        assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn an_untrusted_peers_forwarded_header_is_ignored() {
        let app = app(&config_with(allowed_ip(&["198.51.100.0/24"])));
        let response = app
            .oneshot(request("/api/x", [203, 0, 113, 5], Some("198.51.100.9")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    /// `trusted_proxies` alone, with no rule, still resolves the client: the
    /// login limiter reads the result.
    #[tokio::test]
    async fn the_client_address_is_recorded_without_any_rule() {
        let mut config = Config::default();
        config.admin.filter.trusted_proxies = vec!["172.16.0.0/12".to_string()];
        let response = app(&config)
            .oneshot(request("/ip", [172, 18, 0, 2], Some("198.51.100.9")))
            .await
            .unwrap();
        assert!(body(response).await.contains("198.51.100.9"));
    }

    #[test]
    fn an_unknown_is_a_500() {
        let response = refusal(
            &Outcome::Undecided("script died".to_string()),
            None,
            "/api/x",
        );
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn identifier_only_check_types_are_refused_by_name() {
        for kind in IDENTIFIER_ONLY_TYPES {
            let error = build(&config_with(CheckConfig {
                r#type: (*kind).to_string(),
                ..CheckConfig::default()
            }))
            .unwrap_err()
            .to_string();
            assert!(error.contains("admin.filter.check.net"), "{error}");
            assert!(error.contains(kind), "{error}");
        }
    }

    #[test]
    fn a_rule_moved_to_the_identifier_stage_is_refused() {
        let mut check = allowed_ip(&["10.0.0.0/8"]);
        check.stages = vec!["identifiers".to_string()];
        let error = build(&config_with(check)).unwrap_err().to_string();
        assert!(error.contains("admin.filter.rule.mgmt"), "{error}");
    }

    #[test]
    fn an_engine_error_names_the_section() {
        let error = build(&config_with(allowed_ip(&["not-a-network"])))
            .unwrap_err()
            .to_string();
        assert!(error.starts_with("admin.filter: "), "{error}");
    }

    #[test]
    fn a_rule_without_rules_is_refused() {
        let mut config = config_with(allowed_ip(&["10.0.0.0/8"]));
        config.admin.filter.rules.clear();
        let error = build(&config).unwrap_err().to_string();
        assert!(error.contains("admin.filter.rules is empty"), "{error}");
    }

    #[test]
    fn a_bad_trusted_proxy_is_refused_without_rules() {
        let mut config = Config::default();
        config.admin.filter.trusted_proxies = vec!["nope".to_string()];
        assert!(build(&config).is_err());
    }
}
