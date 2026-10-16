//! Optional audit row for every refused response on a mounted ACME profile.
//!
//! This layer sits outside admission, profile filtering, handlers and the
//! catch-panic layer. It therefore sees refusals that occur before an account
//! or order can be identified. The access layer remains outside it and has
//! already assigned a request ID. The response is returned unchanged.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::Request,
    middleware::Next,
    response::Response,
};

use acme_proxy_core::audit::{Actor, AuditEvent, AuditRecord, RequestContext};
use acme_proxy_core::client::ProxyPolicy;
use acme_proxy_core::error::ProblemAuditInfo;
use acme_proxy_jobs::auditor::Auditor;

/// Only the profile values needed to attribute a request. A separate snapshot
/// keeps the refusal layer independent of signer and challenge state.
#[derive(Clone)]
pub struct AuditProfile {
    pub name: String,
    pub path: String,
    pub proxy: ProxyPolicy,
}

#[derive(Clone)]
pub struct RefusalAudit {
    pub auditor: Arc<Auditor>,
    pub profiles: Arc<Vec<AuditProfile>>,
}

/// Keep attacker-controlled text bounded and single-line in both the row and
/// any downstream export. The response's problem detail is already public.
fn bounded(value: &str, limit: usize) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .take(limit)
        .collect()
}

pub async fn record_refusal(
    State(state): State<RefusalAudit>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let path = request.uri().path();
    let Some(profile) = state.profiles.iter().find(|profile| {
        path == profile.path
            || path
                .strip_prefix(&profile.path)
                .is_some_and(|tail| tail.starts_with('/'))
    }) else {
        return next.run(request).await;
    };

    // Do this here rather than reading ClientIp after the handler: middleware
    // cannot read an inner layer's modifications to the consumed Request.
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip());
    let mut client = RequestContext::from_request(&request);
    client.ip = profile.proxy.resolve(peer, request.headers());
    let method = bounded(request.method().as_str(), 32);
    let path = bounded(path, 256);
    let profile_name = profile.name.clone();

    let response = next.run(request).await;
    if !response.status().is_client_error() && !response.status().is_server_error() {
        return response;
    }

    let status = response.status().as_u16();
    let problem = response.extensions().get::<ProblemAuditInfo>();
    let reason = problem
        .map(|problem| problem.typ.to_owned())
        .unwrap_or_else(|| format!("http_{status}"));
    let detail = match problem {
        Some(problem) => format!(
            "{} {}: HTTP {}; {}",
            method,
            path,
            status,
            bounded(&problem.detail, 512)
        ),
        None => format!("{} {}: HTTP {}", method, path, status),
    };
    let record = AuditRecord::new(
        AuditEvent::AcmeRequestRefused,
        profile_name,
        Actor::acme_unidentified(),
    )
    .with_client(state.auditor.client(&client).await)
    .with_reason(reason)
    .with_detail(detail);
    state.auditor.record(record).await;
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use acme_proxy_core::{client::ProxyPolicy, error::Problem};
    use acme_proxy_store::{
        audit::{AuditEntry, AuditQuery},
        db::Database,
    };
    use axum::{Router, http::StatusCode, middleware, routing::get};
    use tower::ServiceExt;

    #[test]
    fn bounded_text_removes_controls_and_limits_unicode() {
        assert_eq!(bounded("a\nb\t😀z", 3), "ab😀");
    }

    #[tokio::test]
    async fn records_early_refusal_once_with_resolved_client_and_problem() {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        let auditor = Arc::new(Auditor::offline(database.clone()));
        let proxy = ProxyPolicy::new(&["10.0.0.0/8".to_owned()], "x-forwarded-for").unwrap();
        let state = RefusalAudit {
            auditor,
            profiles: Arc::new(vec![AuditProfile {
                name: "demo".to_owned(),
                path: "/profile/demo".to_owned(),
                proxy,
            }]),
        };
        let app = Router::new()
            .route(
                "/profile/demo/refuse",
                get(|| async { Problem::access_denied("blocked") }),
            )
            .route("/profile/demo/ok", get(|| async { StatusCode::OK }))
            .route("/health", get(|| async { StatusCode::SERVICE_UNAVAILABLE }))
            .layer(middleware::from_fn_with_state(state, record_refusal))
            .layer(middleware::from_fn(
                crate::middlewares::access::add_access_middleware,
            ));

        let mut request = Request::builder()
            .uri("/profile/demo/refuse?secret=must-not-store")
            .header("x-forwarded-for", "198.51.100.7")
            .header("x-request-id", "refusal-1")
            .header("user-agent", "test-client")
            .body(Body::empty())
            .unwrap();
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([10, 0, 0, 5], 443))));
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        for uri in ["/profile/demo/ok", "/health"] {
            let request = Request::builder().uri(uri).body(Body::empty()).unwrap();
            app.clone().oneshot(request).await.unwrap();
        }
        let (rows, total) = AuditEntry::search(
            &AuditQuery {
                limit: 10,
                ..AuditQuery::default()
            },
            &database,
        )
        .await
        .unwrap();
        assert_eq!(total, 1);
        let row = &rows[0];
        assert_eq!(row.event, "acme_request_refused");
        assert_eq!(row.profile, "demo");
        assert_eq!(row.actor_kind, "acme");
        assert_eq!(row.actor_id, None);
        assert_eq!(row.client_ip.as_deref(), Some("198.51.100.7"));
        assert_eq!(row.request_id.as_deref(), Some("refusal-1"));
        assert_eq!(row.user_agent.as_deref(), Some("test-client"));
        assert_eq!(
            row.reason.as_deref(),
            Some("urn:ietf:params:acme:error:unauthorized")
        );
        assert!(
            row.detail
                .as_deref()
                .unwrap()
                .contains("GET /profile/demo/refuse: HTTP 403; blocked")
        );
        assert!(!row.detail.as_deref().unwrap().contains("must-not-store"));
    }
}
