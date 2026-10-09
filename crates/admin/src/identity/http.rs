//! The two requests an OpenID Connect relying party makes: a `GET` for JSON
//! (discovery, the key set, userinfo) and a form `POST` (the token endpoint).
//!
//! Over [`Outbound`] -- the generation's `[dns]` resolver and `[proxy]`
//! policy -- like every other outbound client in the tree, so a provider is
//! reached the way an inventory or a webhook is. Policy stays here, plumbing in
//! `acme_proxy_net::http_client`: the provider's certificate is checked against
//! the public roots plus `ca_cert_path`, a body is capped at
//! [`MAX_RESPONSE_BYTES`], and nothing follows a redirect (a provider's
//! endpoints are the ones its discovery document names).

use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::Request;
use serde_json::Value;
use url::Url;

use acme_proxy_net::http_client::{Endpoint, MAX_RESPONSE_BYTES, Outbound, error_excerpt};

/// One provider's transport: where to dial through and whom to trust.
#[derive(Clone)]
pub(crate) struct Client {
    pub(crate) outbound: Outbound,
    pub(crate) tls: Arc<rustls::ClientConfig>,
}

impl Client {
    /// `GET url`, with an optional bearer token, answering the JSON body.
    pub(crate) async fn get_json(&self, url: &Url, bearer: Option<&str>) -> Result<Value, String> {
        let mut request = Request::builder()
            .method("GET")
            .header(hyper::header::ACCEPT, "application/json");
        if let Some(token) = bearer {
            request = request.header(hyper::header::AUTHORIZATION, format!("Bearer {token}"));
        }
        self.send(url, request, Bytes::new()).await
    }

    /// `POST url` with a form body and HTTP Basic credentials -- RFC 6749
    /// §2.3.1's `client_secret_basic`, the one client authentication every
    /// provider must support.
    pub(crate) async fn post_form(
        &self,
        url: &Url,
        form: &[(&str, &str)],
        basic: (&str, &str),
    ) -> Result<Value, String> {
        use base64::prelude::*;

        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(form)
            .finish();
        // §2.3.1: each half is form-urlencoded before the two are joined, so a
        // secret holding `:` cannot move the split.
        let encode = |value: &str| {
            url::form_urlencoded::byte_serialize(value.as_bytes()).collect::<String>()
        };
        let credentials =
            BASE64_STANDARD.encode(format!("{}:{}", encode(basic.0), encode(basic.1)));
        let request = Request::builder()
            .method("POST")
            .header(hyper::header::ACCEPT, "application/json")
            .header(
                hyper::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .header(hyper::header::AUTHORIZATION, format!("Basic {credentials}"));
        self.send(url, request, Bytes::from(body)).await
    }

    async fn send(
        &self,
        url: &Url,
        builder: hyper::http::request::Builder,
        body: Bytes,
    ) -> Result<Value, String> {
        let endpoint = Endpoint::from_url(url).map_err(|error| format!("{url}: {error}"))?;
        let mut connection = self
            .outbound
            .connect::<Full<Bytes>>(&endpoint, &self.tls)
            .await
            .map_err(|error| format!("{url}: {error}"))?;

        // hyper 1.x's low-level client sends exactly what it is given, `Host`
        // included.
        let request = builder
            .uri(connection.request_target(url))
            .header(hyper::header::HOST, endpoint.authority())
            .header(hyper::header::USER_AGENT, "acme-proxy")
            .header(hyper::header::CONNECTION, "close")
            .body(Full::new(body))
            .map_err(|error| format!("building the request to {url}: {error}"))?;

        let response = connection
            .send_request(request)
            .await
            .map_err(|error| format!("request to {url} failed: {error}"))?;
        let status = response.status();
        let body = Limited::new(response.into_body(), MAX_RESPONSE_BYTES)
            .collect()
            .await
            .map_err(|_| format!("response from {url} exceeds {MAX_RESPONSE_BYTES} bytes"))?
            .to_bytes();

        if !status.is_success() {
            return Err(format!("{url} answered {status}: {}", error_excerpt(&body)));
        }
        serde_json::from_slice(&body)
            .map_err(|error| format!("{url} returned unreadable JSON: {error}"))
    }
}
