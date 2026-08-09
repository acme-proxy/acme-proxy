//! A scripted, in-process ACME *server*, for testing the outbound client and
//! the relay against something that behaves like a real upstream.
//!
//! This exists because the thing under test is a network client: stubbing the
//! transport would leave the JWS assembly, the nonce cycle, the `Location`
//! handling and the polling loop — i.e. nearly everything that can be wrong —
//! unexercised. A loopback `TcpListener` speaking real HTTP/1.1 costs little
//! and covers all of it, the same trade `challenge::http_01`'s own loopback
//! test makes.
//!
//! It is deliberately *not* a conforming ACME server: it verifies no
//! signatures and enforces no state machine beyond what a test asks for. What
//! it does faithfully is the shape — status codes, `Location`, `Replay-Nonce`,
//! `Retry-After`, and problem documents.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// The token this upstream poses on its one authorization. Fixed rather than
/// random so a test can name it — the `http-01` responder is keyed by token,
/// so the fetch URL has to be predictable from outside the relay.
pub const CHALLENGE_TOKEN: &str = "upstream-token-value";

/// How the scripted upstream should behave for one test. Every field's
/// default is "behave like a healthy upstream that settles immediately", so a
/// test names only the one thing it is exercising.
#[derive(Clone, Default)]
pub struct Script {
    /// Order polls answered `processing` before the order turns `ready`.
    pub polls_before_ready: usize,
    /// Order polls answered `processing` before it turns `valid`, after
    /// finalize.
    pub polls_before_valid: usize,
    /// Reject the first signed POST with `badNonce`, to drive the retry.
    pub bad_nonce_once: bool,
    /// Answer `finalize` with a `badCSR` problem.
    pub bad_csr: bool,
    /// Answer `revokeCert` with an `alreadyRevoked` problem.
    pub already_revoked: bool,
    /// Drive the order to `invalid` instead of ever becoming ready.
    pub order_fails: bool,
    /// Omit `Location` from the `newAccount`/`newOrder` response.
    pub omit_location: bool,
    /// The PEM chain served at the certificate URL.
    pub chain: String,
    /// Send `Retry-After: 0` on `processing` polls.
    pub retry_after: bool,
    /// Omit `renewalInfo` from the directory, as an upstream predating
    /// RFC 9773 does.
    pub no_renewal_info: bool,
    /// The `suggestedWindow` served at `renewalInfo`, as `(start, end)`
    /// RFC3339 strings. Garbage here drives the parse-failure branch.
    pub renewal_window: Option<(String, String)>,
    /// Refuse `newAccount` unless it carries an `externalAccountBinding`, as a
    /// CA that issues EAB credentials does.
    pub require_eab: bool,
    /// Refuse `newAccount` with `externalAccountRequired` unconditionally,
    /// even when a binding is presented — simulating a CA that doesn't
    /// recognize the offered `kid`/secret (wrong, expired, or already
    /// consumed), as opposed to `require_eab` simulating one that simply
    /// wants any binding at all.
    pub reject_eab: bool,
    /// Pose a real challenge: the order starts `pending` with one
    /// authorization, which only turns `valid` once its challenge is triggered.
    pub pose_challenge: bool,
    /// Offer `http-01` on that authorization instead of the default `dns-01`.
    pub offer_http01: bool,
    /// Reject the challenge instead of accepting it.
    pub fail_challenge: bool,
    /// Make the authorization's identifier a wildcard, which `http-01` cannot
    /// prove.
    pub wildcard_identifier: bool,
    /// Base URL of an `http-01` responder this upstream should *really* fetch
    /// the challenge file from before deciding the authorization, e.g.
    /// `http://127.0.0.1:41234`.
    ///
    /// `None` — the default — keeps `/chall/1` a counter bump, which is all the
    /// `dns-01` and bypass scenarios need. `Some` is what turns this from
    /// "the relay said it triggered" into "the bytes were actually served",
    /// the one claim the `http01` strategy rests on.
    pub http01_responder: Option<String>,
}

/// A running fake upstream. Dropping it stops the accept loop.
pub struct Upstream {
    pub base: String,
    counters: Arc<Counters>,
    _task: tokio::task::JoinHandle<()>,
}

#[derive(Default)]
struct Counters {
    order_polls: AtomicUsize,
    /// The value of `order_polls` when `finalize` arrived, so polls before and
    /// after it can be scripted independently.
    polls_at_finalize: AtomicUsize,
    finalized: AtomicUsize,
    revoked: AtomicUsize,
    /// `/newNonce` requests. One per signed POST, which is the property the
    /// client's "fetch a fresh nonce every time" rule is asserted on.
    nonce_fetches: AtomicUsize,
    /// Serial source for the nonce values themselves.
    nonce_serial: AtomicUsize,
    bad_nonce_sent: AtomicUsize,
    /// Set once the posed challenge has been triggered.
    challenge_triggered: AtomicUsize,
    /// The body the `http-01` challenge fetch returned, so a test can assert on
    /// the exact key authorization served — the twin of the dns-01 tests
    /// asserting against `expected_value(...)` on their stub updater.
    http01_body: std::sync::Mutex<Option<String>>,
    /// Whether that fetch produced a body bound to the token it asked for.
    http01_ok: std::sync::atomic::AtomicBool,
    /// ARI lookups, and the certID the last one carried — the identifier the
    /// upstream would have to recognize.
    ari_requests: AtomicUsize,
    last_cert_id: std::sync::Mutex<Option<String>>,
    /// The decoded `newAccount` payload of the last EAB-carrying request, so a
    /// test can assert on the binding that was actually sent.
    last_eab_payload: std::sync::Mutex<Option<String>>,
}

impl Upstream {
    /// How many times the order was polled (POST-as-GET).
    pub fn order_polls(&self) -> usize {
        self.counters.order_polls.load(Ordering::SeqCst)
    }
    /// Whether `finalize` was called, and how often.
    pub fn finalized(&self) -> usize {
        self.counters.finalized.load(Ordering::SeqCst)
    }
    /// How many `revokeCert` requests arrived.
    pub fn revoked(&self) -> usize {
        self.counters.revoked.load(Ordering::SeqCst)
    }
    /// How many nonces were fetched — one per signed request, so this is the
    /// proof that each POST got its own rather than reusing one.
    pub fn nonce_fetches(&self) -> usize {
        self.counters.nonce_fetches.load(Ordering::SeqCst)
    }

    /// How many times the posed challenge was triggered.
    pub fn challenge_triggered(&self) -> usize {
        self.counters.challenge_triggered.load(Ordering::SeqCst)
    }

    /// The body the `http-01` challenge fetch read back from the responder,
    /// when [`Script::http01_responder`] pointed at one.
    pub fn http01_body(&self) -> Option<String> {
        self.counters.http01_body.lock().unwrap().clone()
    }

    /// How many ARI lookups arrived.
    pub fn ari_requests(&self) -> usize {
        self.counters.ari_requests.load(Ordering::SeqCst)
    }

    /// The certID of the most recent ARI lookup.
    pub fn last_cert_id(&self) -> Option<String> {
        self.counters.last_cert_id.lock().unwrap().clone()
    }

    /// The decoded `newAccount` payload of the last EAB-carrying request.
    pub fn last_eab_payload(&self) -> Option<String> {
        self.counters.last_eab_payload.lock().unwrap().clone()
    }

    pub fn directory_url(&self) -> String {
        format!("{}/directory", self.base)
    }
}

/// Starts the scripted upstream on a loopback port.
pub async fn start(script: Script) -> Upstream {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let base = format!("http://127.0.0.1:{port}");
    let counters = Arc::new(Counters::default());

    let task = {
        let base = base.clone();
        let counters = counters.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let base = base.clone();
                let counters = counters.clone();
                let script = script.clone();
                tokio::spawn(async move {
                    let Some((method, path, body)) = read_request(&mut stream).await else {
                        return;
                    };
                    let response = route(&method, &path, &body, &base, &script, &counters).await;
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        })
    };

    Upstream {
        base,
        counters,
        _task: task,
    }
}

/// Reads one HTTP/1.1 request: the method, the path, and the body.
async fn read_request(stream: &mut tokio::net::TcpStream) -> Option<(String, String, String)> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 1024];

    // Headers first, up to the blank line.
    let head_end = loop {
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(position) = find(&buffer, b"\r\n\r\n") {
            break position + 4;
        }
    };

    let head = String::from_utf8_lossy(&buffer[..head_end]).into_owned();
    let mut lines = head.lines();
    let mut request_line = lines.next()?.split_whitespace();
    let method = request_line.next()?.to_string();
    let path = request_line.next()?.to_string();

    let length: usize = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().ok())?
        })
        .unwrap_or(0);

    // Then exactly `Content-Length` bytes of body.
    let mut body = buffer[head_end..].to_vec();
    while body.len() < length {
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..read]);
    }

    Some((method, path, String::from_utf8_lossy(&body).into_owned()))
}

/// Pulls the base64url `payload` member out of a flattened JWS body and
/// decodes it, so a route can look at what was actually signed.
fn decoded_payload(body: &str) -> Option<String> {
    use base64::prelude::*;

    let value: Value = serde_json::from_str(body).ok()?;
    let payload = value.get("payload")?.as_str()?;
    let bytes = BASE64_URL_SAFE_NO_PAD.decode(payload).ok()?;
    String::from_utf8(bytes).ok()
}

/// One HTTP/1.1 GET, returning `(status, body)`.
///
/// Hand-written for the same reason the rest of this file is: a real client
/// would drag TLS, DNS and a connection pool in for a request to a loopback
/// port. `Connection: close` plus `read_to_end` is enough here because the
/// peer is `axum`, which answers a sized body with `Content-Length` rather than
/// chunked encoding.
async fn fetch(url: &str) -> Option<(u16, String)> {
    let rest = url.strip_prefix("http://")?;
    let (authority, path) = match rest.find('/') {
        Some(position) => (&rest[..position], &rest[position..]),
        None => (rest, "/"),
    };

    let mut stream = tokio::net::TcpStream::connect(authority).await.ok()?;
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .ok()?;

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.ok()?;
    let raw = String::from_utf8_lossy(&raw);

    let (head, body) = raw.split_once("\r\n\r\n")?;
    let status = head.split_whitespace().nth(1)?.parse().ok()?;
    Some((status, body.to_string()))
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Async only because of the `http-01` arm, which really fetches the challenge
/// file from the responder under test; every other arm is pure.
async fn route(
    method: &str,
    path: &str,
    body: &str,
    base: &str,
    script: &Script,
    counters: &Counters,
) -> String {
    // Strip any absolute-form URI down to its path: the client sends the full
    // URL, which is legal for HTTP/1.1 origin servers to receive.
    let path = path
        .strip_prefix(base)
        .unwrap_or(path)
        .split('?')
        .next()
        .unwrap_or(path);

    // Every signed request is preceded by a nonce fetch, so the counter here
    // is what proves the client is not reusing one.
    if path == "/newNonce" {
        counters.nonce_fetches.fetch_add(1, Ordering::SeqCst);
        return with_nonce(200, "", None, counters);
    }

    if path == "/directory" {
        let mut directory = json!({
            "newNonce": format!("{base}/newNonce"),
            "newAccount": format!("{base}/newAccount"),
            "newOrder": format!("{base}/newOrder"),
            "revokeCert": format!("{base}/revokeCert"),
        });
        if !script.no_renewal_info {
            directory["renewalInfo"] = json!(format!("{base}/renewalInfo"));
        }
        return json_response(200, &directory, None, counters);
    }

    // ARI is an unauthenticated GET of `{renewalInfo}/{certID}`, so the certID
    // arrives as a path segment rather than a body.
    if let Some(cert_id) = path.strip_prefix("/renewalInfo/") {
        counters.ari_requests.fetch_add(1, Ordering::SeqCst);
        *counters.last_cert_id.lock().unwrap() = Some(cert_id.to_string());
        let (start, end) = script.renewal_window.clone().unwrap_or_else(|| {
            (
                "2026-08-01T00:00:00Z".to_string(),
                "2026-08-08T00:00:00Z".to_string(),
            )
        });
        return json_response(
            200,
            &json!({ "suggestedWindow": { "start": start, "end": end } }),
            None,
            counters,
        );
    }

    // One scripted `badNonce`, to drive the client's retry path.
    if script.bad_nonce_once
        && method == "POST"
        && counters.bad_nonce_sent.fetch_add(1, Ordering::SeqCst) == 0
    {
        return problem(
            400,
            "urn:ietf:params:acme:error:badNonce",
            "stale",
            counters,
        );
    }

    match path {
        "/newAccount" => {
            if script.reject_eab {
                return problem(
                    403,
                    "urn:ietf:params:acme:error:externalAccountRequired",
                    "the offered external account binding was not recognized",
                    counters,
                );
            }
            if script.require_eab {
                // Only the presence of the member is checked: this fake
                // verifies no signatures (see the module docs). The *contents*
                // are pinned by `acme_proxy::eab`'s round-trip test against
                // this crate's own verifier, which is a stronger check than
                // anything re-implemented here would be.
                let carries_eab = decoded_payload(body)
                    .map(|payload| payload.contains("externalAccountBinding"))
                    .unwrap_or(false);
                if !carries_eab {
                    return problem(
                        403,
                        "urn:ietf:params:acme:error:externalAccountRequired",
                        "an external account binding is required",
                        counters,
                    );
                }
                *counters.last_eab_payload.lock().unwrap() = decoded_payload(body);
            }
            let location = (!script.omit_location).then(|| format!("{base}/acct/1"));
            json_response(201, &json!({ "status": "valid" }), location, counters)
        }
        "/newOrder" => {
            let location = (!script.omit_location).then(|| format!("{base}/order/1"));
            json_response(
                201,
                &order_object(base, "pending", false),
                location,
                counters,
            )
        }
        // A posed challenge holds the order at `pending` until it is answered.
        "/authz/1" => {
            let answered = counters.challenge_triggered.load(Ordering::SeqCst) > 0;
            // With a responder configured, "answered" is not enough: the file
            // has to have been served with the right bytes, exactly as a real
            // CA decides it.
            let fetch_ok =
                script.http01_responder.is_none() || counters.http01_ok.load(Ordering::SeqCst);
            let status = if answered && (script.fail_challenge || !fetch_ok) {
                "invalid"
            } else if answered {
                "valid"
            } else {
                "pending"
            };
            let typ = if script.offer_http01 {
                "http-01"
            } else {
                "dns-01"
            };
            let identifier = if script.wildcard_identifier {
                "*.example.com"
            } else {
                "example.com"
            };
            json_response(
                200,
                &json!({
                    "status": status,
                    "identifier": { "type": "dns", "value": identifier },
                    "challenges": [{
                        "type": typ,
                        "url": format!("{base}/chall/1"),
                        "token": CHALLENGE_TOKEN,
                        "status": status,
                    }],
                }),
                None,
                counters,
            )
        }
        "/chall/1" => {
            counters.challenge_triggered.fetch_add(1, Ordering::SeqCst);
            if let Some(responder) = &script.http01_responder {
                // The whole claim of the `http01` strategy is that something
                // answers at the well-known path with the right bytes; a
                // counter bump would only prove the relay *triggered*.
                let url = format!("{responder}/.well-known/acme-challenge/{CHALLENGE_TOKEN}");
                if let Some((200, served)) = fetch(&url).await {
                    // The binding a server can check without knowing the
                    // proxy's thumbprint. The exact value is asserted by the
                    // test, from `http01_body()`.
                    let served = served.trim().to_string();
                    counters.http01_ok.store(
                        served.starts_with(&format!("{CHALLENGE_TOKEN}.")),
                        Ordering::SeqCst,
                    );
                    *counters.http01_body.lock().unwrap() = Some(served);
                }
            }
            json_response(200, &json!({ "status": "processing" }), None, counters)
        }
        "/order/1" => {
            let polls = counters.order_polls.fetch_add(1, Ordering::SeqCst);
            if script.order_fails {
                return json_response(200, &order_object(base, "invalid", false), None, counters);
            }
            // While a posed challenge is unanswered the order stays pending.
            if script.pose_challenge && counters.challenge_triggered.load(Ordering::SeqCst) == 0 {
                return json_response(200, &order_object(base, "pending", false), None, counters);
            }
            let status = if counters.finalized.load(Ordering::SeqCst) == 0 {
                // Before finalize: hold at `processing`, then offer `ready`.
                if polls >= script.polls_before_ready {
                    "ready"
                } else {
                    "processing"
                }
            } else {
                // After it: hold again, then hand over the certificate.
                let since = polls.saturating_sub(counters.polls_at_finalize.load(Ordering::SeqCst));
                if since >= script.polls_before_valid {
                    "valid"
                } else {
                    "processing"
                }
            };
            let response = json_response(200, &order_object(base, status, true), None, counters);
            if script.retry_after && status == "processing" {
                insert_header(&response, "Retry-After: 0")
            } else {
                response
            }
        }
        "/order/1/finalize" => {
            if script.bad_csr {
                return problem(
                    403,
                    "urn:ietf:params:acme:error:badCSR",
                    "CSR rejected upstream",
                    counters,
                );
            }
            assert!(
                body.contains("payload"),
                "finalize must carry a signed JWS body"
            );
            counters.polls_at_finalize.store(
                counters.order_polls.load(Ordering::SeqCst),
                Ordering::SeqCst,
            );
            counters.finalized.fetch_add(1, Ordering::SeqCst);
            json_response(
                200,
                &order_object(base, "processing", false),
                None,
                counters,
            )
        }
        "/cert/1" => text_response(200, &script.chain, counters),
        "/revokeCert" => {
            counters.revoked.fetch_add(1, Ordering::SeqCst);
            if script.already_revoked {
                return problem(
                    400,
                    "urn:ietf:params:acme:error:alreadyRevoked",
                    "already revoked",
                    counters,
                );
            }
            json_response(200, &json!({}), None, counters)
        }
        _ => problem(
            404,
            "urn:ietf:params:acme:error:malformed",
            "no such resource",
            counters,
        ),
    }
}

fn order_object(base: &str, status: &str, with_certificate: bool) -> Value {
    let mut object = json!({
        "status": status,
        "finalize": format!("{base}/order/1/finalize"),
        "authorizations": [format!("{base}/authz/1")],
    });
    if with_certificate && status == "valid" {
        object["certificate"] = json!(format!("{base}/cert/1"));
    }
    if status == "invalid" {
        object["error"] = json!({ "detail": "upstream refused the order" });
    }
    object
}

fn next_nonce(counters: &Counters) -> String {
    format!(
        "nonce-{}",
        counters.nonce_serial.fetch_add(1, Ordering::SeqCst)
    )
}

fn with_nonce(status: u16, body: &str, location: Option<String>, counters: &Counters) -> String {
    let mut response = format!(
        "HTTP/1.1 {status} {}\r\nReplay-Nonce: {}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n",
        reason(status),
        next_nonce(counters),
        body.len()
    );
    if let Some(location) = location {
        response.push_str(&format!("Location: {location}\r\n"));
    }
    response.push_str("\r\n");
    response.push_str(body);
    response
}

fn json_response(
    status: u16,
    body: &Value,
    location: Option<String>,
    counters: &Counters,
) -> String {
    with_nonce(status, &body.to_string(), location, counters)
}

fn text_response(status: u16, body: &str, counters: &Counters) -> String {
    with_nonce(status, body, None, counters)
}

fn problem(status: u16, typ: &str, detail: &str, counters: &Counters) -> String {
    with_nonce(
        status,
        &json!({ "type": typ, "detail": detail }).to_string(),
        None,
        counters,
    )
}

fn insert_header(response: &str, header: &str) -> String {
    let (head, body) = response.split_once("\r\n\r\n").unwrap();
    format!("{head}\r\n{header}\r\n\r\n{body}")
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        _ => "Unknown",
    }
}
