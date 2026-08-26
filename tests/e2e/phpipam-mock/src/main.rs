//! A phpIPAM stand-in for the e2e lab — the twin of `netbox-mock`, and
//! deliberately the same division of labour so the two scenarios read as each
//! other's mirror:
//!
//! - **certbot** — a name on the address's own custom column.
//! - **acme.sh** — an empty column plus a `deviceId`, so the fallback fires.
//! - anything else — a **404**, which is phpIPAM's way of saying "no such
//!   address" and the one wire behaviour that differs from NetBox's.
//!
//! phpIPAM's envelope (`{"code":…,"success":…,"data":…}`), its bare `token`
//! header, its `custom_` column prefix and its habit of rendering integers as
//! strings are all reproduced, because those are exactly what the backend is
//! written against.

use axum::{
    Router,
    extract::Path,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json},
    routing::get,
};
use serde_json::{Value, json};
use std::{collections::HashMap, env};

/// Address rows keyed by IP, in phpIPAM's own shape: every column is a
/// top-level member, and integers come back as strings.
fn get_addresses() -> HashMap<String, Value> {
    let certbot_ip = env::var("CERTBOT_IP").unwrap_or_else(|_| "10.60.0.4".to_string());
    let acmesh_ip = env::var("ACMESH_IP").unwrap_or_else(|_| "10.60.0.5".to_string());

    let mut map = HashMap::new();
    map.insert(
        certbot_ip.clone(),
        json!({
            "id": "12",
            "subnetId": "4",
            "ip": certbot_ip,
            "hostname": "",
            "deviceId": "0",
            // A text column, so several names would be comma-separated.
            "custom_acme_domains": "allowed.example.com",
        }),
    );
    map.insert(
        acmesh_ip.clone(),
        json!({
            "id": "13",
            "subnetId": "4",
            "ip": acmesh_ip,
            "hostname": "",
            "deviceId": "3",
            "custom_acme_domains": "",
        }),
    );
    map
}

fn get_devices() -> HashMap<u32, Value> {
    let mut map = HashMap::new();
    map.insert(
        3,
        json!({
            "id": "3",
            "hostname": "srv1",
            "custom_acme_domains": "machine.example.com",
        }),
    );
    map
}

/// phpIPAM's own scheme: a bare `token` header holding the application's app
/// code, not an `Authorization` header.
fn check_token(headers: &HeaderMap) -> Result<(), (StatusCode, Json<Value>)> {
    let token = env::var("PHPIPAM_MOCK_TOKEN").unwrap_or_else(|_| "labtoken".to_string());
    if let Some(supplied) = headers.get("token")
        && supplied.to_str().unwrap_or("") == token
    {
        return Ok(());
    }
    Err((
        StatusCode::UNAUTHORIZED,
        Json(json!({ "code": 401, "success": false, "message": "Invalid app code" })),
    ))
}

/// `GET /api/<app_id>/addresses/search/<ip>/`
async fn search(headers: HeaderMap, Path((_app, ip)): Path<(String, String)>) -> impl IntoResponse {
    if let Err(e) = check_token(&headers) {
        return e.into_response();
    }

    println!("phpipam-mock: querying ip address {ip}");

    match get_addresses().remove(&ip) {
        Some(row) => (
            StatusCode::OK,
            Json(json!({ "code": 200, "success": true, "data": [row] })),
        )
            .into_response(),
        // The behaviour the whole backend is shaped around: an unknown address
        // is a 404 with an envelope, not an empty list.
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "code": 404, "success": false, "message": "No addresses found" })),
        )
            .into_response(),
    }
}

/// `GET /api/<app_id>/devices/<id>/`
async fn device(headers: HeaderMap, Path((_app, id)): Path<(String, u32)>) -> impl IntoResponse {
    if let Err(e) = check_token(&headers) {
        return e.into_response();
    }

    println!("phpipam-mock: querying device {id}");

    match get_devices().remove(&id) {
        Some(row) => (
            StatusCode::OK,
            Json(json!({ "code": 200, "success": true, "data": row })),
        )
            .into_response(),
        // phpIPAM answers an absent device with 200 and an empty array rather
        // than a 404 — it lends no names, but it is not an error.
        None => (
            StatusCode::OK,
            Json(json!({ "code": 200, "success": true, "data": [] })),
        )
            .into_response(),
    }
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/api/{app_id}/addresses/search/{ip}/", get(search))
        .route("/api/{app_id}/addresses/search/{ip}", get(search))
        .route("/api/{app_id}/devices/{id}/", get(device))
        .route("/api/{app_id}/devices/{id}", get(device));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    println!("phpipam-mock: listening on 0.0.0.0:8080");
    axum::serve(listener, app).await.unwrap();
}
