use axum::{
    extract::{Path, Query},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json},
    routing::get,
    Router,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, env};

#[derive(Deserialize)]
struct IpQuery {
    address: Option<String>,
}

#[derive(Serialize)]
struct IpAddress {
    id: u32,
    address: String,
    dns_name: String,
    custom_fields: serde_json::Value,
    assigned_object_type: Option<String>,
    assigned_object: Option<serde_json::Value>,
}

#[derive(Serialize)]
struct Device {
    id: u32,
    custom_fields: serde_json::Value,
}

#[derive(Serialize)]
struct IpResponse {
    count: usize,
    results: Vec<IpAddress>,
}

fn get_addresses() -> HashMap<String, IpAddress> {
    let certbot_ip = env::var("CERTBOT_IP").unwrap_or_else(|_| "10.60.0.4".to_string());
    let acmesh_ip = env::var("ACMESH_IP").unwrap_or_else(|_| "10.60.0.5".to_string());

    let mut map = HashMap::new();
    map.insert(
        certbot_ip.clone(),
        IpAddress {
            id: 12,
            address: format!("{}/24", certbot_ip),
            dns_name: "".to_string(),
            custom_fields: serde_json::json!({"acme_allowed_names": ["allowed.example.com"]}),
            assigned_object_type: None,
            assigned_object: None,
        },
    );
    map.insert(
        acmesh_ip.clone(),
        IpAddress {
            id: 13,
            address: format!("{}/24", acmesh_ip),
            dns_name: "".to_string(),
            custom_fields: serde_json::json!({"acme_allowed_names": []}),
            assigned_object_type: Some("dcim.interface".to_string()),
            assigned_object: Some(serde_json::json!({"id": 7, "name": "eth0", "device": {"id": 3}})),
        },
    );
    map
}

fn get_devices() -> HashMap<u32, Device> {
    let mut map = HashMap::new();
    map.insert(
        3,
        Device {
            id: 3,
            custom_fields: serde_json::json!({"acme_allowed_names": ["machine.example.com"]}),
        },
    );
    map
}

async fn check_token(headers: &HeaderMap) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    let token = env::var("NETBOX_MOCK_TOKEN").unwrap_or_else(|_| "labtoken".to_string());
    if let Some(auth) = headers.get("Authorization") {
        let expected = format!("Token {}", token);
        if auth.to_str().unwrap_or("") == expected {
            return Ok(());
        }
    }
    Err((
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({"detail": "Invalid token header."})),
    ))
}

async fn ip_addresses(
    headers: HeaderMap,
    Query(query): Query<IpQuery>,
) -> impl IntoResponse {
    if let Err(e) = check_token(&headers).await {
        return e.into_response();
    }

    let mut results = vec![];
    if let Some(wanted) = query.address {
        println!("netbox-mock: querying ip address {}", wanted);
        if let Some(ip) = get_addresses().remove(&wanted) {
            results.push(ip);
        }
    }

    (StatusCode::OK, Json(IpResponse { count: results.len(), results })).into_response()
}

async fn devices(
    headers: HeaderMap,
    Path(device_id): Path<u32>,
) -> impl IntoResponse {
    if let Err(e) = check_token(&headers).await {
        return e.into_response();
    }

    println!("netbox-mock: querying device {}", device_id);
    if let Some(device) = get_devices().remove(&device_id) {
        (StatusCode::OK, Json(device)).into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"detail": "Not found."})),
        ).into_response()
    }
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/api/ipam/ip-addresses/", get(ip_addresses))
        .route("/api/dcim/devices/{device_id}", get(devices))
        // trailing slash handler for devices if needed
        .route("/api/dcim/devices/{device_id}/", get(devices));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    println!("netbox-mock: listening on 0.0.0.0:8080");
    axum::serve(listener, app).await.unwrap();
}
