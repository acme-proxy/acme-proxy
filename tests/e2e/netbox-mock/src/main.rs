//! A NetBox stand-in for the e2e lab.
//!
//! Serves the five queries the `netbox` IPAM backend makes, for three lab
//! clients:
//!
//! - **certbot** — a name on the address's own custom field, and an interface
//!   in *no* FHRP group, which is what proves membership is required.
//! - **acme.sh** — an empty custom field, so the `device` fallback fires; its
//!   interface *is* in FHRP group 41, and its device carries a role-tagged VIP,
//!   so both service-address sources have something to find.

use axum::{
    Router,
    extract::{Path, Query, RawQuery},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json},
    routing::get,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, env};

#[derive(Deserialize)]
struct IpQuery {
    address: Option<String>,
    device_id: Option<u32>,
    virtual_machine_id: Option<u32>,
}

#[derive(Deserialize)]
struct AssignmentQuery {
    interface_type: Option<String>,
    interface_id: Option<u32>,
}

#[derive(Serialize, Clone)]
struct IpAddress {
    id: u32,
    address: String,
    dns_name: String,
    custom_fields: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    role: Option<serde_json::Value>,
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

#[derive(Serialize)]
struct AssignmentResponse {
    count: usize,
    results: Vec<serde_json::Value>,
}

fn no_names() -> serde_json::Value {
    serde_json::json!({ "acme_allowed_names": [] })
}

/// An address on `device`'s interface `interface`, carrying no names itself.
fn on_interface(id: u32, ip: &str, device: u32, interface: u32) -> IpAddress {
    IpAddress {
        id,
        address: format!("{ip}/24"),
        dns_name: String::new(),
        custom_fields: no_names(),
        role: None,
        assigned_object_type: Some("dcim.interface".to_string()),
        assigned_object: Some(
            serde_json::json!({ "id": interface, "name": "eth0", "device": { "id": device } }),
        ),
    }
}

fn get_addresses() -> HashMap<String, IpAddress> {
    let certbot_ip = env::var("CERTBOT_IP").unwrap_or_else(|_| "10.60.0.4".to_string());
    let acmesh_ip = env::var("ACMESH_IP").unwrap_or_else(|_| "10.60.0.5".to_string());

    let mut map = HashMap::new();
    // certbot: names on the address itself, and interface 8 belongs to no
    // group — the negative half of the FHRP scenario.
    map.insert(
        certbot_ip.clone(),
        IpAddress {
            id: 12,
            address: format!("{certbot_ip}/24"),
            dns_name: String::new(),
            custom_fields: serde_json::json!({"acme_allowed_names": ["allowed.example.com"]}),
            role: None,
            assigned_object_type: Some("dcim.interface".to_string()),
            assigned_object: Some(
                serde_json::json!({ "id": 8, "name": "eth0", "device": { "id": 4 } }),
            ),
        },
    );
    // acme.sh: silent address, so the device fallback fires — and interface 7
    // is the one recorded in FHRP group 41.
    map.insert(acmesh_ip.clone(), on_interface(13, &acmesh_ip, 3, 7));
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

/// Role-tagged service addresses, keyed by the device they sit on.
fn get_service_addresses() -> HashMap<u32, Vec<IpAddress>> {
    let mut map = HashMap::new();
    map.insert(
        3,
        vec![IpAddress {
            id: 20,
            address: "10.60.0.100/24".to_string(),
            dns_name: "vip.example.com".to_string(),
            custom_fields: no_names(),
            role: Some(serde_json::json!({ "value": "vrrp", "label": "VRRP" })),
            assigned_object_type: None,
            assigned_object: None,
        }],
    );
    map
}

/// FHRP group ids, keyed by the interface recorded as a member. Only acme.sh's
/// interface 7 is in one; certbot's interface 8 deliberately is not — which is
/// the whole negative half of the membership scenario.
fn get_memberships() -> HashMap<u32, Vec<u32>> {
    let mut map = HashMap::new();
    map.insert(7, vec![41]);
    map
}

/// The addresses assigned to each FHRP group.
fn get_group_addresses() -> HashMap<u32, Vec<IpAddress>> {
    let mut map = HashMap::new();
    map.insert(
        41,
        vec![IpAddress {
            id: 21,
            address: "10.60.0.101/24".to_string(),
            dns_name: "service.example.com".to_string(),
            custom_fields: no_names(),
            role: None,
            assigned_object_type: Some("ipam.fhrpgroup".to_string()),
            assigned_object: Some(serde_json::json!({ "id": 41 })),
        }],
    );
    map
}

async fn check_token(headers: &HeaderMap) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    let token = env::var("NETBOX_MOCK_TOKEN").unwrap_or_else(|_| "labtoken".to_string());
    if let Some(auth) = headers.get("Authorization") {
        let expected = format!("Token {token}");
        if auth.to_str().unwrap_or("") == expected {
            return Ok(());
        }
    }
    Err((
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({"detail": "Invalid token header."})),
    ))
}

/// `?address=`, `?device_id=&role=`, and `?fhrpgroup_id=` all land here, the
/// way they do in NetBox — one endpoint, several filters.
async fn ip_addresses(
    headers: HeaderMap,
    Query(query): Query<IpQuery>,
    RawQuery(raw): RawQuery,
) -> impl IntoResponse {
    if let Err(e) = check_token(&headers).await {
        return e.into_response();
    }

    let raw = raw.unwrap_or_default();
    let roles: Vec<String> = form_values(&raw, "role");
    let groups: Vec<u32> = form_values(&raw, "fhrpgroup_id")
        .iter()
        .filter_map(|v| v.parse().ok())
        .collect();

    let mut results = vec![];

    if let Some(wanted) = query.address {
        println!("netbox-mock: querying ip address {wanted}");
        if let Some(ip) = get_addresses().remove(&wanted) {
            results.push(ip);
        }
    } else if !groups.is_empty() {
        println!("netbox-mock: querying fhrp group addresses {groups:?}");
        let addresses = get_group_addresses();
        for id in groups {
            results.extend(addresses.get(&id).cloned().unwrap_or_default());
        }
    } else if let Some(device_id) = query.device_id.or(query.virtual_machine_id) {
        println!("netbox-mock: querying service addresses on device {device_id} roles {roles:?}");
        results = get_service_addresses()
            .remove(&device_id)
            .unwrap_or_default()
            .into_iter()
            .filter(|ip| {
                ip.role
                    .as_ref()
                    .and_then(|role| role.get("value"))
                    .and_then(|value| value.as_str())
                    .is_some_and(|value| roles.iter().any(|wanted| wanted == value))
            })
            .collect();
    }

    (
        StatusCode::OK,
        Json(IpResponse {
            count: results.len(),
            results,
        }),
    )
        .into_response()
}

/// The membership question: which groups does *this interface* belong to?
async fn fhrp_group_assignments(
    headers: HeaderMap,
    Query(query): Query<AssignmentQuery>,
) -> impl IntoResponse {
    if let Err(e) = check_token(&headers).await {
        return e.into_response();
    }

    let interface_id = query.interface_id.unwrap_or_default();
    let interface_type = query.interface_type.unwrap_or_default();
    println!("netbox-mock: querying fhrp membership of {interface_type} {interface_id}");

    let results: Vec<serde_json::Value> = get_memberships()
        .remove(&interface_id)
        .unwrap_or_default()
        .into_iter()
        .enumerate()
        .map(|(index, group)| {
            serde_json::json!({
                "id": index + 1,
                "group": { "id": group, "name": format!("vrrp-{group}") },
                "interface_type": interface_type,
                "interface_id": interface_id,
            })
        })
        .collect();

    (
        StatusCode::OK,
        Json(AssignmentResponse {
            count: results.len(),
            results,
        }),
    )
        .into_response()
}

async fn devices(headers: HeaderMap, Path(device_id): Path<u32>) -> impl IntoResponse {
    if let Err(e) = check_token(&headers).await {
        return e.into_response();
    }

    println!("netbox-mock: querying device {device_id}");
    if let Some(device) = get_devices().remove(&device_id) {
        (StatusCode::OK, Json(device)).into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"detail": "Not found."})),
        )
            .into_response()
    }
}

/// Every value of a repeated query parameter. `axum`'s `Query` keeps only one,
/// and `role`/`fhrpgroup_id` are NetBox multiple-choice filters — repeating
/// them rather than comma-joining is exactly what the client is asserting.
fn form_values(raw: &str, key: &str) -> Vec<String> {
    raw.split('&')
        .filter_map(|pair| pair.split_once('='))
        .filter(|(name, _)| *name == key)
        .map(|(_, value)| value.replace("%3A", ":"))
        .collect()
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/api/ipam/ip-addresses/", get(ip_addresses))
        .route("/api/ipam/fhrp-group-assignments/", get(fhrp_group_assignments))
        .route("/api/dcim/devices/{device_id}", get(devices))
        // trailing slash handler for devices if needed
        .route("/api/dcim/devices/{device_id}/", get(devices));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    println!("netbox-mock: listening on 0.0.0.0:8080");
    axum::serve(listener, app).await.unwrap();
}
