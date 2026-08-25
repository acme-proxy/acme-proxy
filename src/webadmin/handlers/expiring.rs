//! `/api/expiring` — what lapses soon, and whether anything has replaced it.
//!
//! The digest's question (`[notify.expiry]`), asked on demand instead of once
//! per interval into a mailbox. There is no mutating route in this file and
//! there is not meant to be one: renewing a certificate is the *client's*
//! action, driven by its own ACME flow, and a panel button that placed an order
//! on a subscriber's behalf would be this server signing for a key it does not
//! hold. That is why neither handler here takes
//! [`AuthenticatedWrite`](crate::webadmin::session::AuthenticatedWrite) and why
//! `tests/admin_api.rs::mutating_endpoints()` has no entry for `/api/expiring`.
//!
//! Everything below the extractors is [`crate::admin::list_expiring`], which
//! `/ui/expiring` and `order list --expiring-in` also call — one query, one
//! supersession rule, three front ends.

use axum::Json;
use axum::extract::{Query, State};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::admin;
use crate::webadmin::AdminState;
use crate::webadmin::error::AdminError;
use crate::webadmin::handlers::paging::{PageParams, page_envelope};
use crate::webadmin::session::Authenticated;

/// The window fields are inline, not `#[serde(flatten)]` — see the note on
/// [`super::accounts::AccountListParams`].
#[derive(Debug, Deserialize, Default)]
pub struct ExpiringListParams {
    pub profile: Option<String>,
    /// How far ahead to look. Absent is [`crate::admin::default_lead_days`],
    /// which is the deployment's own `[notify.expiry] lead_days` wherever the
    /// digest is on — the operator reading this page is the operator who set
    /// it.
    pub days: Option<u64>,
    /// `"hide"` drops the rows something has already replaced. Anything else,
    /// this member absent included, keeps them: supersession is an annotation,
    /// and the digest's argument for that is in [`crate::notify::expiry`]'s
    /// module docs. The page has room for a control the digest does not, which
    /// is the whole of why this exists here and not there.
    pub superseded: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

impl ExpiringListParams {
    /// The window in days, resolved against the configuration.
    pub(crate) fn lead_days(&self, config: &crate::config::Config) -> u64 {
        self.days
            .unwrap_or_else(|| admin::default_lead_days(config))
    }

    /// Whether replaced certificates stay in the answer.
    ///
    /// Both front ends call this, so `/api/expiring?superseded=typo` and
    /// `/ui/expiring?superseded=typo` give the same answer — the reasoning on
    /// [`super::orders::OrderListParams::parsed_status`]. A value that is not
    /// `"hide"` shows them, because showing is the conservative direction: a
    /// row wrongly hidden is a certificate an operator stops watching.
    pub(crate) fn include_superseded(&self) -> bool {
        self.superseded.as_deref() != Some("hide")
    }
}

/// `GET /api/expiring?profile=&days=&superseded=&limit=&offset=`
pub async fn list_expiring(
    State(state): State<AdminState>,
    Query(params): Query<ExpiringListParams>,
    _auth: Authenticated,
) -> Result<Json<Value>, AdminError> {
    let page = PageParams::from(params.limit, params.offset).resolve(&state.config);
    let days = params.lead_days(&state.config);
    let query = admin::ExpiringQuery {
        profile: params.profile.clone(),
        before: admin::expiring_horizon(days),
        include_superseded: params.include_superseded(),
        limit: page.limit,
        offset: page.offset,
    };
    let (entries, total, hidden) = admin::list_expiring(&query, state.database.clone()).await?;

    let items = entries.iter().map(admin::render_expiring_json).collect();
    let mut envelope = page_envelope(items, total, page);
    if let Some(object) = envelope.as_object_mut() {
        // `total` counts the *window*, not the rows below it: supersession is
        // computed per row and cannot become a SQL predicate, so a hidden row
        // is still counted. `hidden` is what closes that gap for a caller
        // doing its own arithmetic — see `admin::list_expiring`.
        object.insert("hidden".to_string(), json!(hidden));
        object.insert("days".to_string(), json!(days));
    }
    Ok(Json(envelope))
}
