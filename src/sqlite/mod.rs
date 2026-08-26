//! Persistence: one module per table, over `sqlx` and SQLite.
//!
//! Queries are built with the runtime `sqlx::query` API rather than the
//! compile-time macros, so `DATABASE_URL` is not needed to build the crate.
//! Migrations are embedded and run at startup — see [`db`].
//!
//! Two invariants shape almost everything here:
//!
//! - **A profile is a data boundary.** `accounts` and `orders` carry a
//!   `profile` column and `accounts` is keyed `UNIQUE(profile, pubkey)`, so one
//!   client key at two endpoints is two unrelated accounts. Request-path
//!   lookups always take the profile; the admin layer uses the deliberately
//!   unscoped `find_any_*` variants.
//! - **[`audit`] rows outlive their subjects.** That table has no foreign keys,
//!   because a `CASCADE` would delete the evidence along with the account or
//!   order it describes. It is INSERT-only: there is no setter and no `UPDATE`
//!   against it anywhere in the crate.
//!
//! Methods return `Result<_, sqlx::Error>` and leave the mapping to a
//! [`crate::error::Problem`] to their caller.

pub mod account;
pub mod admin_recovery_code;
pub mod admin_session;
pub mod admin_user;
pub mod audit;
pub mod authz;
pub mod db;
pub mod eab;
pub mod id;
pub mod job;
pub mod nonce;
pub mod order;
pub mod status;
pub mod upstream_order;
