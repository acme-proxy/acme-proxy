//! The configuration structs, one file per TOML section.
//!
//! Split out of a single 1008-line `types.rs`: forty struct + `Default` pairs
//! with no logic and no cross-references, which is exactly the shape that reads
//! better grouped by the section an operator is actually editing. Everything is
//! re-exported flat, so no import anywhere outside this directory changes.

use serde::Deserialize;

pub mod audit;
pub mod challenge;
pub mod filter;
pub mod notify;
pub mod profile;
pub mod server;
pub mod signer;

pub use audit::*;
pub use challenge::*;
pub use filter::*;
pub use notify::*;
pub use profile::*;
pub use server::*;
pub use signer::*;

/// Deserializes a `Vec<String>`, treating a single empty-string element as an empty list.
pub(crate) fn empty_string_is_no_values<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let values = Vec::<String>::deserialize(deserializer)?;
    Ok(match values.as_slice() {
        [only] if only.is_empty() => Vec::new(),
        _ => values,
    })
}
