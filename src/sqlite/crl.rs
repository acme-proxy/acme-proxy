//! The `crls` table: each local CA's current signed CRL.
//!
//! One row per issuer, replaced in place. RFC 5280 §5.2.3's `crlNumber` must
//! only increase, and several processes may sign a CRL for one CA, so a
//! replacement is guarded on the number its writer read:
//! [`StoredCrl::replace_if_number`] answers `false` to a writer that lost the
//! race, which re-reads and signs again. Nothing here signs anything — that is
//! `signer::local_ca`'s job, done outside any transaction since a PKCS#11
//! signature is a token round trip.

use sqlx::Row;
use tracing::{debug, info};

use crate::sqlite::db::Database;

/// A signed CRL as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredCrl {
    /// Hex SHA-256 of the issuing CA's SubjectPublicKeyInfo.
    pub issuer: String,
    pub crl_number: u64,
    pub der: Vec<u8>,
    /// Epoch seconds, as signed into the CRL.
    pub this_update: i64,
    /// Epoch seconds, as signed into the CRL.
    pub next_update: i64,
}

impl StoredCrl {
    fn from_row(row: &sqlx::sqlite::SqliteRow) -> Result<Self, sqlx::Error> {
        let number: i64 = row.try_get("crl_number")?;
        Ok(Self {
            issuer: row.try_get("issuer")?,
            crl_number: u64::try_from(number).map_err(|error| sqlx::Error::ColumnDecode {
                index: "crl_number".to_string(),
                source: Box::new(error),
            })?,
            der: row.try_get("der")?,
            this_update: row.try_get("this_update")?,
            next_update: row.try_get("next_update")?,
        })
    }

    /// The current CRL for `issuer`, if one has been stored.
    pub async fn find<'e, E>(issuer: &str, executor: E) -> Result<Option<Self>, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
    {
        sqlx::query(
            "SELECT issuer, crl_number, der, this_update, next_update FROM crls WHERE issuer = ?;",
        )
        .bind(issuer)
        .fetch_optional(executor)
        .await?
        .as_ref()
        .map(Self::from_row)
        .transpose()
    }

    /// [`find`](Self::find) over the pool, for a reader outside `src/sqlite/`
    /// that holds a [`Database`] rather than a
    /// connection — the read side of a local CA, which serves the stored CRL
    /// and never signs one.
    pub async fn find_current(
        issuer: &str,
        database: &Database,
    ) -> Result<Option<Self>, sqlx::Error> {
        Self::find(issuer, &database.pool).await
    }

    /// Stores the first CRL for its issuer, answering whether it was written.
    ///
    /// `false` means another writer stored one first, and theirs stands. This
    /// is what makes a CA's one-time initialisation — the sidecar import — safe
    /// to race: whoever inserts this row owns the import, in the same
    /// transaction.
    pub async fn insert_initial<'e, E>(&self, executor: E) -> Result<bool, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
    {
        let result = sqlx::query(
            "INSERT INTO crls (issuer, crl_number, der, this_update, next_update) \
             VALUES (?, ?, ?, ?, ?) ON CONFLICT (issuer) DO NOTHING;",
        )
        .bind(&self.issuer)
        .bind(number(self.crl_number)?)
        .bind(&self.der)
        .bind(self.this_update)
        .bind(self.next_update)
        .execute(executor)
        .await?;
        let inserted = result.rows_affected() == 1;
        info!(
            event = "db_crl_initialized",
            outcome = "success",
            issuer = %self.issuer,
            crl_number = self.crl_number,
            inserted,
        );
        Ok(inserted)
    }

    /// Replaces the stored CRL with `self`, but only if the stored one is still
    /// numbered `expected` — the number this writer read before signing.
    ///
    /// `false` means somebody else stored a CRL in between. The caller must not
    /// retry this same `self`, whose snapshot is now older than what is stored;
    /// it re-reads and signs again.
    pub async fn replace_if_number(
        &self,
        expected: u64,
        database: &Database,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "UPDATE crls SET crl_number = ?, der = ?, this_update = ?, next_update = ? \
             WHERE issuer = ? AND crl_number = ?;",
        )
        .bind(number(self.crl_number)?)
        .bind(&self.der)
        .bind(self.this_update)
        .bind(self.next_update)
        .bind(&self.issuer)
        .bind(number(expected)?)
        .execute(&database.pool)
        .await?;
        let replaced = result.rows_affected() == 1;
        if replaced {
            info!(
                event = "db_crl_replaced",
                outcome = "success",
                issuer = %self.issuer,
                crl_number = self.crl_number,
            );
        } else {
            debug!(
                event = "db_crl_replace_superseded",
                outcome = "failure",
                issuer = %self.issuer,
                expected_crl_number = expected,
            );
        }
        Ok(replaced)
    }
}

/// A `crl_number` as SQLite stores it. `u64` past `i64::MAX` cannot be bound,
/// and cannot occur: it is a counter bumped once per signed CRL.
fn number(value: u64) -> Result<i64, sqlx::Error> {
    i64::try_from(value).map_err(|error| sqlx::Error::Encode(Box::new(error)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn crl(number: u64, der: &[u8]) -> StoredCrl {
        StoredCrl {
            issuer: "ca".to_string(),
            crl_number: number,
            der: der.to_vec(),
            this_update: 10,
            next_update: 20,
        }
    }

    #[tokio::test]
    async fn the_first_initial_crl_wins() {
        let database = Database::connect_in_memory().await.unwrap();
        assert!(
            StoredCrl::find("ca", &database.pool)
                .await
                .unwrap()
                .is_none()
        );

        assert!(
            crl(1, b"first")
                .insert_initial(&database.pool)
                .await
                .unwrap()
        );
        assert!(
            !crl(7, b"second")
                .insert_initial(&database.pool)
                .await
                .unwrap()
        );

        assert_eq!(
            StoredCrl::find("ca", &database.pool).await.unwrap(),
            Some(crl(1, b"first"))
        );
    }

    /// The guard that keeps `crl_number` monotonic across writers: a CRL signed
    /// over a snapshot that is no longer current is refused, not stored.
    #[tokio::test]
    async fn a_replacement_signed_over_a_stale_number_is_refused() {
        let database = Database::connect_in_memory().await.unwrap();
        crl(1, b"one").insert_initial(&database.pool).await.unwrap();

        // Two writers both read number 1; the first to store wins.
        assert!(
            crl(2, b"two-a")
                .replace_if_number(1, &database)
                .await
                .unwrap()
        );
        assert!(
            !crl(2, b"two-b")
                .replace_if_number(1, &database)
                .await
                .unwrap()
        );
        // The loser re-reads, and its next attempt lands above the winner.
        assert!(
            crl(3, b"three")
                .replace_if_number(2, &database)
                .await
                .unwrap()
        );

        assert_eq!(
            StoredCrl::find("ca", &database.pool).await.unwrap(),
            Some(crl(3, b"three"))
        );
    }

    #[tokio::test]
    async fn nothing_is_replaced_for_an_issuer_never_initialised() {
        let database = Database::connect_in_memory().await.unwrap();
        assert!(
            !crl(2, b"two")
                .replace_if_number(1, &database)
                .await
                .unwrap()
        );
        assert!(
            StoredCrl::find("ca", &database.pool)
                .await
                .unwrap()
                .is_none()
        );
    }
}
