//! The `revocations` table: what a local CA has revoked.
//!
//! One row per `(issuer, serial)`. The CRL is signed over these rows and stored
//! in [`super::crl`]; `signer::local_ca` is the only writer of either. No
//! foreign key to `orders`, for the reason the migration gives: a revocation
//! must outlive an order an operator deletes.

use sqlx::Row;
use tracing::{debug, info};

use crate::db::Database;

/// One revoked certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revocation {
    /// The CA that issued it: hex SHA-256 of that CA's SubjectPublicKeyInfo.
    pub issuer: String,
    /// The certificate's serial, hex, as `orders.cert_serial` stores it.
    pub serial: String,
    /// Epoch seconds.
    pub revoked_at: i64,
    /// RFC 5280 §5.3.1 `CRLReason` code.
    pub reason: Option<u32>,
    /// The certificate's own `notAfter`, epoch seconds. `None` is never pruned.
    pub not_after: Option<i64>,
}

impl Revocation {
    /// Records the revocation unless this serial is already revoked under this
    /// issuer, answering whether a row was written.
    ///
    /// The first revocation wins: a repeat changes neither its time nor its
    /// reason, the rule the file-backed ledger's merge kept too.
    pub async fn insert_if_absent<'e, E>(&self, executor: E) -> Result<bool, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
    {
        let result = sqlx::query(
            "INSERT INTO revocations (issuer, serial, revoked_at, reason, not_after) \
             VALUES (?, ?, ?, ?, ?) ON CONFLICT (issuer, serial) DO NOTHING;",
        )
        .bind(&self.issuer)
        .bind(&self.serial)
        .bind(self.revoked_at)
        .bind(self.reason.map(i64::from))
        .bind(self.not_after)
        .execute(executor)
        .await?;
        let inserted = result.rows_affected() == 1;
        debug!(
            event = "db_revocation_recorded",
            outcome = "success",
            issuer = %self.issuer,
            cert_serial = %self.serial,
            inserted,
        );
        Ok(inserted)
    }

    /// Every revocation recorded under `issuer`, oldest first.
    pub async fn list_for_issuer<'e, E>(issuer: &str, executor: E) -> Result<Vec<Self>, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
    {
        let rows = sqlx::query(
            "SELECT issuer, serial, revoked_at, reason, not_after FROM revocations \
             WHERE issuer = ? ORDER BY revoked_at, serial;",
        )
        .bind(issuer)
        .fetch_all(executor)
        .await?;
        rows.iter()
            .map(|row| {
                let reason: Option<i64> = row.try_get("reason")?;
                Ok(Self {
                    issuer: row.try_get("issuer")?,
                    serial: row.try_get("serial")?,
                    revoked_at: row.try_get("revoked_at")?,
                    // A code outside `u32` can only arrive by hand-edit; reading
                    // it as "no reason" is `reason_from_u32`'s own treatment of
                    // an unrecognised code, and refusing to list a revocation
                    // over it would be the unsafe direction.
                    reason: reason.and_then(|code| u32::try_from(code).ok()),
                    not_after: row.try_get("not_after")?,
                })
            })
            .collect()
    }

    /// How many revocations under `issuer` [`Self::prune_expired`] would delete
    /// for the same pair of bounds.
    pub async fn count_expired(
        issuer: &str,
        cutoff: i64,
        listed_before: i64,
        database: &Database,
    ) -> Result<u64, sqlx::Error> {
        let count: i64 = sqlx::query(
            "SELECT COUNT(*) FROM revocations \
             WHERE issuer = ? AND not_after IS NOT NULL AND not_after < ? \
               AND revoked_at <= ?;",
        )
        .bind(issuer)
        .bind(cutoff)
        .bind(listed_before)
        .fetch_one(&database.pool)
        .await?
        .try_get(0)?;
        Ok(u64::try_from(count).unwrap_or_default())
    }

    /// Deletes the revocations under `issuer` whose certificates expired before
    /// `cutoff`, and which a CRL issued at or after `listed_before` already
    /// carried (RFC 5280 §3.3), returning how many went.
    ///
    /// **A row with no `not_after` is never deleted**: an unknown expiry is not
    /// an expired one. The caller backdates `cutoff` by the clock-skew
    /// allowance.
    ///
    /// `listed_before` is the stored CRL's `thisUpdate`, and the second bound
    /// is what §3.3 actually asks for: an entry "MUST NOT be removed from the
    /// CRL until it appears on one regularly scheduled CRL issued beyond the
    /// revoked certificate's validity period". A certificate that expired an
    /// hour ago has not yet appeared on any such CRL, so dropping it here would
    /// leave a relying party holding the last CRL that listed it — signed
    /// before the expiry — with nothing to replace it.
    ///
    /// The `revoked_at` bound is inclusive: the CRL is signed from the rows as
    /// they stand when it is built, so an entry stamped in the same second is
    /// one it carries. An entry recorded in that second but after the snapshot
    /// could be dropped without having been listed, and only if it is *also*
    /// already expired — a revocation of a certificate nothing would honour
    /// anyway.
    pub async fn prune_expired<'e, E>(
        issuer: &str,
        cutoff: i64,
        listed_before: i64,
        executor: E,
    ) -> Result<u64, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
    {
        let result = sqlx::query(
            "DELETE FROM revocations \
             WHERE issuer = ? AND not_after IS NOT NULL AND not_after < ? \
               AND revoked_at <= ?;",
        )
        .bind(issuer)
        .bind(cutoff)
        .bind(listed_before)
        .execute(executor)
        .await?;
        info!(
            event = "db_revocation_pruned",
            outcome = "success",
            issuer = %issuer,
            rows_removed = result.rows_affected(),
            cutoff,
        );
        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn revocation(serial: &str, revoked_at: i64, not_after: Option<i64>) -> Revocation {
        Revocation {
            issuer: "ca".to_string(),
            serial: serial.to_string(),
            revoked_at,
            reason: Some(1),
            not_after,
        }
    }

    #[tokio::test]
    async fn the_first_revocation_of_a_serial_is_the_one_kept() {
        let database = Database::connect_in_memory().await.unwrap();

        assert!(
            revocation("01", 100, None)
                .insert_if_absent(&database.pool)
                .await
                .unwrap()
        );
        let mut repeat = revocation("01", 200, Some(9));
        repeat.reason = Some(4);
        assert!(!repeat.insert_if_absent(&database.pool).await.unwrap());

        let listed = Revocation::list_for_issuer("ca", &database.pool)
            .await
            .unwrap();
        assert_eq!(listed, vec![revocation("01", 100, None)]);
    }

    /// One serial under two issuers is two certificates.
    #[tokio::test]
    async fn issuers_do_not_see_each_others_rows() {
        let database = Database::connect_in_memory().await.unwrap();
        revocation("01", 100, None)
            .insert_if_absent(&database.pool)
            .await
            .unwrap();
        let mut other = revocation("01", 100, None);
        other.issuer = "other".to_string();
        assert!(other.insert_if_absent(&database.pool).await.unwrap());

        assert_eq!(
            Revocation::list_for_issuer("ca", &database.pool)
                .await
                .unwrap()
                .len(),
            1
        );
        assert!(
            Revocation::list_for_issuer("nobody", &database.pool)
                .await
                .unwrap()
                .is_empty()
        );
    }

    /// §3.3: an entry stays until it has appeared on a CRL issued after the
    /// certificate expired. A CRL signed before the expiry does not count, so
    /// the entry it lists is kept even though the certificate is gone.
    #[tokio::test]
    async fn an_entry_no_crl_has_outlived_is_kept() {
        let database = Database::connect_in_memory().await.unwrap();
        // Revoked at 10, expired at 50; the stored CRL was signed at 40.
        revocation("expired", 10, Some(50))
            .insert_if_absent(&database.pool)
            .await
            .unwrap();

        assert_eq!(
            Revocation::count_expired("ca", 50, 40, &database)
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            Revocation::prune_expired("ca", 50, 40, &database.pool)
                .await
                .unwrap(),
            0
        );

        // A CRL signed at 60 carries it past its expiry, and now it may go.
        assert_eq!(
            Revocation::prune_expired("ca", 60, 60, &database.pool)
                .await
                .unwrap(),
            1
        );
    }

    #[tokio::test]
    async fn the_prune_takes_only_known_expiries_before_the_cutoff() {
        let database = Database::connect_in_memory().await.unwrap();
        for row in [
            revocation("expired", 1, Some(50)),
            revocation("boundary", 2, Some(100)),
            revocation("current", 3, Some(500)),
            revocation("unknown", 4, None),
        ] {
            row.insert_if_absent(&database.pool).await.unwrap();
        }
        let mut elsewhere = revocation("elsewhere", 5, Some(50));
        elsewhere.issuer = "other".to_string();
        elsewhere.insert_if_absent(&database.pool).await.unwrap();

        assert_eq!(
            Revocation::count_expired("ca", 100, 1_000, &database)
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            Revocation::prune_expired("ca", 100, 1_000, &database.pool)
                .await
                .unwrap(),
            1
        );

        let left: Vec<String> = Revocation::list_for_issuer("ca", &database.pool)
            .await
            .unwrap()
            .into_iter()
            .map(|row| row.serial)
            .collect();
        assert_eq!(left, ["boundary", "current", "unknown"]);
        assert_eq!(
            Revocation::list_for_issuer("other", &database.pool)
                .await
                .unwrap()
                .len(),
            1,
            "a prune is scoped to its issuer"
        );
    }

    /// A reason code only a hand-edit could store reads as "no reason" rather
    /// than hiding the revocation.
    #[tokio::test]
    async fn an_out_of_range_reason_reads_as_none() {
        let database = Database::connect_in_memory().await.unwrap();
        sqlx::query(
            "INSERT INTO revocations (issuer, serial, revoked_at, reason) VALUES ('ca', '01', 1, -3);",
        )
        .execute(&database.pool)
        .await
        .unwrap();
        let listed = Revocation::list_for_issuer("ca", &database.pool)
            .await
            .unwrap();
        assert_eq!(listed[0].reason, None);
    }
}
