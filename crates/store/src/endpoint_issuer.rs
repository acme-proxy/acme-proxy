//! The `endpoint_issuers` table: the CA each `local_ca` endpoint issues from.
//!
//! What lets a worker notice that its CA is not the one the rest of the
//! deployment issues from — a second host started with no key files, or with
//! another host's. The reasoning is in
//! `migrations/20261011130000_profile_issuers.sql`; the check itself is
//! `signer::local_ca::identity`.

use crate::db::Database;

/// One endpoint's recorded issuer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointIssuer {
    pub endpoint: String,
    /// Hex SHA-256 of the CA certificate's SubjectPublicKeyInfo.
    pub issuer: String,
    pub recorded_at: i64,
}

impl EndpointIssuer {
    /// The issuer recorded for `endpoint`, if any.
    pub async fn find(endpoint: &str, database: &Database) -> Result<Option<Self>, sqlx::Error> {
        crate::sql::query(
            "SELECT endpoint, issuer, recorded_at FROM endpoint_issuers WHERE endpoint = ?;",
        )
        .bind(endpoint)
        .fetch_optional(database)
        .await?
        .map(|row| {
            Ok(Self {
                endpoint: row.try_get("endpoint")?,
                issuer: row.try_get("issuer")?,
                recorded_at: row.try_get("recorded_at")?,
            })
        })
        .transpose()
    }

    /// Records `issuer` for `endpoint` unless one is recorded already, and
    /// returns whichever stands.
    ///
    /// Insert-then-read rather than read-then-insert: two workers starting at
    /// once with different CAs both reach this, and exactly one row wins; the
    /// other reads the winner back and refuses.
    pub async fn record_if_absent(
        endpoint: &str,
        issuer: &str,
        now: i64,
        database: &Database,
    ) -> Result<Self, sqlx::Error> {
        crate::sql::query(
            "INSERT INTO endpoint_issuers (endpoint, issuer, recorded_at) VALUES (?, ?, ?) \
             ON CONFLICT (endpoint) DO NOTHING;",
        )
        .bind(endpoint)
        .bind(issuer)
        .bind(now)
        .execute(database)
        .await?;
        Self::find(endpoint, database)
            .await?
            .ok_or(sqlx::Error::RowNotFound)
    }

    /// Records `issuer` for `endpoint`, replacing whatever was recorded: the
    /// deliberate change of CA an operator asks for.
    pub async fn replace(
        endpoint: &str,
        issuer: &str,
        now: i64,
        database: &Database,
    ) -> Result<(), sqlx::Error> {
        crate::sql::query(
            "INSERT INTO endpoint_issuers (endpoint, issuer, recorded_at) VALUES (?, ?, ?) \
             ON CONFLICT (endpoint) DO UPDATE SET \
             issuer = excluded.issuer, recorded_at = excluded.recorded_at;",
        )
        .bind(endpoint)
        .bind(issuer)
        .bind(now)
        .execute(database)
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_first_record_stands_until_replaced() {
        let database = Database::connect_for_test().await.unwrap();
        assert_eq!(
            EndpointIssuer::find("default", &database).await.unwrap(),
            None
        );

        let first = EndpointIssuer::record_if_absent("default", "aa", 1, &database)
            .await
            .unwrap();
        assert_eq!(first.issuer, "aa");
        // A second worker with another CA reads the first one back.
        let second = EndpointIssuer::record_if_absent("default", "bb", 2, &database)
            .await
            .unwrap();
        assert_eq!(second, first);

        EndpointIssuer::replace("default", "bb", 3, &database)
            .await
            .unwrap();
        let now = EndpointIssuer::find("default", &database)
            .await
            .unwrap()
            .unwrap();
        assert_eq!((now.issuer.as_str(), now.recorded_at), ("bb", 3));

        // Endpoints are independent.
        assert_eq!(
            EndpointIssuer::record_if_absent("other", "aa", 4, &database)
                .await
                .unwrap()
                .issuer,
            "aa"
        );
    }
}
