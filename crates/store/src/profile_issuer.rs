//! The `profile_issuers` table: the CA each `local_ca` profile issues from.
//!
//! What lets a worker notice that its CA is not the one the rest of the
//! deployment issues from — a second host started with no key files, or with
//! another host's. The reasoning is in
//! `migrations/20261011130000_profile_issuers.sql`; the check itself is
//! `signer::local_ca::identity`.

use crate::db::Database;

/// One profile's recorded issuer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileIssuer {
    pub profile: String,
    /// Hex SHA-256 of the CA certificate's SubjectPublicKeyInfo.
    pub issuer: String,
    pub recorded_at: i64,
}

impl ProfileIssuer {
    /// The issuer recorded for `profile`, if any.
    pub async fn find(profile: &str, database: &Database) -> Result<Option<Self>, sqlx::Error> {
        crate::sql::query(
            "SELECT profile, issuer, recorded_at FROM profile_issuers WHERE profile = ?;",
        )
        .bind(profile)
        .fetch_optional(database)
        .await?
        .map(|row| {
            Ok(Self {
                profile: row.try_get("profile")?,
                issuer: row.try_get("issuer")?,
                recorded_at: row.try_get("recorded_at")?,
            })
        })
        .transpose()
    }

    /// Records `issuer` for `profile` unless one is recorded already, and
    /// returns whichever stands.
    ///
    /// Insert-then-read rather than read-then-insert: two workers starting at
    /// once with different CAs both reach this, and exactly one row wins; the
    /// other reads the winner back and refuses.
    pub async fn record_if_absent(
        profile: &str,
        issuer: &str,
        now: i64,
        database: &Database,
    ) -> Result<Self, sqlx::Error> {
        crate::sql::query(
            "INSERT INTO profile_issuers (profile, issuer, recorded_at) VALUES (?, ?, ?) \
             ON CONFLICT (profile) DO NOTHING;",
        )
        .bind(profile)
        .bind(issuer)
        .bind(now)
        .execute(database)
        .await?;
        Self::find(profile, database)
            .await?
            .ok_or(sqlx::Error::RowNotFound)
    }

    /// Records `issuer` for `profile`, replacing whatever was recorded: the
    /// deliberate change of CA an operator asks for.
    pub async fn replace(
        profile: &str,
        issuer: &str,
        now: i64,
        database: &Database,
    ) -> Result<(), sqlx::Error> {
        crate::sql::query(
            "INSERT INTO profile_issuers (profile, issuer, recorded_at) VALUES (?, ?, ?) \
             ON CONFLICT (profile) DO UPDATE SET \
             issuer = excluded.issuer, recorded_at = excluded.recorded_at;",
        )
        .bind(profile)
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
            ProfileIssuer::find("default", &database).await.unwrap(),
            None
        );

        let first = ProfileIssuer::record_if_absent("default", "aa", 1, &database)
            .await
            .unwrap();
        assert_eq!(first.issuer, "aa");
        // A second worker with another CA reads the first one back.
        let second = ProfileIssuer::record_if_absent("default", "bb", 2, &database)
            .await
            .unwrap();
        assert_eq!(second, first);

        ProfileIssuer::replace("default", "bb", 3, &database)
            .await
            .unwrap();
        let now = ProfileIssuer::find("default", &database)
            .await
            .unwrap()
            .unwrap();
        assert_eq!((now.issuer.as_str(), now.recorded_at), ("bb", 3));

        // Profiles are independent.
        assert_eq!(
            ProfileIssuer::record_if_absent("other", "aa", 4, &database)
                .await
                .unwrap()
                .issuer,
            "aa"
        );
    }
}
