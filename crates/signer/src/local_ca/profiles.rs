//! The ACME profiles (draft-ietf-acme-profiles) a local CA offers:
//! `[signer.local_ca.profiles.<name>]`, each a description and a leaf lifetime,
//! plus the `default_profile` an order naming none is issued under.
//!
//! Validated **once, at construction**, by both halves of the backend — the
//! signing [`LocalCa`](super::LocalCa) and the read side
//! [`LocalCaInfo`](super::LocalCaInfo) — from the same configuration, so the
//! directory a client reads and the lifetime a worker signs cannot disagree
//! about which names exist.
//!
//! There is no forced profile here, unlike a relay's `signer.relay.profile`:
//! the operator writes this list, so offering one profile is how a local CA
//! forces it. A client naming any other is refused at `newOrder`
//! (`invalidProfile`), which is what the draft asks of a server; one naming
//! none gets `default_profile`.

use std::collections::BTreeMap;

use acme_proxy_core::config::{ConfigDuration, LocalCaConfig, validate_key_names};

use super::check_leaf_validity;
use crate::{AcmeProfiles, SignerError};

/// A local CA's profiles, checked.
#[derive(Debug, Clone, Default)]
pub(crate) struct LeafProfiles {
    /// Name to lifetime.
    lifetimes: BTreeMap<String, ConfigDuration>,
    /// What [`SignerInfo::acme_profiles`](crate::SignerInfo::acme_profiles)
    /// reports.
    offer: AcmeProfiles,
}

impl LeafProfiles {
    /// Checks every profile's name and lifetime and the default's name, or
    /// fails startup naming the key at fault.
    pub(crate) fn from_config(cfg: &LocalCaConfig) -> anyhow::Result<Self> {
        validate_key_names("signer.local_ca.profiles", cfg.profiles.keys())?;
        for (name, profile) in &cfg.profiles {
            check_leaf_validity(
                &format!("signer.local_ca.profiles.{name}.leaf_validity"),
                profile.leaf_validity,
            )?;
        }
        let default = (!cfg.default_profile.is_empty()).then(|| cfg.default_profile.clone());
        if let Some(default) = &default {
            anyhow::ensure!(
                cfg.profiles.contains_key(default),
                "signer.local_ca.default_profile = \"{default}\" names no \
                 [signer.local_ca.profiles.{default}]"
            );
        }
        Ok(Self {
            lifetimes: cfg
                .profiles
                .iter()
                .map(|(name, profile)| (name.clone(), profile.leaf_validity))
                .collect(),
            offer: AcmeProfiles {
                offered: Some(
                    cfg.profiles
                        .iter()
                        .map(|(name, profile)| (name.clone(), profile.description.clone()))
                        .collect(),
                ),
                default,
                forced: None,
            },
        })
    }

    /// The lifetime to sign under: the order's profile's, or `base` (the CA's
    /// own `leaf_validity`) for an order with none.
    ///
    /// # Errors
    ///
    /// [`SignerError::InvalidProfile`] for a profile not (or no longer)
    /// offered: `newOrder` checked it against the offer of its day, and a
    /// reload since may have removed it.
    pub(crate) fn lifetime(
        &self,
        base: ConfigDuration,
        profile: Option<&str>,
    ) -> Result<ConfigDuration, SignerError> {
        match profile {
            None => Ok(base),
            Some(name) => self
                .lifetimes
                .get(name)
                .copied()
                .ok_or_else(|| SignerError::InvalidProfile(name.to_string())),
        }
    }

    pub(crate) fn offer(&self) -> AcmeProfiles {
        if self.lifetimes.is_empty() {
            AcmeProfiles::none()
        } else {
            self.offer.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use acme_proxy_core::config::LocalCaProfileConfig;

    fn config(profiles: &[(&str, &str)], default: &str) -> LocalCaConfig {
        LocalCaConfig {
            profiles: profiles
                .iter()
                .map(|(name, lifetime)| {
                    (
                        (*name).to_string(),
                        LocalCaProfileConfig {
                            description: format!("{name} certificates"),
                            leaf_validity: ConfigDuration::parse(lifetime).unwrap(),
                        },
                    )
                })
                .collect(),
            default_profile: default.to_string(),
            ..LocalCaConfig::default()
        }
    }

    #[test]
    fn no_profiles_offers_none_and_signs_the_base_lifetime() {
        let profiles = LeafProfiles::from_config(&config(&[], "")).unwrap();
        assert_eq!(profiles.offer(), AcmeProfiles::none());
        let base = ConfigDuration::from_days(90);
        assert_eq!(profiles.lifetime(base, None).unwrap(), base);
    }

    #[test]
    fn each_profile_signs_its_own_lifetime_and_offers_its_description() {
        let profiles = LeafProfiles::from_config(&config(
            &[("shortlived", "160h"), ("classic", "90d")],
            "shortlived",
        ))
        .unwrap();
        let base = ConfigDuration::from_days(30);
        assert_eq!(
            profiles.lifetime(base, Some("shortlived")).unwrap(),
            ConfigDuration::from_hours(160)
        );
        assert_eq!(
            profiles.lifetime(base, Some("classic")).unwrap(),
            ConfigDuration::from_days(90)
        );
        assert_eq!(profiles.lifetime(base, None).unwrap(), base);

        let offer = profiles.offer();
        assert_eq!(offer.default.as_deref(), Some("shortlived"));
        assert_eq!(offer.forced, None);
        assert_eq!(
            offer.offered.unwrap()["shortlived"],
            "shortlived certificates"
        );
    }

    /// A reload that removed the profile an order was accepted under fails the
    /// order rather than signing it under some other lifetime.
    #[test]
    fn a_profile_not_offered_is_an_invalid_profile_at_signing() {
        let profiles = LeafProfiles::from_config(&config(&[("classic", "90d")], "")).unwrap();
        assert!(matches!(
            profiles.lifetime(ConfigDuration::from_days(90), Some("gone")),
            Err(SignerError::InvalidProfile(name)) if name == "gone"
        ));
    }

    #[test]
    fn bad_configurations_are_refused_naming_the_key() {
        for (cfg, key) in [
            (
                config(&[("short", "30m")], ""),
                "signer.local_ca.profiles.short.leaf_validity",
            ),
            (
                config(&[("classic", "90d")], "shortlived"),
                "signer.local_ca.default_profile",
            ),
            (
                config(&[("Short_Lived", "1d")], ""),
                "signer.local_ca.profiles",
            ),
        ] {
            let error = LeafProfiles::from_config(&cfg).unwrap_err().to_string();
            assert!(error.contains(key), "{error}");
        }
    }
}
