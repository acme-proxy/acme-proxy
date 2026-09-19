//! Waiting for a published `dns-01` record to be served before the upstream is
//! asked to look at it.
//!
//! ## Why the relay waits at all
//!
//! An RFC 2136 NOERROR says the update server *accepted* the record, not that
//! the nameservers the CA will ask are *serving* it: a provider bridging the
//! update to an API answers before its edge has the value, and a primary's
//! secondaries catch up by NOTIFY and IXFR. Triggering in that window is not a
//! cheap retry here. Once the upstream looks and finds nothing, the
//! authorization is `invalid` for good, which [`super::flow`] maps to a
//! permanent failure of the client's order — and a public CA counts it against
//! its failed-validation limit.
//!
//! ## Why a fixed delay, and not a poll
//!
//! The tempting check — ask a public resolver until the value appears — asks
//! the wrong server. The CA resolves through the zone's authoritative
//! nameservers itself; a recursive resolver answers from whichever one it
//! happened to reach, and caches a "no such record" from a lagging one for the
//! zone's negative TTL, failing every later poll. It also never succeeds for an
//! internal or split-horizon zone. A fixed delay is right everywhere, needs no
//! DNS logic, and is the model certbot's DNS plugins use. Polling each
//! authoritative nameserver directly is the sound check, and would be another
//! variant here rather than a change to this one.

use std::time::Duration;

use tracing::debug;

use acme_proxy_core::config::Dns01PropagationConfig;

/// What `answer_dns01` waits for between publishing a record and asking the
/// upstream to validate it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Propagation {
    /// Trigger at once — right when the update server is the one the CA asks.
    None,
    /// Sleep a fixed time — for a provider that accepts an update before
    /// serving it, and the only model that works for every zone view.
    Delay(Duration),
}

impl Propagation {
    /// Builds `[signer.relay.dns01.propagation]`, refusing what cannot work.
    ///
    /// `poll_timeout` is `signer.relay.poll_timeout_secs`, which is the relay
    /// job's lease and so the only bound on a whole attempt: a delay as long as
    /// that would have every attempt killed mid-sleep, the record never
    /// validated and the order retried until its deadline. The delay runs once
    /// per authorization, which a startup check cannot see — the documentation
    /// carries that half.
    pub(super) fn from_config(
        cfg: &Dns01PropagationConfig,
        poll_timeout: Duration,
    ) -> anyhow::Result<Self> {
        match cfg.mode.trim().to_ascii_lowercase().as_str() {
            "none" => Ok(Self::None),
            "delay" => {
                if cfg.delay_secs == 0 {
                    anyhow::bail!(
                        "signer.relay.dns01.propagation.delay_secs is 0: use mode = \"none\" \
                         to trigger right after the update"
                    );
                }
                let delay = Duration::from_secs(cfg.delay_secs);
                if delay >= poll_timeout {
                    anyhow::bail!(
                        "signer.relay.dns01.propagation.delay_secs ({}) must be less than \
                         signer.relay.poll_timeout_secs ({}), which bounds the whole relay \
                         attempt",
                        cfg.delay_secs,
                        poll_timeout.as_secs()
                    );
                }
                Ok(Self::Delay(delay))
            }
            other => anyhow::bail!(
                "unknown signer.relay.dns01.propagation.mode: {other} (supported: none, delay)"
            ),
        }
    }

    /// Waits as configured before the record at `name` is validated.
    pub(super) async fn wait(&self, name: &str) {
        match self {
            Self::None => {}
            Self::Delay(delay) => {
                debug!(
                    event = "signer_relay_dns_01_propagation_waited",
                    outcome = "progress",
                    name = %name,
                    delay_ms = acme_proxy_core::logfields::millis(*delay),
                );
                tokio::time::sleep(*delay).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;

    fn config(mode: &str, delay_secs: u64) -> Dns01PropagationConfig {
        Dns01PropagationConfig {
            mode: mode.to_string(),
            delay_secs,
        }
    }

    const BUDGET: Duration = Duration::from_secs(300);

    #[test]
    fn the_default_waits_for_nothing() {
        assert_eq!(
            Propagation::from_config(&Dns01PropagationConfig::default(), BUDGET).unwrap(),
            Propagation::None
        );
    }

    /// `delay_secs` means nothing under `none`, so a zero there is not an
    /// error — only the mode that reads it validates it.
    #[test]
    fn none_ignores_the_delay() {
        assert_eq!(
            Propagation::from_config(&config("none", 0), BUDGET).unwrap(),
            Propagation::None
        );
    }

    #[test]
    fn delay_builds_its_duration() {
        assert_eq!(
            Propagation::from_config(&config("Delay", 45), BUDGET).unwrap(),
            Propagation::Delay(Duration::from_secs(45))
        );
    }

    /// Each refusal names the key an operator has to change.
    #[test]
    fn every_unworkable_setting_is_refused_by_name() {
        for (cfg, expected) in [
            (config("sometimes", 30), "propagation.mode: sometimes"),
            (config("delay", 0), "propagation.delay_secs is 0"),
            (
                config("delay", 300),
                "must be less than signer.relay.poll_timeout_secs",
            ),
            (
                config("delay", 301),
                "must be less than signer.relay.poll_timeout_secs",
            ),
        ] {
            let error = Propagation::from_config(&cfg, BUDGET)
                .expect_err("this setting must not build")
                .to_string();
            assert!(
                error.contains(expected),
                "expected {expected:?} in: {error}"
            );
        }
    }

    #[tokio::test]
    async fn none_returns_at_once() {
        let started = Instant::now();
        Propagation::None.wait("_acme-challenge.example.org.").await;
        assert!(started.elapsed() < Duration::from_millis(100));
    }

    #[tokio::test]
    async fn delay_waits_its_duration() {
        let started = Instant::now();
        Propagation::Delay(Duration::from_millis(150))
            .wait("_acme-challenge.example.org.")
            .await;
        assert!(started.elapsed() >= Duration::from_millis(150));
    }
}
