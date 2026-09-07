//! The `email` notify backend: SMTP via `lettre`.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use tracing::info;

use super::{NotifyBackend, NotifyError, NotifyEvent, render};
use crate::config::EmailNotifyConfig;

/// Delivers a subject + body per event over SMTP.
#[derive(Debug)]
pub struct EmailNotifier {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: Mailbox,
    to: Vec<Mailbox>,
    env: Arc<minijinja::Environment<'static>>,
}

impl EmailNotifier {
    /// Validates the configuration and builds the SMTP transport. Building
    /// the transport does not itself connect — that only happens on `send`,
    /// consistent with the rest of this codebase preferring to fail requests
    /// (or, here, individual deliveries) rather than startup on a transient
    /// network condition.
    /// `allow_empty_to` is set only for the process-wide `[admin.notify]`
    /// dispatcher, whose events carry their own recipient
    /// ([`NotifyEvent::recipient`]): there, an empty `to` is a valid "deliver
    /// to each operator's own `contact_email` and nowhere else". Every
    /// per-profile dispatcher passes `false` and keeps the startup error, since
    /// its events name no recipient and a `send` would have nowhere to go.
    pub fn from_config(
        cfg: &EmailNotifyConfig,
        env: Arc<minijinja::Environment<'static>>,
        allow_empty_to: bool,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            !cfg.smtp_host.trim().is_empty(),
            "notify.email is enabled but notify.email.smtp_host is empty"
        );
        anyhow::ensure!(
            !cfg.from.trim().is_empty(),
            "notify.email is enabled but notify.email.from is empty"
        );
        anyhow::ensure!(
            allow_empty_to || !cfg.to.is_empty(),
            "notify.email is enabled but notify.email.to is empty"
        );

        let from: Mailbox = cfg.from.parse().map_err(|error| {
            anyhow::anyhow!(
                "notify.email.from `{}` is not a valid address: {error}",
                cfg.from
            )
        })?;
        let to = cfg
            .to
            .iter()
            .map(|addr| {
                addr.parse::<Mailbox>().map_err(|error| {
                    anyhow::anyhow!("notify.email.to `{addr}` is not a valid address: {error}")
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;

        let mut builder = match cfg.smtp_security.as_str() {
            "starttls" => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&cfg.smtp_host)?,
            "tls" => AsyncSmtpTransport::<Tokio1Executor>::relay(&cfg.smtp_host)?,
            "none" => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&cfg.smtp_host),
            other => anyhow::bail!(
                "notify.email.smtp_security: unknown value `{other}` \
                 (expected \"starttls\", \"tls\" or \"none\")"
            ),
        };
        builder = builder
            .port(cfg.smtp_port)
            .timeout(Some(Duration::from_millis(cfg.timeout_ms)));
        if !cfg.smtp_username.is_empty() {
            builder = builder.credentials(Credentials::new(
                cfg.smtp_username.clone(),
                cfg.smtp_password.clone(),
            ));
        }
        let transport = builder.build();

        info!(
            event = "notify_email_loaded",
            outcome = "success",
            smtp_host = %cfg.smtp_host,
            smtp_port = cfg.smtp_port,
            smtp_security = %cfg.smtp_security,
            to = ?cfg.to,
        );

        Ok(Self {
            transport,
            from,
            to,
            env,
        })
    }
}

#[async_trait]
impl NotifyBackend for EmailNotifier {
    fn name(&self) -> &'static str {
        "email"
    }

    async fn send(&self, event: &NotifyEvent) -> Result<(), NotifyError> {
        let kind = event.kind();
        let subject = render(&self.env, &format!("email/{kind}.subject.j2"), event)?;
        let body = render(&self.env, &format!("email/{kind}.body.j2"), event)?;

        // An event that names its own recipient (the web-admin security
        // events, whose subject is one operator) goes there instead of the
        // configured `to` -- the operator is the one who has to be told. A
        // parse failure is permanent: the same string will not parse next
        // time either.
        let recipients: Vec<Mailbox> = match event.recipient() {
            Some(address) => vec![address.parse().map_err(|error| {
                NotifyError::permanent(format!(
                    "recipient `{address}` is not a valid address: {error}"
                ))
            })?],
            None => self.to.clone(),
        };
        if recipients.is_empty() {
            // No per-event recipient and no configured fallback: there is
            // nobody to deliver to. Not a failure -- the event is still logged.
            return Ok(());
        }

        let mut builder = Message::builder()
            .from(self.from.clone())
            .subject(subject.trim());
        for to in &recipients {
            builder = builder.to(to.clone());
        }
        // Permanent: an address or a header the builder refuses is a
        // configuration or a template, and it will be refused identically on
        // every attempt.
        let message = builder
            .body(body)
            .map_err(|error| NotifyError::permanent(format!("failed to build message: {error}")))?;

        // Retryable: a relay that is down, refusing connections or greylisting
        // has decided nothing about this message.
        self.transport
            .send(message)
            .await
            .map_err(|error| NotifyError::new(format!("SMTP delivery failed: {error}")))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notify::{CertificateIssuedData, build_environment};

    fn cfg() -> EmailNotifyConfig {
        EmailNotifyConfig {
            smtp_host: "localhost".to_string(),
            from: "acme-proxy@example.com".to_string(),
            to: vec!["ops@example.com".to_string()],
            ..EmailNotifyConfig::default()
        }
    }

    #[test]
    fn missing_smtp_host_is_a_startup_error() {
        let cfg = EmailNotifyConfig {
            smtp_host: String::new(),
            ..cfg()
        };
        let error =
            EmailNotifier::from_config(&cfg, Arc::new(build_environment("")), false).unwrap_err();
        assert!(error.to_string().contains("smtp_host is empty"));
    }

    #[test]
    fn missing_to_is_a_startup_error() {
        let cfg = EmailNotifyConfig {
            to: Vec::new(),
            ..cfg()
        };
        let error =
            EmailNotifier::from_config(&cfg, Arc::new(build_environment("")), false).unwrap_err();
        assert!(error.to_string().contains("to is empty"));
    }

    #[test]
    fn unknown_smtp_security_is_a_startup_error() {
        let cfg = EmailNotifyConfig {
            smtp_security: "smtps-but-typo".to_string(),
            ..cfg()
        };
        let error =
            EmailNotifier::from_config(&cfg, Arc::new(build_environment("")), false).unwrap_err();
        assert!(error.to_string().contains("smtp_security"));
    }

    #[test]
    fn invalid_from_address_is_a_startup_error() {
        let cfg = EmailNotifyConfig {
            from: "not an address".to_string(),
            ..cfg()
        };
        let error =
            EmailNotifier::from_config(&cfg, Arc::new(build_environment("")), false).unwrap_err();
        assert!(error.to_string().contains("notify.email.from"));
    }

    /// One bad address among several is caught, not skipped: the recipient
    /// list is what the operator asked to be reachable at.
    #[test]
    fn an_invalid_recipient_is_a_startup_error() {
        let cfg = EmailNotifyConfig {
            to: vec!["ops@example.com".to_string(), "not an address".to_string()],
            ..cfg()
        };
        let error =
            EmailNotifier::from_config(&cfg, Arc::new(build_environment("")), false).unwrap_err();
        assert!(error.to_string().contains("notify.email.to"), "{error}");
    }

    #[test]
    fn a_missing_from_is_a_startup_error() {
        let cfg = EmailNotifyConfig {
            from: String::new(),
            ..cfg()
        };
        let error =
            EmailNotifier::from_config(&cfg, Arc::new(build_environment("")), false).unwrap_err();
        assert!(error.to_string().contains("from is empty"), "{error}");
    }

    /// `send` renders both templates, builds the message and hands it to the
    /// transport. Nothing listens on port 1, so delivery fails — which is the
    /// point: everything up to and including the SMTP call has run, and the
    /// failure is reported rather than swallowed.
    #[tokio::test]
    async fn send_reports_a_delivery_failure() {
        let cfg = EmailNotifyConfig {
            smtp_host: "127.0.0.1".to_string(),
            smtp_port: 1,
            smtp_security: "none".to_string(),
            timeout_ms: 2000,
            ..cfg()
        };
        let notifier =
            EmailNotifier::from_config(&cfg, Arc::new(build_environment("")), false).unwrap();
        assert_eq!(notifier.name(), "email");

        let error = notifier
            .send(&NotifyEvent::ProfileMounted(
                crate::notify::ProfileMountedData {
                    profile: "le".to_string(),
                },
            ))
            .await
            .expect_err("nothing is listening on port 1");
        assert!(
            error.to_string().contains("SMTP delivery failed"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn renders_the_certificate_issued_template() {
        let notifier =
            EmailNotifier::from_config(&cfg(), Arc::new(build_environment("")), false).unwrap();
        let event = NotifyEvent::CertificateIssued(CertificateIssuedData {
            profile: "le".to_string(),
            order_id: "ord-1".to_string(),
            account_id: "acc-1".to_string(),
            cert_serial: "AA:BB".to_string(),
            identifiers: vec!["example.com".to_string()],
            client_ip: Some("203.0.113.1".to_string()),
        });
        // Delivery itself needs a real SMTP server; a loopback-listener test
        // would only prove `AsyncSmtpTransport` connects, not this backend's
        // own logic. What matters here is that both templates render without
        // error against real event data.
        let subject = render(&notifier.env, "email/certificate_issued.subject.j2", &event).unwrap();
        let body = render(&notifier.env, "email/certificate_issued.body.j2", &event).unwrap();
        assert!(subject.contains("le"));
        assert!(body.contains("example.com"));
    }

    /// An empty `to` is only accepted with `allow_empty_to` — the shape the
    /// process-wide `[admin.notify]` dispatcher passes, since its events carry
    /// their own recipient.
    #[test]
    fn an_empty_to_is_accepted_only_when_allowed() {
        let cfg = EmailNotifyConfig {
            to: Vec::new(),
            ..cfg()
        };
        assert!(EmailNotifier::from_config(&cfg, Arc::new(build_environment("")), false).is_err());
        assert!(EmailNotifier::from_config(&cfg, Arc::new(build_environment("")), true).is_ok());
    }

    fn admin_sign_in(recipient: Option<&str>) -> NotifyEvent {
        NotifyEvent::AdminSignIn(crate::notify::AdminSignInData {
            profile: crate::notify::ADMIN_DISPATCHER_KEY.to_string(),
            username: "alice".to_string(),
            recipient: recipient.map(str::to_string),
            outcome: crate::notify::AdminSignInOutcome::SucceededFromNewAddress,
            client_ip: Some("203.0.113.9".to_string()),
            user_agent: None,
            at: 1_700_000_000,
        })
    }

    /// A per-event recipient is used instead of the configured `to`. Delivery
    /// against port 1 fails, but the failure names the *event's* address — so
    /// the message was addressed there, not to `ops@example.com`.
    #[tokio::test]
    async fn a_per_event_recipient_replaces_the_configured_to() {
        let cfg = EmailNotifyConfig {
            smtp_host: "127.0.0.1".to_string(),
            smtp_port: 1,
            smtp_security: "none".to_string(),
            timeout_ms: 2000,
            ..cfg()
        };
        let notifier =
            EmailNotifier::from_config(&cfg, Arc::new(build_environment("")), false).unwrap();

        // A recipient that will not parse is a permanent failure, and it names
        // the address it tried — proof the per-event recipient was chosen.
        let error = notifier
            .send(&admin_sign_in(Some("not an address")))
            .await
            .expect_err("the recipient does not parse");
        assert!(!error.retryable(), "a bad address is permanent");
        assert!(error.to_string().contains("not an address"), "{error}");
    }

    /// No per-event recipient and an empty configured `to`: nobody to deliver
    /// to, which is `Ok(())` rather than an error — the event is still logged.
    #[tokio::test]
    async fn no_recipient_and_no_fallback_is_a_silent_ok() {
        let cfg = EmailNotifyConfig {
            to: Vec::new(),
            ..cfg()
        };
        let notifier =
            EmailNotifier::from_config(&cfg, Arc::new(build_environment("")), true).unwrap();
        notifier
            .send(&admin_sign_in(None))
            .await
            .expect("nowhere to send is not a failure");
    }

    /// With no per-event recipient, the configured `to` is still used — the
    /// fallback for an operator with no `contact_email`.
    #[tokio::test]
    async fn without_a_recipient_the_configured_to_is_the_fallback() {
        let cfg = EmailNotifyConfig {
            smtp_host: "127.0.0.1".to_string(),
            smtp_port: 1,
            smtp_security: "none".to_string(),
            timeout_ms: 2000,
            ..cfg()
        };
        let notifier =
            EmailNotifier::from_config(&cfg, Arc::new(build_environment("")), true).unwrap();
        let error = notifier
            .send(&admin_sign_in(None))
            .await
            .expect_err("nothing is listening on port 1");
        assert!(
            error.to_string().contains("SMTP delivery failed"),
            "{error}"
        );
    }
}
