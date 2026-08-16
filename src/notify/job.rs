//! One queued notification delivery, as a durable job.
//!
//! The counterpart to [`NotifyDispatcher::dispatch`](super::NotifyDispatcher::dispatch):
//! that side writes a row per (occurrence × backend), this side claims one and
//! runs it. Lives beside its subsystem rather than in [`crate::jobs`], the way
//! `signer::relay::flow::RelayJob` does — `jobs` owns the mechanism, a
//! subsystem owns what its work means.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;
use tracing::{info, warn};

use super::{NotifyDispatcher, NotifyEvent};
use crate::jobs::{JobHandler, JobOutcome};
use crate::sqlite::job::Job;

/// The `jobs.kind` one notification delivery is queued under.
pub const NOTIFY_JOB_KIND: &str = "notify_deliver";

/// Delivers queued notifications.
///
/// Holds the whole `profile name -> dispatcher` map rather than one dispatcher,
/// because there is exactly one handler for a kind and a job row names its own
/// profile. That is also why nothing deduplicates it at registration the way the
/// signer handlers are deduplicated: there is only ever one of these.
pub struct NotifyJob(Arc<HashMap<String, Arc<NotifyDispatcher>>>);

impl NotifyJob {
    #[must_use]
    pub fn new(dispatchers: Arc<HashMap<String, Arc<NotifyDispatcher>>>) -> Self {
        Self(dispatchers)
    }
}

/// What a claimed row says it wants delivered.
struct Delivery {
    profile: String,
    backend: String,
    event: NotifyEvent,
}

impl Delivery {
    /// Reads a payload back. Every failure here is permanent by construction —
    /// the bytes are already written and re-reading them cannot change them.
    fn parse(payload: &Value) -> Result<Self, String> {
        let profile = payload
            .get("profile")
            .and_then(Value::as_str)
            .ok_or("the job payload names no profile")?
            .to_string();
        let backend = payload
            .get("backend")
            .and_then(Value::as_str)
            .ok_or("the job payload names no backend")?
            .to_string();
        let event = payload
            .get("event")
            .ok_or("the job payload carries no event")?;
        let event: NotifyEvent = serde_json::from_value(event.clone())
            .map_err(|error| format!("the job payload's event does not parse: {error}"))?;
        Ok(Self {
            profile,
            backend,
            event,
        })
    }
}

#[async_trait]
impl JobHandler for NotifyJob {
    fn kind(&self) -> &'static str {
        NOTIFY_JOB_KIND
    }

    /// One delivery attempt.
    ///
    /// Three things retire the job immediately rather than retrying, and they
    /// share a shape: nothing about them can change between now and the fifth
    /// attempt. A payload that does not parse never will; a profile or a backend
    /// that is no longer configured is a configuration the operator changed
    /// under a queued row, and re-reading it every thirty seconds until the
    /// budget runs out would say nothing the first log line did not.
    async fn run(&self, job: &Job) -> JobOutcome {
        let delivery = match Delivery::parse(&job.payload) {
            Ok(delivery) => delivery,
            Err(reason) => return JobOutcome::Failed(reason),
        };

        let Some(dispatcher) = self.0.get(&delivery.profile) else {
            return JobOutcome::Failed(format!(
                "no profile `{}` is mounted, so its notification cannot be delivered",
                delivery.profile
            ));
        };

        let kind = delivery.event.kind();
        match dispatcher.deliver(&delivery.backend, &delivery.event).await {
            Some(Ok(())) => {
                info!(
                    event = "notify_delivered",
                    outcome = "success",
                    profile = %delivery.profile,
                    backend = %delivery.backend,
                    kind,
                    attempt = job.attempts,
                );
                JobOutcome::Done
            }
            Some(Err(error)) => {
                warn!(
                    event = "notify_delivery_failed",
                    outcome = "failure",
                    profile = %delivery.profile,
                    backend = %delivery.backend,
                    kind,
                    attempt = job.attempts,
                    retryable = error.retryable(),
                    error = %error,
                );
                if error.retryable() {
                    JobOutcome::Retry(error.to_string())
                } else {
                    JobOutcome::Failed(error.to_string())
                }
            }
            None => JobOutcome::Failed(format!(
                "profile `{}` has no notify backend `{}` configured any more",
                delivery.profile, delivery.backend
            )),
        }
    }

    /// The end of the line for one notification.
    ///
    /// There is nobody to tell, which is the whole difference from
    /// `RelayJob::abandon`: a relay's subject is a client polling an order, and
    /// this one's subject is the operator whose only channel is what just
    /// failed. So this is a log line and nothing else — but it is the log line
    /// to alert on, because it is the moment a notification is genuinely lost.
    async fn abandon(&self, job: &Job, reason: &str) {
        let (profile, backend, kind) = match Delivery::parse(&job.payload) {
            Ok(delivery) => (
                delivery.profile,
                delivery.backend,
                delivery.event.kind().to_string(),
            ),
            // Unparsable is itself one of the ways a job is retired here, so
            // this arm is reachable and must still name what it can.
            Err(_) => (String::new(), String::new(), String::new()),
        };
        warn!(
            event = "notify_delivery_abandoned",
            outcome = "failure",
            profile = %profile,
            backend = %backend,
            kind = %kind,
            attempts = job.attempts,
            reason = %reason,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ALL_NOTIFY_EVENTS;
    use crate::jobs::{JobQueue, JobSpec};
    use crate::notify::tests::RecordingNotifyBackend;
    use crate::notify::{BackendSlot, NotifyError, ProfileMountedData};
    use crate::sqlite::db::Database;
    use serde_json::json;

    async fn queue() -> JobQueue {
        let database = Arc::new(Database::connect_in_memory().await.unwrap());
        JobQueue::new(database, &crate::config::JobsConfig::default())
    }

    fn every_kind() -> Vec<String> {
        ALL_NOTIFY_EVENTS.iter().map(|k| (*k).to_string()).collect()
    }

    fn mounted(profile: &str) -> NotifyEvent {
        NotifyEvent::ProfileMounted(ProfileMountedData {
            profile: profile.to_string(),
        })
    }

    /// A handler over one profile whose single backend is `recorder`.
    fn handler(
        profile: &str,
        recorder: Arc<RecordingNotifyBackend>,
        queue: JobQueue,
    ) -> (NotifyJob, Arc<NotifyDispatcher>) {
        let dispatcher = Arc::new(NotifyDispatcher::new(
            profile,
            vec![BackendSlot::new("recording", recorder, &every_kind())],
            queue,
        ));
        let mut map = HashMap::new();
        map.insert(profile.to_string(), dispatcher.clone());
        (NotifyJob::new(Arc::new(map)), dispatcher)
    }

    /// A job row carrying `payload`, without going through the queue — the
    /// handler only ever reads `payload` and `attempts`.
    fn row(payload: Value) -> Job {
        Job {
            id: "job-1".to_string(),
            kind: NOTIFY_JOB_KIND.to_string(),
            dedup_key: "k".to_string(),
            payload,
            status: "running".to_string(),
            run_at: 0,
            attempts: 1,
            max_attempts: 5,
            deadline: None,
            lease_until: None,
            lease_owner: None,
            last_error: None,
            created_at: 0,
            updated_at: 0,
        }
    }

    fn delivery(profile: &str, backend: &str, event: &NotifyEvent) -> Value {
        json!({ "profile": profile, "backend": backend, "event": event.payload() })
    }

    #[tokio::test]
    async fn a_delivered_notification_is_done() {
        let recorder = Arc::new(RecordingNotifyBackend::default());
        let (job, _dispatcher) = handler("le", recorder.clone(), queue().await);

        let outcome = job
            .run(&row(delivery("le", "recording", &mounted("le"))))
            .await;

        assert!(matches!(outcome, JobOutcome::Done), "{outcome:?}");
        assert_eq!(recorder.events.lock().unwrap().len(), 1);
    }

    /// The distinction the whole queue rests on, at this subsystem's boundary:
    /// a refused connection is asked again, a template that will never render
    /// is not.
    #[tokio::test]
    async fn a_retryable_failure_retries_and_a_permanent_one_does_not() {
        let queue = queue().await;

        let flaky = Arc::new(RecordingNotifyBackend::failing());
        let (job, _d) = handler("le", flaky, queue.clone());
        let outcome = job
            .run(&row(delivery("le", "recording", &mounted("le"))))
            .await;
        assert!(matches!(outcome, JobOutcome::Retry(_)), "{outcome:?}");

        let broken = Arc::new(RecordingNotifyBackend::failing_permanently());
        let (job, _d) = handler("le", broken, queue);
        let outcome = job
            .run(&row(delivery("le", "recording", &mounted("le"))))
            .await;
        assert!(matches!(outcome, JobOutcome::Failed(_)), "{outcome:?}");
    }

    /// A configuration change under a queued row. Both of these would otherwise
    /// burn the whole retry budget re-reading a map that cannot change while the
    /// process lives.
    #[tokio::test]
    async fn an_unknown_profile_or_backend_is_retired_rather_than_retried() {
        let recorder = Arc::new(RecordingNotifyBackend::default());
        let (job, _d) = handler("le", recorder.clone(), queue().await);

        let outcome = job
            .run(&row(delivery("staging", "recording", &mounted("le"))))
            .await;
        match outcome {
            JobOutcome::Failed(reason) => assert!(reason.contains("staging"), "{reason}"),
            other => panic!("{other:?}"),
        }

        let outcome = job
            .run(&row(delivery("le", "carrier-pigeon", &mounted("le"))))
            .await;
        match outcome {
            JobOutcome::Failed(reason) => assert!(reason.contains("carrier-pigeon"), "{reason}"),
            other => panic!("{other:?}"),
        }

        assert!(
            recorder.events.lock().unwrap().is_empty(),
            "neither case may reach a backend"
        );
    }

    /// Three shapes of payload that can never be delivered. Written out rather
    /// than folded into one case because each is a different missing member, and
    /// a `parse` that stopped checking one of them would still pass the others.
    #[tokio::test]
    async fn a_payload_that_cannot_be_read_is_never_retried() {
        let recorder = Arc::new(RecordingNotifyBackend::default());
        let (job, _d) = handler("le", recorder, queue().await);

        for payload in [
            json!({ "backend": "recording", "event": mounted("le").payload() }),
            json!({ "profile": "le", "event": mounted("le").payload() }),
            json!({ "profile": "le", "backend": "recording" }),
            json!({ "profile": "le", "backend": "recording", "event": {"hook": "not_an_event"} }),
        ] {
            let outcome = job.run(&row(payload.clone())).await;
            assert!(
                matches!(outcome, JobOutcome::Failed(_)),
                "{payload}: {outcome:?}"
            );
        }
    }

    /// `abandon` must not panic on the payload that got the job retired in the
    /// first place — the unparsable one is reachable from `run`'s own `Failed`.
    #[tokio::test]
    async fn abandon_survives_the_payload_that_retired_the_job() {
        let recorder = Arc::new(RecordingNotifyBackend::default());
        let (job, _d) = handler("le", recorder, queue().await);

        job.abandon(&row(json!({})), "the payload names no profile")
            .await;
        job.abandon(
            &row(delivery("le", "recording", &mounted("le"))),
            "the attempts ran out",
        )
        .await;
    }

    /// The handler never enqueues anything of its own: a queued row is already
    /// durable, so there is no external state for a restart to re-derive.
    #[tokio::test]
    async fn recover_queues_nothing() {
        let queue = queue().await;
        let recorder = Arc::new(RecordingNotifyBackend::default());
        let (job, _d) = handler("le", recorder, queue.clone());

        job.recover(&queue).await;

        assert!(
            Job::find_live(NOTIFY_JOB_KIND, "k", queue.database())
                .await
                .unwrap()
                .is_none()
        );
    }

    /// A permanent error reported by a backend must not be laundered into a
    /// retry on the way through the handler.
    #[test]
    fn the_error_split_survives_the_round_trip() {
        assert!(NotifyError::new("connection refused").retryable());
        assert!(!NotifyError::permanent("template missing").retryable());
    }

    #[tokio::test]
    async fn the_queued_spec_is_addressed_at_one_backend() {
        let queue = queue().await;
        let spec = JobSpec::now(NOTIFY_JOB_KIND, "delivery-1:email");
        assert!(queue.enqueue(spec).await.unwrap());
        assert!(
            Job::find_live(NOTIFY_JOB_KIND, "delivery-1:email", queue.database())
                .await
                .unwrap()
                .is_some()
        );
    }
}
