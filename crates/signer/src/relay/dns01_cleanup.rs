//! A bounded worker keeps publication and exact-value cleanup after cancellation.
//! The relay job remains responsible for issuance. Process exit stops this worker.

use std::{
    collections::HashMap,
    sync::{Arc, LazyLock, Mutex, Weak},
    time::Duration,
};

use tokio::sync::{Mutex as AsyncMutex, oneshot};

use super::dns01::DnsUpdater;

type RecordLocks = HashMap<(String, String), Weak<AsyncMutex<()>>>;
static LOCKS: LazyLock<Mutex<RecordLocks>> = LazyLock::new(|| Mutex::new(HashMap::new()));

/// The worker keeps the UPDATE and cleanup when its caller is cancelled.
pub(super) struct PublishedTxt {
    finish: Option<oneshot::Sender<()>>,
    worker: tokio::task::JoinHandle<Result<(), String>>,
}

impl PublishedTxt {
    pub async fn publish(
        updater: Arc<dyn DnsUpdater>,
        update_timeout: Duration,
        name: String,
        value: String,
    ) -> Result<Self, String> {
        let lock = record_lock(&name, &value);
        let (ready, result) = oneshot::channel();
        let (finish, finished) = oneshot::channel();
        let cleanup_timeout = update_timeout * 2;
        let worker = tokio::spawn(async move {
            // A retry with the same value must wait for earlier cleanup.
            let _lock = lock.lock().await;
            if ready.is_closed() {
                return Ok(());
            }
            let added = tokio::time::timeout(update_timeout, updater.upsert_txt(&name, &value))
                .await
                .unwrap_or_else(|_| Err("DNS update timed out".to_string()));
            let success = added.is_ok();
            if ready.send(added).is_ok() && success {
                let _ = finished.await;
            }
            let result = cleanup(
                updater.as_ref(),
                &name,
                &value,
                update_timeout,
                cleanup_timeout,
            )
            .await;
            if result.is_err() {
                tracing::warn!(event = "signer_relay_dns_01_cleanup_failed", outcome = "failure", name = %name);
            }
            result
        });
        match result.await {
            Ok(Ok(())) => Ok(Self {
                finish: Some(finish),
                worker,
            }),
            result => {
                let _ = worker.await;
                Err(match result {
                    Ok(Err(error)) => error,
                    _ => "DNS update worker failed".to_string(),
                })
            }
        }
    }

    pub async fn cleanup(mut self) -> Result<(), String> {
        if let Some(finish) = self.finish.take() {
            let _ = finish.send(());
        }
        (&mut self.worker)
            .await
            .map_err(|_| "DNS cleanup worker failed".to_string())?
    }
}

async fn cleanup(
    updater: &dyn DnsUpdater,
    name: &str,
    value: &str,
    update_timeout: Duration,
    budget: Duration,
) -> Result<(), String> {
    tokio::time::timeout(budget, async {
        for _ in 0..2 {
            if let Ok(Ok(())) =
                tokio::time::timeout(update_timeout, updater.delete_txt(name, value)).await
            {
                return Ok(());
            }
        }
        Err("DNS cleanup failed".to_string())
    })
    .await
    .unwrap_or_else(|_| Err("DNS cleanup timed out".to_string()))
}

fn record_lock(name: &str, value: &str) -> Arc<AsyncMutex<()>> {
    let mut locks = LOCKS.lock().unwrap_or_else(|error| error.into_inner());
    locks.retain(|_, value| value.strong_count() > 0);
    let entry = locks
        .entry((name.to_ascii_lowercase(), value.to_string()))
        .or_default();
    let lock = entry
        .upgrade()
        .unwrap_or_else(|| Arc::new(AsyncMutex::new(())));
    *entry = Arc::downgrade(&lock);
    lock
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Default)]
    struct Updater {
        writes: AtomicUsize,
        deletes: AtomicUsize,
        deleting: tokio::sync::Notify,
        release: tokio::sync::Notify,
        block_delete: bool,
        block_write: bool,
    }
    #[async_trait]
    impl DnsUpdater for Updater {
        async fn upsert_txt(&self, _: &str, _: &str) -> Result<(), String> {
            self.writes.fetch_add(1, Ordering::SeqCst);
            if self.block_write {
                std::future::pending::<()>().await;
            }
            Ok(())
        }
        async fn delete_txt(&self, _: &str, _: &str) -> Result<(), String> {
            self.deletes.fetch_add(1, Ordering::SeqCst);
            self.deleting.notify_one();
            if self.block_delete {
                self.release.notified().await;
            }
            Ok(())
        }
    }

    fn settings() -> Duration {
        Duration::from_millis(100)
    }

    #[tokio::test]
    async fn retry_waits_for_cancelled_attempt_cleanup() {
        let updater = Arc::new(Updater {
            block_delete: true,
            ..Default::default()
        });
        let first =
            PublishedTxt::publish(updater.clone(), settings(), "owner".into(), "value".into())
                .await
                .unwrap();
        drop(first);
        updater.deleting.notified().await;
        let second_updater = updater.clone();
        let second = tokio::spawn(async move {
            PublishedTxt::publish(second_updater, settings(), "owner".into(), "value".into()).await
        });
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(updater.writes.load(Ordering::SeqCst), 1);
        updater.release.notify_one();
        let second = second.await.unwrap().unwrap();
        assert_eq!(updater.writes.load(Ordering::SeqCst), 2);
        updater.release.notify_one();
        second.cleanup().await.unwrap();
        assert_eq!(updater.deletes.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn uncertain_update_still_removes_its_value() {
        let updater = Arc::new(Updater {
            block_write: true,
            ..Default::default()
        });
        assert!(
            PublishedTxt::publish(updater.clone(), settings(), "owner".into(), "value".into())
                .await
                .is_err()
        );
        assert_eq!(updater.deletes.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn cleanup_has_its_own_finite_deadline() {
        let updater = Arc::new(Updater {
            block_delete: true,
            ..Default::default()
        });
        let record =
            PublishedTxt::publish(updater.clone(), settings(), "owner".into(), "value".into())
                .await
                .unwrap();
        let result = tokio::time::timeout(Duration::from_secs(1), record.cleanup())
            .await
            .unwrap();
        assert!(result.is_err());
        assert_eq!(updater.deletes.load(Ordering::SeqCst), 2);
    }
}
