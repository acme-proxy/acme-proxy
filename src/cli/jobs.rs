//! `acme-proxy jobs` — inspect and manage the background queue
//! (`src/jobs/` + `src/sqlite/job.rs`), the subsystem whose whole purpose is
//! surviving the failures an operator gets paged about.
//!
//! `list` and `show` are the read half; `cancel` and `run-now` are the two
//! mutations. Cancelling a `signer_relay_issue` job also abandons the ACME
//! order it was driving — that coupling lives in [`crate::admin::ops::cancel_job`],
//! shared with the runner's own `RelayJob::abandon`.

use std::io::BufRead;
use std::sync::Arc;

use clap::Subcommand;

use crate::admin::{self, CancelJobOutcome, RunJobNowOutcome};
use crate::audit::{Actor, ClientContext};
use crate::cli::CliError;
use crate::cli::render;
use crate::cli::style::Palette;
use crate::cli::window::{DEFAULT_LIMIT, Window};
use crate::sqlite::db::Database;
use crate::sqlite::job::{Job, JobQuery};
use crate::sqlite::status::JobStatus;

#[derive(Subcommand)]
pub enum JobsCommand {
    /// List background jobs, optionally filtered.
    List {
        /// A job kind (`signer_relay_issue`, `nonce_sweep`, …). Passed through
        /// as-is: kinds are an open set, so an unknown one simply matches
        /// nothing rather than being an error — unlike `--status`.
        #[arg(long)]
        kind: Option<String>,
        #[arg(long)]
        status: Option<String>,
        #[arg(long, default_value_t = DEFAULT_LIMIT)]
        limit: i64,
        #[arg(long, default_value_t = 0)]
        offset: i64,
        #[arg(long)]
        json: bool,
    },
    /// Show one job, plus the upstream order it drives if it is a relay job.
    Show {
        id: String,
        #[arg(long)]
        json: bool,
    },
    /// Retire a job. On an in-flight relay issuance this also marks the ACME
    /// order invalid and abandons the upstream mapping.
    Cancel { id: String },
    /// Make a job eligible to run at the next queue poll. On a failed job this
    /// grants exactly one more attempt.
    RunNow { id: String },
}

pub async fn run_jobs_command(
    command: JobsCommand,
    yes: bool,
    palette: Palette,
    reader: &mut impl BufRead,
    database: Arc<Database>,
) -> Result<(), CliError> {
    match command {
        JobsCommand::List {
            kind,
            status,
            limit,
            offset,
            json,
        } => {
            // Refused by name rather than passed through: an unknown status
            // would match no rows, which reads exactly like "nothing is in
            // that state" (the `order list --status` rule).
            let status = status
                .map(|value| value.parse::<JobStatus>())
                .transpose()
                .map_err(|error| CliError::bad_request(format!("--status: {error}")))?;
            let window = Window::resolve(limit, offset);
            let query = JobQuery {
                kind,
                status,
                limit: window.limit,
                offset: window.offset,
            };
            let (jobs, total) = Job::search(&query, &database).await?;
            render::print_page(&jobs, total, window, json, admin::render_job_json, |job| {
                render::render_job_line(job, palette)
            });
        }
        JobsCommand::Show { id, json } => {
            let Some(detail) = admin::load_job_detail(&id, database).await? else {
                return Err(not_found(&id));
            };
            if json {
                println!("{}", admin::render_job_detail_json(&detail));
            } else {
                print!("{}", render::render_job_detail_text(&detail, palette));
            }
        }
        JobsCommand::Cancel { id } => {
            match admin::confirm_cancel_job(
                &id,
                yes,
                reader,
                Actor::cli(),
                ClientContext::default(),
                database,
            )
            .await
            .map_err(|error| CliError::failed(error.to_string()))?
            {
                None => println!("Cancelled."),
                Some(CancelJobOutcome::NotFound) => return Err(not_found(&id)),
                Some(CancelJobOutcome::NotCancellable(status)) => {
                    return Err(CliError::bad_request(format!(
                        "job {id} is {status}: only ready or failed jobs can be cancelled"
                    )));
                }
                Some(CancelJobOutcome::Cancelled(job)) => {
                    println!("Cancelled job {id} ({}).", job.kind);
                }
                Some(CancelJobOutcome::CancelledAndOrderAbandoned { order_id, .. }) => {
                    println!(
                        "Cancelled relay job {id}. Order {order_id} was marked invalid and the \
                         upstream mapping abandoned; the client will stop polling."
                    );
                }
            }
        }
        JobsCommand::RunNow { id } => match admin::run_job_now(&id, database).await? {
            RunJobNowOutcome::NotFound => return Err(not_found(&id)),
            RunJobNowOutcome::Refused(status) => {
                return Err(CliError::bad_request(format!(
                    "job {id} is {status}: run-now applies to ready or failed jobs"
                )));
            }
            RunJobNowOutcome::Nudged(_) => {
                println!("Job {id} will run at the next queue poll (run_at set to now).");
            }
            RunJobNowOutcome::Revived(job) => {
                println!(
                    "Job {id} revived: status ready, attempts {}/{} (one more attempt).",
                    job.attempts, job.max_attempts
                );
            }
        },
    }
    Ok(())
}

fn not_found(id: &str) -> CliError {
    CliError::bad_request(format!("no such job: {id}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::CliErrorKind;
    use crate::sqlite::job::NewJob;
    use crate::sqlite::nonce::now_secs;
    use serde_json::json;

    async fn db() -> Arc<Database> {
        Arc::new(Database::connect_in_memory().await.unwrap())
    }

    async fn seed(kind: &str, key: &str, run_at: i64, db: &Database) -> uuid::Uuid {
        let id = crate::sqlite::id::mint();
        Job::enqueue(
            NewJob {
                id,
                kind,
                dedup_key: key,
                payload: &json!({}),
                run_at,
                deadline: None,
                max_attempts: 5,
            },
            db,
        )
        .await
        .unwrap();
        id
    }

    fn palette() -> Palette {
        Palette::plain()
    }

    #[tokio::test]
    async fn every_arm_refuses_an_unknown_job() {
        let db = db().await;
        for cmd in [
            JobsCommand::Show {
                id: "nope".into(),
                json: false,
            },
            JobsCommand::Cancel { id: "nope".into() },
            JobsCommand::RunNow { id: "nope".into() },
        ] {
            let err = run_jobs_command(cmd, true, palette(), &mut &b""[..], db.clone())
                .await
                .unwrap_err();
            assert!(err.message.contains("no such job"), "{}", err.message);
            assert_eq!(err.kind(), CliErrorKind::BadRequest);
        }
    }

    #[tokio::test]
    async fn list_renders_both_ways() {
        let db = db().await;
        seed("nonce_sweep", "a", now_secs(), &db).await;
        seed("signer_relay_issue", "b", now_secs(), &db).await;
        for json in [true, false] {
            run_jobs_command(
                JobsCommand::List {
                    kind: None,
                    status: None,
                    limit: 50,
                    offset: 0,
                    json,
                },
                true,
                palette(),
                &mut &b""[..],
                db.clone(),
            )
            .await
            .unwrap();
        }
    }

    #[tokio::test]
    async fn an_unknown_status_is_refused_by_name() {
        let db = db().await;
        let err = run_jobs_command(
            JobsCommand::List {
                kind: None,
                status: Some("halfway".into()),
                limit: 50,
                offset: 0,
                json: false,
            },
            true,
            palette(),
            &mut &b""[..],
            db,
        )
        .await
        .unwrap_err();
        assert!(err.message.contains("--status"), "{}", err.message);
        assert!(err.message.contains("halfway"), "{}", err.message);
        assert!(
            err.message
                .contains("ready, running, done, failed, cancelled"),
            "{}",
            err.message
        );
        assert_eq!(err.kind(), CliErrorKind::BadRequest);
    }

    #[tokio::test]
    async fn every_job_status_is_accepted_as_a_filter() {
        let db = db().await;
        for status in JobStatus::ALL {
            run_jobs_command(
                JobsCommand::List {
                    kind: None,
                    status: Some(status.as_str().to_string()),
                    limit: 50,
                    offset: 0,
                    json: false,
                },
                true,
                palette(),
                &mut &b""[..],
                db.clone(),
            )
            .await
            .unwrap();
        }
    }

    #[tokio::test]
    async fn cancel_is_confirm_gated() {
        let db = db().await;
        let id = seed("nonce_sweep", "a", now_secs(), &db).await;
        run_jobs_command(
            JobsCommand::Cancel { id: id.to_string() },
            false,
            palette(),
            &mut b"n\n".as_slice(),
            db.clone(),
        )
        .await
        .unwrap();
        assert_eq!(
            Job::find_by_id(id, &db).await.unwrap().unwrap().status,
            "ready"
        );
    }

    #[tokio::test]
    async fn cancel_a_ready_job_and_refuse_a_running_one() {
        let db = db().await;
        let id = seed("nonce_sweep", "a", now_secs(), &db).await;
        run_jobs_command(
            JobsCommand::Cancel { id: id.to_string() },
            true,
            palette(),
            &mut &b""[..],
            db.clone(),
        )
        .await
        .unwrap();
        assert_eq!(
            Job::find_by_id(id, &db).await.unwrap().unwrap().status,
            "cancelled"
        );

        let running = seed("nonce_sweep", "b", now_secs(), &db).await;
        sqlx::query("UPDATE jobs SET status = 'running' WHERE id = ?;")
            .bind(running)
            .execute(&db.pool)
            .await
            .unwrap();
        let err = run_jobs_command(
            JobsCommand::Cancel {
                id: running.to_string(),
            },
            true,
            palette(),
            &mut &b""[..],
            db,
        )
        .await
        .unwrap_err();
        assert!(err.message.contains("running"), "{}", err.message);
        assert_eq!(err.kind(), CliErrorKind::BadRequest);
    }

    #[tokio::test]
    async fn run_now_nudges_and_revives() {
        let db = db().await;
        let ready = seed("nonce_sweep", "a", now_secs() + 3_600, &db).await;
        run_jobs_command(
            JobsCommand::RunNow {
                id: ready.to_string(),
            },
            true,
            palette(),
            &mut &b""[..],
            db.clone(),
        )
        .await
        .unwrap();
        assert!(Job::find_by_id(ready, &db).await.unwrap().unwrap().run_at <= now_secs() + 1);

        let failed = seed("nonce_sweep", "b", now_secs(), &db).await;
        sqlx::query("UPDATE jobs SET status = 'failed', attempts = 5 WHERE id = ?;")
            .bind(failed)
            .execute(&db.pool)
            .await
            .unwrap();
        run_jobs_command(
            JobsCommand::RunNow {
                id: failed.to_string(),
            },
            true,
            palette(),
            &mut &b""[..],
            db.clone(),
        )
        .await
        .unwrap();
        let job = Job::find_by_id(failed, &db).await.unwrap().unwrap();
        assert_eq!(job.status, "ready");
        assert_eq!(job.attempts, 4);
    }

    #[tokio::test]
    async fn run_now_on_a_done_job_is_refused() {
        let db = db().await;
        let id = seed("nonce_sweep", "a", now_secs(), &db).await;
        sqlx::query("UPDATE jobs SET status = 'done' WHERE id = ?;")
            .bind(id)
            .execute(&db.pool)
            .await
            .unwrap();
        let err = run_jobs_command(
            JobsCommand::RunNow { id: id.to_string() },
            true,
            palette(),
            &mut &b""[..],
            db,
        )
        .await
        .unwrap_err();
        assert!(err.message.contains("done"), "{}", err.message);
    }

    #[tokio::test]
    async fn the_window_clamps_a_nonsense_one() {
        let db = db().await;
        seed("nonce_sweep", "a", now_secs(), &db).await;
        run_jobs_command(
            JobsCommand::List {
                kind: None,
                status: None,
                limit: 0,
                offset: -5,
                json: false,
            },
            true,
            palette(),
            &mut &b""[..],
            db,
        )
        .await
        .unwrap();
    }
}
