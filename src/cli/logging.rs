//! `[logging]` — resolving the configuration into an installed subscriber.
//!
//! Split out of `cli/mod.rs`, where it was ~95 production lines with no
//! coupling to anything else in the file: the clap tree, `dispatch` and the
//! `serve*` chain never call any of it beyond the single `init_logging` in
//! [`run`](super::run).
//!
//! The rule the whole module follows: **every knob is validated before anything
//! is installed, and an unknown value is an error the caller prints and exits
//! on rather than a silent fallback.** A certificate authority running at a log
//! level or to a destination its operator did not ask for is worse than one
//! that refuses to start and says why.

use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::fmt::writer::BoxMakeWriter;

/// Builds the tracing filter: `RUST_LOG` if set and valid, else
/// `logging.filter`.
///
/// Returns an error rather than unwrapping. `logging.filter` is
/// operator-supplied and environment-overridable, so a typo in it used to
/// panic the process with a backtrace — four lines after a configuration error
/// was handled cleanly with a message and an exit code. Exiting rather than
/// silently falling back to a default is the deliberate half: a certificate
/// authority quietly running at a different log level than its operator asked
/// for is worse than one that refuses to start and says why.
fn build_env_filter(logging: &crate::config::LoggingConfig) -> Result<EnvFilter, String> {
    if let Ok(filter) = EnvFilter::try_from_default_env() {
        return Ok(filter);
    }
    EnvFilter::try_new(&logging.filter).map_err(|error| {
        format!(
            "configuration error: logging.filter `{}` is not a valid tracing filter: {error}",
            logging.filter
        )
    })
}

/// Resolves `logging.target` to the writer records are sent to.
///
/// Boxed so both values leave this function as one type — the two `fmt`
/// builder chains below are already split by `json_format`, and splitting them
/// again by writer would be four arms saying the same thing.
fn parse_target(target: &str) -> Result<BoxMakeWriter, String> {
    match target {
        "stdout" => Ok(BoxMakeWriter::new(std::io::stdout)),
        "stderr" => Ok(BoxMakeWriter::new(std::io::stderr)),
        other => Err(format!(
            "configuration error: logging.target `{other}` is not a known target (stdout, stderr)"
        )),
    }
}

/// Resolves `logging.span_events` to the span lifecycle records emitted.
///
/// `close` is the one worth reaching for: it emits a record as each span ends,
/// carrying the time spent busy and idle inside it — per-request timing without
/// a metrics endpoint. `full` adds `new`/`enter`/`exit` and is a debugging tool,
/// not something to run a server on.
fn parse_span_events(span_events: &str) -> Result<FmtSpan, String> {
    match span_events {
        "none" => Ok(FmtSpan::NONE),
        "close" => Ok(FmtSpan::CLOSE),
        "full" => Ok(FmtSpan::FULL),
        other => Err(format!(
            "configuration error: logging.span_events `{other}` is not a known value (none, close, full)"
        )),
    }
}

/// Whether to colour the human-readable format: `logging.ansi`, with `NO_COLOR`
/// able to veto it.
///
/// `tracing-subscriber` honours `NO_COLOR` in its own default, and calling
/// `with_ansi` at all replaces that default outright — so configuring this key
/// naively would have silently broken the convention for every operator who
/// relies on it. Either switch turns colour off; neither can turn it on against
/// the other.
///
/// Per the convention, `NO_COLOR` counts only when set to a non-empty value.
fn ansi_enabled(configured: bool, no_color: Option<&str>) -> bool {
    configured && no_color.is_none_or(str::is_empty)
}

/// Installs the process-wide tracing subscriber from `[logging]`.
///
/// Every knob is validated before anything is installed, and an unknown value
/// is an error the caller prints and exits on rather than a silent fallback —
/// the same reasoning as [`build_env_filter`]: a certificate authority running
/// at a log level or to a destination its operator did not ask for is worse
/// than one that refuses to start and says why.
pub(crate) fn init_logging(logging: &crate::config::LoggingConfig) -> Result<(), String> {
    let env_filter = build_env_filter(logging)?;
    let writer = parse_target(&logging.target)?;
    let span_events = parse_span_events(&logging.span_events)?;
    let ansi = ansi_enabled(logging.ansi, std::env::var("NO_COLOR").ok().as_deref());

    // The two arms are separate because `.json()` changes the builder's type,
    // not because they differ in what they configure.
    if logging.json_format {
        tracing_subscriber::fmt()
            .json()
            .flatten_event(logging.flatten_event)
            .with_env_filter(env_filter)
            .with_span_events(span_events)
            .with_writer(writer)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_ansi(ansi)
            .with_env_filter(env_filter)
            .with_span_events(span_events)
            .with_writer(writer)
            .init();
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A malformed `logging.filter` is an error a caller can print, not a
    /// panic. It is operator-supplied and environment-overridable, so a typo
    /// used to take the process down with a backtrace — four lines after a
    /// configuration error was handled cleanly.
    #[test]
    fn a_malformed_logging_filter_is_reported_rather_than_panicking() {
        let logging = crate::config::LoggingConfig {
            filter: "this is not=a=valid=filter".to_string(),
            ..Default::default()
        };
        let error = build_env_filter(&logging).unwrap_err();
        assert!(error.contains("logging.filter"), "{error}");
        assert!(error.contains("this is not=a=valid=filter"), "{error}");
    }

    #[test]
    fn a_valid_logging_filter_builds() {
        let logging = crate::config::LoggingConfig {
            filter: "acme_proxy=debug".to_string(),
            ..Default::default()
        };
        assert!(build_env_filter(&logging).is_ok());
    }

    /// `NO_COLOR` must keep working: `tracing-subscriber` honours it in the
    /// default that `with_ansi` replaces, so configuring the key at all is what
    /// put the convention at risk.
    #[test]
    fn no_color_vetoes_ansi_and_an_empty_value_does_not() {
        assert!(ansi_enabled(true, None));
        assert!(!ansi_enabled(true, Some("1")));
        assert!(!ansi_enabled(true, Some("anything")));
        // The convention counts only a non-empty value.
        assert!(ansi_enabled(true, Some("")));
        // Configured off stays off however NO_COLOR is set.
        assert!(!ansi_enabled(false, None));
        assert!(!ansi_enabled(false, Some("1")));
    }

    #[test]
    fn both_logging_targets_resolve() {
        assert!(parse_target("stdout").is_ok());
        assert!(parse_target("stderr").is_ok());
    }

    /// A typo'd target must stop the process, not quietly pick one: an operator
    /// who asked for `stderr` and silently got `stdout` would look for the log
    /// in the wrong stream.
    #[test]
    fn an_unknown_logging_target_is_reported() {
        let error = parse_target("syslog").unwrap_err();
        assert!(error.contains("logging.target"), "{error}");
        assert!(error.contains("syslog"), "{error}");
        assert!(error.contains("stdout"), "{error}");
    }

    #[test]
    fn every_span_events_value_resolves() {
        assert_eq!(parse_span_events("none").unwrap(), FmtSpan::NONE);
        assert_eq!(parse_span_events("close").unwrap(), FmtSpan::CLOSE);
        assert_eq!(parse_span_events("full").unwrap(), FmtSpan::FULL);
    }

    #[test]
    fn an_unknown_span_events_value_is_reported() {
        let error = parse_span_events("enter").unwrap_err();
        assert!(error.contains("logging.span_events"), "{error}");
        assert!(error.contains("enter"), "{error}");
        assert!(error.contains("close"), "{error}");
    }

    /// `init_logging` validates everything before installing anything, so each
    /// bad key is reported by name. Only the failure path is driven here:
    /// installing a subscriber is process-wide and would leak into every other
    /// test in this binary.
    #[test]
    fn init_logging_reports_each_bad_key_by_name() {
        for (logging, expected) in [
            (
                crate::config::LoggingConfig {
                    filter: "not=a=filter".to_string(),
                    ..Default::default()
                },
                "logging.filter",
            ),
            (
                crate::config::LoggingConfig {
                    target: "nowhere".to_string(),
                    ..Default::default()
                },
                "logging.target",
            ),
            (
                crate::config::LoggingConfig {
                    span_events: "sometimes".to_string(),
                    ..Default::default()
                },
                "logging.span_events",
            ),
        ] {
            // `RUST_LOG` wins over `logging.filter`, so the filter case is only
            // reachable with it unset — which the crate-wide lock guarantees.
            let _guard = crate::config::ENV_LOCK
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            unsafe { std::env::remove_var("RUST_LOG") };

            let error = init_logging(&logging).unwrap_err();
            assert!(error.contains(expected), "{error}");
        }
    }

    /// The two arms that actually install a subscriber, one per test.
    ///
    /// `init()` panics on a second call, so these would be untestable under
    /// plain `cargo test` — one process, every test a thread. nextest runs each
    /// test as its own process, which is what makes installing a *global*
    /// subscriber a thing a test can do at all. (The suite already requires
    /// nextest for an unrelated reason; see the Testing notes.)
    #[test]
    fn the_human_readable_subscriber_installs() {
        let logging = crate::config::LoggingConfig {
            target: "stderr".to_string(),
            ansi: false,
            span_events: "close".to_string(),
            ..Default::default()
        };
        assert!(init_logging(&logging).is_ok());
    }

    #[test]
    fn the_json_subscriber_installs() {
        let logging = crate::config::LoggingConfig {
            json_format: true,
            flatten_event: true,
            span_events: "full".to_string(),
            ..Default::default()
        };
        assert!(init_logging(&logging).is_ok());
    }
}
