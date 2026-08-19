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
//!
//! # Reloading
//!
//! All six keys reload on `SIGHUP`, which is why the whole stack is built as one
//! [`Installed`] layer behind a [`tracing_subscriber::reload::Layer`] rather
//! than through the `tracing_subscriber::fmt()` builder. Three things that shape
//! rests on, each a bug if reversed:
//!
//! - **The filter is composed with [`Layer::and_then`], never `with_filter`.**
//!   `reload::Handle::reload` is documented as unusable with a
//!   [`tracing_subscriber::filter::Filtered`] layer (tokio-rs/tracing#1629),
//!   because replacing it mints a filter id the registry never saw. `and_then`
//!   is global filtering — `Layered::enabled` is the conjunction of both halves
//!   — which is exactly the semantics `with_env_filter` gave before.
//! - **One boxed layer, not two.** `Box<dyn Layer<S>>` has to name its `S`, and
//!   a second `.with()` makes the next layer's `S` the `Layered<…>` of the
//!   first — a type nothing can write down in a `static`. One box is also one
//!   lock rather than two.
//! - **The handle lives in a process-wide [`OnceLock`], beside the global it is
//!   a handle to.** The subscriber already is process-global (`.init()` panics
//!   on a second call); this is not a second one. Threading the handle from
//!   `main.rs` to `cli::apply_reload` instead would touch six signatures,
//!   including the `serve_on*` seams every test enters through. When it is
//!   unset — a test binary, or a consumer that installed its own subscriber —
//!   [`publish_logging`] is a **no-op that says so**, since logging is then not
//!   ours to swap.
//!
//! The cost, stated rather than buried: a `reload::Layer` puts an `RwLock` read
//! on every event.

use std::sync::OnceLock;

use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::fmt::writer::BoxMakeWriter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer, Registry, reload};

/// The layer stack as one value, so a reload can replace all of it at once.
///
/// Boxed against `Registry` specifically: that is the base subscriber both
/// [`init_logging`] and every swap build on.
type Installed = Box<dyn Layer<Registry> + Send + Sync>;

/// The handle to the installed stack, or unset when this process installed no
/// subscriber of its own. See the reloading notes in the module doc.
static RELOAD: OnceLock<reload::Handle<Installed, Registry>> = OnceLock::new();

/// The tracing filter, and where it came from.
///
/// The provenance travels with the filter because it decides whether an
/// operator is owed a warning: with `RUST_LOG` set, editing `logging.filter`
/// and reloading changes nothing at all, and a silent no-op is the one outcome
/// worth a line in the log.
#[derive(Debug)]
struct ResolvedFilter {
    filter: EnvFilter,
    from_env: bool,
}

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
///
/// The `RUST_LOG`-wins precedence is the same on a reload as at startup, and
/// deliberately: the two disagreeing about what the server is running would be
/// worse than the override itself.
fn build_env_filter(logging: &crate::config::LoggingConfig) -> Result<ResolvedFilter, String> {
    if let Ok(filter) = EnvFilter::try_from_default_env() {
        return Ok(ResolvedFilter {
            filter,
            from_env: true,
        });
    }
    EnvFilter::try_new(&logging.filter)
        .map(|filter| ResolvedFilter {
            filter,
            from_env: false,
        })
        .map_err(|error| {
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

/// A layer stack built from `[logging]` but not yet installed.
///
/// The build/publish split is [`crate::Assembly::build_dispatchers`] and
/// `publish_notifiers`', for the same reason: a reload must be able to fail
/// *after* building this and still leave the running configuration untouched.
pub(crate) struct PreparedLogging {
    layer: Installed,
    /// `RUST_LOG` was set and parsed, so `logging.filter` had no say.
    pub(crate) filter_from_env: bool,
}

/// Resolves `[logging]` into a layer stack, validating every key.
///
/// The one place a stack is built, so startup and a reload cannot drift — the
/// reasoning behind [`super::build_generation`], applied to one layer.
pub(crate) fn prepare_logging(
    logging: &crate::config::LoggingConfig,
) -> Result<PreparedLogging, String> {
    let ResolvedFilter { filter, from_env } = build_env_filter(logging)?;
    let writer = parse_target(&logging.target)?;
    let span_events = parse_span_events(&logging.span_events)?;
    let ansi = ansi_enabled(logging.ansi, std::env::var("NO_COLOR").ok().as_deref());

    // The two arms are separate because `.json()` changes the layer's type, not
    // because they differ in what they configure.
    //
    // **`format.and_then(filter)`, never the other way round.** `and_then`
    // makes its argument the *outer* layer, and `Layered::max_level_hint`
    // directly over a `Registry` returns the outer hint alone — so composing
    // them the readable way round hands the format layer's `None` to
    // `LevelFilter::current()`, which then sits at `TRACE` for the life of the
    // process. Every record would still be filtered correctly by `enabled`, so
    // nothing would look wrong; the cost is that `tracing`'s static
    // short-circuit stops working and every disabled callsite in the tree pays
    // a subscriber call.
    let layer: Installed = if logging.json_format {
        tracing_subscriber::fmt::layer()
            .json()
            .flatten_event(logging.flatten_event)
            .with_span_events(span_events)
            .with_writer(writer)
            .and_then(filter)
            .boxed()
    } else {
        tracing_subscriber::fmt::layer()
            .with_ansi(ansi)
            .with_span_events(span_events)
            .with_writer(writer)
            .and_then(filter)
            .boxed()
    };

    Ok(PreparedLogging {
        layer,
        filter_from_env: from_env,
    })
}

/// Makes `prepared` the stack every later record goes through, reporting
/// whether it took.
///
/// `false` means this process installed no subscriber of its own, so there is
/// no handle and nothing was swapped — see the module doc. Synchronous, which
/// is what lets it sit inside `cli::apply_reload`'s publishing run beside the
/// `watch` sends.
pub(crate) fn publish_logging(prepared: PreparedLogging) -> bool {
    RELOAD
        .get()
        .is_some_and(|handle| handle.reload(prepared.layer).is_ok())
}

/// Installs the process-wide tracing subscriber from `[logging]`.
///
/// Every knob is validated before anything is installed, and an unknown value
/// is an error the caller prints and exits on rather than a silent fallback —
/// the same reasoning as [`build_env_filter`]: a certificate authority running
/// at a log level or to a destination its operator did not ask for is worse
/// than one that refuses to start and says why.
pub fn init_logging(logging: &crate::config::LoggingConfig) -> Result<(), String> {
    let prepared = prepare_logging(logging)?;
    let (layer, handle) = reload::Layer::new(prepared.layer);
    tracing_subscriber::registry().with(layer).init();
    // A second install would already have panicked in `init()` above, so the
    // only way this loses the race is a caller that never got that far.
    let _ = RELOAD.set(handle);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing::level_filters::LevelFilter;

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
        let _guard = crate::config::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::remove_var("RUST_LOG") };

        let logging = crate::config::LoggingConfig {
            filter: "acme_proxy=debug".to_string(),
            ..Default::default()
        };
        let resolved = build_env_filter(&logging).expect("a valid filter builds");
        assert!(
            !resolved.from_env,
            "with RUST_LOG unset the filter comes from `logging.filter`",
        );
    }

    /// The provenance the reload path warns off: `RUST_LOG` wins, so an edited
    /// `logging.filter` would change nothing.
    #[test]
    fn rust_log_wins_and_says_so() {
        let _guard = crate::config::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::set_var("RUST_LOG", "acme_proxy=warn") };

        let logging = crate::config::LoggingConfig {
            filter: "acme_proxy=trace".to_string(),
            ..Default::default()
        };
        let resolved = build_env_filter(&logging).expect("RUST_LOG parses");
        assert!(resolved.from_env);

        unsafe { std::env::remove_var("RUST_LOG") };
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

    /// `prepare_logging` validates everything before building anything, so each
    /// bad key is reported by name — which is what makes a reload carrying one
    /// a refusal with the message startup would have printed, rather than a
    /// half-swapped stack. `init_logging` funnels through it, so the failure
    /// path below covers both.
    #[test]
    fn prepare_logging_reports_each_bad_key_by_name() {
        for (logging, expected) in bad_key_cases() {
            let _guard = crate::config::ENV_LOCK
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            unsafe { std::env::remove_var("RUST_LOG") };

            // Not `expect_err`: the `Ok` side holds a boxed `Layer`, which has
            // no `Debug` to print.
            let Err(error) = prepare_logging(&logging) else {
                panic!("`{expected}` must be refused, not built");
            };
            assert!(error.contains(expected), "{error}");
        }
    }

    /// Publishing with no subscriber installed is a documented no-op rather
    /// than a panic or a lie: this process never called `init_logging`, so
    /// logging is not ours to swap. The `false` is what
    /// `ReloadReport::logging_reloaded` carries, so an operator is told.
    #[test]
    fn publishing_without_an_installed_subscriber_is_a_no_op() {
        let _guard = crate::config::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::remove_var("RUST_LOG") };

        let prepared =
            prepare_logging(&crate::config::LoggingConfig::default()).expect("the defaults build");
        assert!(!publish_logging(prepared));
    }

    /// The swap really changes what is enabled, which is the whole feature.
    ///
    /// `LevelFilter::current()` is the static maximum `tracing` consults before
    /// it reaches any subscriber, so asserting it moved is what proves
    /// `Handle::reload` rebuilt the interest cache rather than merely storing a
    /// new layer nothing asks. Its own process, like the two installers below.
    #[test]
    fn a_reloaded_filter_changes_what_is_enabled() {
        let _guard = crate::config::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::remove_var("RUST_LOG") };

        let at_info = crate::config::LoggingConfig {
            filter: "acme_proxy=info".to_string(),
            target: "stderr".to_string(),
            ..Default::default()
        };
        init_logging(&at_info).expect("the subscriber installs");
        assert_eq!(LevelFilter::current(), LevelFilter::INFO);
        assert!(!tracing::enabled!(target: "acme_proxy", tracing::Level::DEBUG));

        let at_debug = crate::config::LoggingConfig {
            filter: "acme_proxy=debug".to_string(),
            target: "stderr".to_string(),
            ..Default::default()
        };
        let prepared = prepare_logging(&at_debug).expect("the debug filter builds");
        assert!(publish_logging(prepared), "the handle is installed");

        assert_eq!(LevelFilter::current(), LevelFilter::DEBUG);
        assert!(tracing::enabled!(target: "acme_proxy", tracing::Level::DEBUG));
    }

    /// The other five keys change the stack's *shape*, which is why the whole
    /// layer is boxed behind one handle rather than only the filter being
    /// reloadable. Human-readable to JSON is the biggest such change there is.
    #[test]
    fn a_reloaded_format_swaps_the_whole_stack() {
        let _guard = crate::config::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::remove_var("RUST_LOG") };

        init_logging(&crate::config::LoggingConfig {
            target: "stderr".to_string(),
            ansi: false,
            ..Default::default()
        })
        .expect("the subscriber installs");

        let as_json = crate::config::LoggingConfig {
            json_format: true,
            flatten_event: true,
            target: "stderr".to_string(),
            span_events: "close".to_string(),
            ..Default::default()
        };
        let prepared = prepare_logging(&as_json).expect("the JSON stack builds");
        assert!(publish_logging(prepared));

        // The filter has to survive the shape change: `and_then` puts it on the
        // outside precisely so `Layered::max_level_hint` keeps reading it, and
        // building the JSON arm the readable way round would silently drop it
        // to `TRACE` here.
        assert_eq!(
            LevelFilter::current(),
            LevelFilter::INFO,
            "swapping the format must not lose the filter's level hint",
        );
    }

    /// The three keys whose value can be wrong, and the name each must be
    /// refused by. Shared so `init_logging` and `prepare_logging` cannot drift
    /// on which of them they check.
    fn bad_key_cases() -> Vec<(crate::config::LoggingConfig, &'static str)> {
        vec![
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
        ]
    }

    /// `init_logging` validates everything before installing anything, so each
    /// bad key is reported by name. Only the failure path is driven here:
    /// installing a subscriber is process-wide and would leak into every other
    /// test in this binary.
    #[test]
    fn init_logging_reports_each_bad_key_by_name() {
        for (logging, expected) in bad_key_cases() {
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
