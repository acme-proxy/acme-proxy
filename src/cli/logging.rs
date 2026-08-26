//! `[logging]` — resolving the configuration into an installed subscriber.
//!
//! Split out of `cli/mod.rs`, where it was ~95 production lines with no
//! coupling to anything else in the file: the clap tree, `dispatch` and the
//! `serve*` chain never call any of it beyond the single [`init_logging`]
//! `src/main.rs` makes.
//!
//! The rule the whole module follows: **every knob is validated before anything
//! is installed, and an unknown value is an error the caller prints and exits
//! on rather than a silent fallback.** A certificate authority running at a log
//! level or to a destination its operator did not ask for is worse than one
//! that refuses to start and says why.
//!
//! # Who gets a subscriber
//!
//! `[logging]` describes the **server's** log stream, and until this module
//! grew [`plan_logging`] every subcommand got it: with the shipped defaults
//! (`acme_proxy=info`, to **stdout**) `acme-proxy account list --json | jq`
//! read a `db_migration_completed` record before the JSON, and `filter
//! explain` wrote a `warn` into the middle of the explanation it was printing.
//!
//! So the decision is now made per invocation, by a pure function a test can
//! drive rather than in `main.rs`, which the coverage floor excludes:
//!
//! - `serve` gets the stack `[logging]` describes, exactly as before.
//! - **Any other subcommand emits nothing at all** unless the operator asks —
//!   with `--log-level`, or with a non-empty `RUST_LOG`. There is no subscriber
//!   in that case, so every `tracing` call in the process is a no-op rather
//!   than a filtered one.
//! - When one does ask, the records go to **stderr** whatever `logging.target`
//!   says, because stdout is the answer the operator's `jq` or `awk` is reading
//!   and a diagnostic does not belong in it.
//!
//! [`LogLevel`] outranks both `RUST_LOG` and `logging.filter`, which is
//! [`super::style`]'s argument for `--color always` outranking `NO_COLOR`: a
//! flag was typed on this command line where the other two are ambient. See
//! [`FilterSource`], which travels with the filter so a reload can say which of
//! the three won.
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

use clap::ValueEnum;
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

/// The `--log-level` directive this process was started with, or unset when the
/// flag was not given.
///
/// Beside [`RELOAD`] and for its reason, stated in the module doc: a reload
/// rebuilds the stack from the *file*, so without somewhere process-wide to
/// read the flag back from, `SIGHUP` would silently drop it — and threading it
/// down instead would touch the same six signatures, `serve_on*` included.
/// Written once, after the value has been validated by building a filter from
/// it, so a refused startup leaves nothing behind.
static FILTER_OVERRIDE: OnceLock<String> = OnceLock::new();

/// The `--log-level` directive to apply, or `None` when the flag was not given.
///
/// The one accessor for [`FILTER_OVERRIDE`], so a reload re-reads what startup
/// was told rather than each caller reaching for the cell.
pub(crate) fn flag_override() -> Option<&'static str> {
    FILTER_OVERRIDE.get().map(String::as_str)
}

/// `--log-level`: how much this invocation logs.
///
/// A crate-local enum rather than [`tracing::Level`] for two reasons: `off` is
/// not a level, and `clap`'s [`ValueEnum`] cannot be implemented for a foreign
/// type anyway. Being a `value_enum` is also what puts the six values into the
/// generated shell completions, which is what `--color` already buys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum LogLevel {
    Off,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    /// The `EnvFilter` directive this level asks for.
    ///
    /// **Scoped to this crate's own target**, so `--log-level debug` does not
    /// also unleash `sqlx`, `hyper` and `rustls` on someone who wanted to see
    /// why one command behaved oddly. `RUST_LOG` stays the way to write a
    /// directive that reaches further — it is the same string this would have
    /// to become, and a flag that took one would be a second spelling of it.
    pub(crate) fn directive(self) -> String {
        match self {
            // Not `acme_proxy=off`: a per-target directive at `off` still
            // leaves every *other* target at the default level, so the one
            // value asking for silence would be the one that did not deliver
            // it.
            Self::Off => "off".to_string(),
            Self::Error => "acme_proxy=error".to_string(),
            Self::Warn => "acme_proxy=warn".to_string(),
            Self::Info => "acme_proxy=info".to_string(),
            Self::Debug => "acme_proxy=debug".to_string(),
            Self::Trace => "acme_proxy=trace".to_string(),
        }
    }
}

/// Which subscriber, if any, an invocation installs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoggingPlan {
    /// Install nothing. Every `tracing` call in the process is then a no-op,
    /// which is stronger — and cheaper — than a subscriber filtering them all
    /// out.
    Silent,
    /// Install the stack `[logging]` describes: the server's own log stream.
    Server,
    /// Install a diagnostic stack on stderr for a one-shot admin command.
    Command,
}

/// Decides what this invocation logs, from the subcommand and the two ways an
/// operator can ask.
///
/// Pure, and here rather than in `src/main.rs` because that file is excluded
/// from the coverage floor: every rule below is a row of a table test.
///
/// `rust_log` counts only when **non-empty**, which is
/// [`super::style::no_color_set`]'s judgement applied to the other ambient
/// environment variable this CLI reads. A `RUST_LOG=` left behind by a
/// `${RUST_LOG:-}`-style shell default is not somebody asking for logs, and
/// treating it as one would put records back in the pipe this exists to keep
/// clean.
pub fn plan_logging(
    command: Option<&super::Command>,
    level: Option<LogLevel>,
    rust_log: Option<&str>,
) -> LoggingPlan {
    match command {
        // A daemon logs; the flag only sharpens what it says. `None` is the
        // default subcommand, i.e. a bare `acme-proxy`.
        None | Some(super::Command::Serve) => LoggingPlan::Server,
        // `main.rs` answers both before it loads a configuration, so neither
        // reaches here — but answering them keeps this total over `Command`,
        // the rule `dispatch` follows for the same pair.
        Some(super::Command::Completions { .. } | super::Command::Man) => LoggingPlan::Silent,
        Some(_) => {
            if level.is_some() || rust_log.is_some_and(|value| !value.is_empty()) {
                LoggingPlan::Command
            } else {
                LoggingPlan::Silent
            }
        }
    }
}

/// Which of the three layers supplied the filter in force.
///
/// The provenance travels with the filter because it decides whether an
/// operator is owed a warning: with either of the two outranking layers in
/// play, editing `logging.filter` and reloading changes nothing at all, and a
/// silent no-op is the one outcome worth a line in the log. It is also the
/// `source` field on that warning, so the operator is told *which* to unset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FilterSource {
    /// `--log-level`, typed on this command line.
    Flag,
    /// `RUST_LOG`, from the environment.
    Env,
    /// `logging.filter`, from the configuration file.
    Config,
}

impl FilterSource {
    /// The `source` field's value on `server_logging_filter_overridden`.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Flag => "flag",
            Self::Env => "env",
            Self::Config => "config",
        }
    }

    /// Whether `logging.filter` was overruled, i.e. whether editing it and
    /// reloading would change nothing.
    pub(crate) fn outranks_config(self) -> bool {
        !matches!(self, Self::Config)
    }
}

/// The tracing filter, and where it came from.
#[derive(Debug)]
struct ResolvedFilter {
    filter: EnvFilter,
    source: FilterSource,
}

/// Builds the tracing filter: `flag` if given, else `RUST_LOG` if set and
/// valid, else `logging.filter`.
///
/// Returns an error rather than unwrapping. `logging.filter` is
/// operator-supplied and environment-overridable, so a typo in it used to
/// panic the process with a backtrace — four lines after a configuration error
/// was handled cleanly with a message and an exit code. Exiting rather than
/// silently falling back to a default is the deliberate half: a certificate
/// authority quietly running at a different log level than its operator asked
/// for is worse than one that refuses to start and says why.
///
/// `flag` outranks `RUST_LOG` for [`super::style`]'s reason: it was typed on
/// this command line, where the environment is ambient. It is a [`LogLevel`]
/// rendering rather than operator text, so it cannot fail to parse — but it
/// goes through the same `try_new` as the other two rather than being trusted,
/// since a value that cannot fail is one nobody notices becoming able to.
///
/// The precedence is the same on a reload as at startup, and deliberately: the
/// two disagreeing about what the server is running would be worse than the
/// override itself.
fn build_env_filter(
    logging: &crate::config::LoggingConfig,
    flag: Option<&str>,
) -> Result<ResolvedFilter, String> {
    if let Some(directive) = flag {
        return EnvFilter::try_new(directive)
            .map(|filter| ResolvedFilter {
                filter,
                source: FilterSource::Flag,
            })
            .map_err(|error| {
                format!("--log-level `{directive}` is not a valid tracing filter: {error}")
            });
    }
    if let Ok(filter) = EnvFilter::try_from_default_env() {
        return Ok(ResolvedFilter {
            filter,
            source: FilterSource::Env,
        });
    }
    EnvFilter::try_new(&logging.filter)
        .map(|filter| ResolvedFilter {
            filter,
            source: FilterSource::Config,
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
/// Per the convention, `NO_COLOR` counts only when set to a non-empty value —
/// which is [`super::style::no_color_set`]'s judgement, shared with the admin
/// CLI's own `--color` so the two answers cannot drift. Note the *precedence*
/// deliberately does not match: a `--color always` outranks `NO_COLOR` where
/// this key cannot, because a flag is typed and a configuration file is
/// ambient. [`super::style`]'s module doc has the argument.
fn ansi_enabled(configured: bool, no_color: Option<&str>) -> bool {
    configured && !super::style::no_color_set(no_color)
}

/// A layer stack built from `[logging]` but not yet installed.
///
/// The build/publish split is [`crate::Assembly::build_dispatchers`] and
/// `publish_notifiers`', for the same reason: a reload must be able to fail
/// *after* building this and still leave the running configuration untouched.
pub(crate) struct PreparedLogging {
    layer: Installed,
    /// Which of the three layers the filter came from, and so whether
    /// `logging.filter` had any say.
    pub(crate) filter_source: FilterSource,
}

/// Resolves `[logging]` into a layer stack, validating every key.
///
/// The one place a stack is built, so startup and a reload cannot drift — the
/// reasoning behind [`super::build_generation`], applied to one layer.
pub(crate) fn prepare_logging(
    logging: &crate::config::LoggingConfig,
    flag: Option<&str>,
) -> Result<PreparedLogging, String> {
    let ResolvedFilter { filter, source } = build_env_filter(logging, flag)?;
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
        filter_source: source,
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
pub fn init_logging(
    logging: &crate::config::LoggingConfig,
    level: Option<LogLevel>,
) -> Result<(), String> {
    let directive = level.map(LogLevel::directive);
    let prepared = prepare_logging(logging, directive.as_deref())?;
    let (layer, handle) = reload::Layer::new(prepared.layer);
    tracing_subscriber::registry().with(layer).init();
    // A second install would already have panicked in `init()` above, so the
    // only way this loses the race is a caller that never got that far.
    let _ = RELOAD.set(handle);
    // Stored only now: a directive that would not build must leave the cell
    // unset, or a refused startup would hand a reload a filter nothing ever
    // installed.
    if let Some(directive) = directive {
        let _ = FILTER_OVERRIDE.set(directive);
    }
    Ok(())
}

/// The stack a one-shot admin command logs through, when it logs at all.
///
/// **`stderr`, whatever `logging.target` says**, and `logging.filter` is not
/// consulted either: that section describes the *server's* log stream, while
/// this is a diagnostic an operator asked one command for. stdout is the answer
/// — the rows, or the `--json` document — and putting a record in it is what
/// this whole path exists to stop.
///
/// Human-readable rather than `logging.json_format`'s shape for the same
/// reason: the audience is the terminal the command was typed into. `NO_COLOR`
/// still vetoes the colour, through the shared [`ansi_enabled`].
fn command_logging_config() -> crate::config::LoggingConfig {
    crate::config::LoggingConfig {
        target: "stderr".to_string(),
        // The compiled default, deliberately, and not the operator's own
        // `logging.filter`. It is reached only when `--log-level` was not
        // given, i.e. when a non-empty `RUST_LOG` is what asked — and that
        // outranks it, so this is a fallback nothing normally reads.
        ..crate::config::LoggingConfig::default()
    }
}

/// Installs the diagnostic subscriber a one-shot admin command asked for.
///
/// `level` is `None` when a non-empty `RUST_LOG` is what asked, in which case
/// it supplies the filter through [`build_env_filter`]'s second layer — see
/// [`plan_logging`], which is what decides this function is called at all.
pub fn init_command_logging(level: Option<LogLevel>) -> Result<(), String> {
    init_logging(&command_logging_config(), level)
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
        let error = build_env_filter(&logging, None).unwrap_err();
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
        let resolved = build_env_filter(&logging, None).expect("a valid filter builds");
        assert_eq!(
            resolved.source,
            FilterSource::Config,
            "with RUST_LOG unset and no flag the filter comes from `logging.filter`",
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
        let resolved = build_env_filter(&logging, None).expect("RUST_LOG parses");
        assert_eq!(resolved.source, FilterSource::Env);

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
            let Err(error) = prepare_logging(&logging, None) else {
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

        let prepared = prepare_logging(&crate::config::LoggingConfig::default(), None)
            .expect("the defaults build");
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
        init_logging(&at_info, None).expect("the subscriber installs");
        assert_eq!(LevelFilter::current(), LevelFilter::INFO);
        assert!(!tracing::enabled!(target: "acme_proxy", tracing::Level::DEBUG));

        let at_debug = crate::config::LoggingConfig {
            filter: "acme_proxy=debug".to_string(),
            target: "stderr".to_string(),
            ..Default::default()
        };
        let prepared = prepare_logging(&at_debug, None).expect("the debug filter builds");
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

        init_logging(
            &crate::config::LoggingConfig {
                target: "stderr".to_string(),
                ansi: false,
                ..Default::default()
            },
            None,
        )
        .expect("the subscriber installs");

        let as_json = crate::config::LoggingConfig {
            json_format: true,
            flatten_event: true,
            target: "stderr".to_string(),
            span_events: "close".to_string(),
            ..Default::default()
        };
        let prepared = prepare_logging(&as_json, None).expect("the JSON stack builds");
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

            let error = init_logging(&logging, None).unwrap_err();
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
        assert!(init_logging(&logging, None).is_ok());
    }

    #[test]
    fn the_json_subscriber_installs() {
        let logging = crate::config::LoggingConfig {
            json_format: true,
            flatten_event: true,
            span_events: "full".to_string(),
            ..Default::default()
        };
        assert!(init_logging(&logging, None).is_ok());
    }

    /// One row of the `plan_logging` table: a command line, the flag, the
    /// environment, and what the three of them must decide.
    type PlanCase<'a> = (
        &'a [&'a str],
        Option<LogLevel>,
        Option<&'a str>,
        LoggingPlan,
    );

    /// Parsed rather than hand-built: naming every subcommand enum here would
    /// be a second copy of the clap tree, and what has to be right is what a
    /// real command line resolves to.
    fn command_of(argv: &[&str]) -> Option<super::super::Command> {
        use clap::Parser;
        super::super::Cli::try_parse_from(argv)
            .expect("the fixture command line parses")
            .command
    }

    /// The whole point of the flag, as a table: **an admin command is silent
    /// unless somebody asked**, `serve` never is, and `RUST_LOG` counts only
    /// when it holds something.
    #[test]
    fn plan_logging_decides_who_gets_a_subscriber() {
        let cases: Vec<PlanCase> = vec![
            // A daemon logs, however it was reached and whatever is unset.
            (&["acme-proxy"], None, None, LoggingPlan::Server),
            (&["acme-proxy", "serve"], None, None, LoggingPlan::Server),
            (
                &["acme-proxy", "serve"],
                Some(LogLevel::Debug),
                None,
                LoggingPlan::Server,
            ),
            // The reported bug: these used to write `db_migration_completed`
            // into the operator's `jq` pipe.
            (
                &["acme-proxy", "account", "list"],
                None,
                None,
                LoggingPlan::Silent,
            ),
            (
                &["acme-proxy", "filter", "show"],
                None,
                None,
                LoggingPlan::Silent,
            ),
            (
                &["acme-proxy", "audit", "list"],
                None,
                None,
                LoggingPlan::Silent,
            ),
            (
                &["acme-proxy", "admin", "user", "list"],
                None,
                None,
                LoggingPlan::Silent,
            ),
            // Both ways of asking, and only those two.
            (
                &["acme-proxy", "account", "list"],
                Some(LogLevel::Debug),
                None,
                LoggingPlan::Command,
            ),
            (
                &["acme-proxy", "account", "list"],
                Some(LogLevel::Off),
                None,
                LoggingPlan::Command,
            ),
            (
                &["acme-proxy", "account", "list"],
                None,
                Some("acme_proxy=debug"),
                LoggingPlan::Command,
            ),
            // A `${RUST_LOG:-}` shell default is present, not a request — the
            // judgement `no_color_set` already makes about the other ambient
            // variable this CLI reads.
            (
                &["acme-proxy", "account", "list"],
                None,
                Some(""),
                LoggingPlan::Silent,
            ),
            // Answered by `main.rs` before any of this, but total here anyway.
            (&["acme-proxy", "man"], None, None, LoggingPlan::Silent),
            (
                &["acme-proxy", "completions", "bash"],
                Some(LogLevel::Trace),
                Some("debug"),
                LoggingPlan::Silent,
            ),
        ];

        for (argv, level, rust_log, expected) in cases {
            let command = command_of(argv);
            let plan = plan_logging(command.as_ref(), level, rust_log);
            assert_eq!(
                plan,
                expected,
                "`{}` with level {level:?} and RUST_LOG {rust_log:?}",
                argv.join(" "),
            );
        }
    }

    /// A flag was typed on this command line where both other layers are
    /// ambient — `super::super::style`'s argument for `--color always`
    /// outranking `NO_COLOR`, applied to the filter.
    #[test]
    fn the_flag_outranks_rust_log_and_the_file() {
        let _guard = crate::config::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::set_var("RUST_LOG", "acme_proxy=warn") };

        let logging = crate::config::LoggingConfig {
            filter: "acme_proxy=error".to_string(),
            ..Default::default()
        };
        let resolved = build_env_filter(&logging, Some(&LogLevel::Trace.directive()))
            .expect("the flag's directive builds");
        assert_eq!(resolved.source, FilterSource::Flag);
        assert_eq!(
            resolved.filter.to_string(),
            "acme_proxy=trace",
            "neither RUST_LOG nor logging.filter may have a say once the flag is given",
        );

        unsafe { std::env::remove_var("RUST_LOG") };
    }

    /// Each level's directive is **scoped to this crate**, so `--log-level
    /// debug` does not also unleash `sqlx` and `hyper` on somebody debugging
    /// one command. `off` is the exception and has to be: a per-target
    /// directive at `off` leaves every other target at the default level, so
    /// the one value asking for silence would be the one not delivering it.
    #[test]
    fn every_level_renders_a_directive_scoped_to_this_crate() {
        assert_eq!(LogLevel::Off.directive(), "off");
        for (level, expected) in [
            (LogLevel::Error, "acme_proxy=error"),
            (LogLevel::Warn, "acme_proxy=warn"),
            (LogLevel::Info, "acme_proxy=info"),
            (LogLevel::Debug, "acme_proxy=debug"),
            (LogLevel::Trace, "acme_proxy=trace"),
        ] {
            assert_eq!(level.directive(), expected);
            EnvFilter::try_new(level.directive()).expect("every directive parses");
        }
        EnvFilter::try_new(LogLevel::Off.directive()).expect("`off` parses");
    }

    /// stdout is the answer an admin command was run for — the rows, or the
    /// `--json` document — so a record asked for with `--log-level` goes to
    /// stderr whatever `logging.target` says. That key describes the server's
    /// stream, and this path deliberately does not consult it.
    #[test]
    fn a_command_run_logs_to_stderr_whatever_logging_target_says() {
        assert_eq!(
            crate::config::LoggingConfig::default().target,
            "stdout",
            "the default this must not inherit",
        );
        let built = command_logging_config();
        assert_eq!(built.target, "stderr");
        assert!(!built.json_format, "the audience is a terminal");
    }

    /// The three `FilterSource`s, and the question the reload warning asks of
    /// them. `config` is the only one that does *not* make an edited
    /// `logging.filter` a no-op.
    #[test]
    fn only_the_two_outranking_sources_silence_an_edit() {
        assert!(FilterSource::Flag.outranks_config());
        assert!(FilterSource::Env.outranks_config());
        assert!(!FilterSource::Config.outranks_config());
        assert_eq!(FilterSource::Flag.as_str(), "flag");
        assert_eq!(FilterSource::Env.as_str(), "env");
        assert_eq!(FilterSource::Config.as_str(), "config");
    }

    /// The flag's own directives cannot fail to parse — they are renderings of
    /// a closed enum — but the arm is built to refuse rather than to trust,
    /// since a value that cannot be wrong is one nobody notices becoming able
    /// to. Driven with a hand-written directive, which is the only way in.
    #[test]
    fn an_unparseable_flag_directive_is_refused_by_name() {
        let error = build_env_filter(
            &crate::config::LoggingConfig::default(),
            Some("not=a=filter"),
        )
        .unwrap_err();
        assert!(error.contains("--log-level"), "{error}");
        assert!(error.contains("not=a=filter"), "{error}");
    }

    /// The whole admin-command path, installed: the flag's level in force and
    /// the records on stderr. Its own process, like the three installers above.
    #[test]
    fn a_command_subscriber_installs_at_the_flags_level() {
        let _guard = crate::config::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::remove_var("RUST_LOG") };

        init_command_logging(Some(LogLevel::Warn)).expect("the subscriber installs");
        assert_eq!(LevelFilter::current(), LevelFilter::WARN);
        assert!(!tracing::enabled!(target: "acme_proxy", tracing::Level::INFO));
        assert_eq!(flag_override(), Some("acme_proxy=warn"));
    }

    /// A `--log-level` typed at startup has to survive a `SIGHUP`: the stack is
    /// rebuilt from the *file*, so without the process-wide cell the reload
    /// would quietly demote the server to `logging.filter`. Its own process,
    /// like the three installers above — it installs a global subscriber and
    /// writes a `OnceLock`.
    #[test]
    fn the_flag_survives_a_reload() {
        let _guard = crate::config::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::remove_var("RUST_LOG") };

        assert!(flag_override().is_none(), "nothing is set before startup");

        let at_error = crate::config::LoggingConfig {
            filter: "acme_proxy=error".to_string(),
            target: "stderr".to_string(),
            ..Default::default()
        };
        init_logging(&at_error, Some(LogLevel::Debug)).expect("the subscriber installs");
        assert_eq!(LevelFilter::current(), LevelFilter::DEBUG);
        assert_eq!(flag_override(), Some("acme_proxy=debug"));

        // The reload's own call, verbatim: a new file with a different filter,
        // rebuilt through the flag the cell remembers.
        let edited = crate::config::LoggingConfig {
            filter: "acme_proxy=error".to_string(),
            target: "stderr".to_string(),
            span_events: "close".to_string(),
            ..Default::default()
        };
        let prepared = prepare_logging(&edited, flag_override()).expect("the stack rebuilds");
        assert_eq!(prepared.filter_source, FilterSource::Flag);
        assert!(publish_logging(prepared));
        assert_eq!(
            LevelFilter::current(),
            LevelFilter::DEBUG,
            "the reload must not demote the server to the file's filter",
        );
    }
}
