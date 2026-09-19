# ADR 0010: Errors derive `thiserror`, carry their whole message, and panic only at startup

## Status

Accepted. This was re-argued more than once before it was written down, which
is why it is written down.

## Context

The workspace has a couple of dozen error types, and each needs a `Display`.
Written by hand, that is roughly 250 lines of `match` and `write!` in which each
message sits several screens from the variant it describes. That distance is
what let messages drift from their variants, more than once.

`anyhow` carries startup errors up to the CLI, where
`CliError::failed(error.to_string())` prints them. `to_string()` renders only an
`anyhow::Error`'s outermost message. An error wrapped with `.context()` would
therefore print its context and silently lose the underlying cause.

The ACME error type, `Problem` (RFC 8555 §6.7), is the `Err` of nearly every
request-path function. clippy's `result_large_err` lint flags a large `Err` in
every one of them.

## Decision

- **Every error type derives `thiserror::Error`.** No hand-written `Display` or
  `std::error::Error` impl remains, and a new one should not add any. Three
  shapes need care:
  - A field literally named `source` is taken as the `#[source]` and must
    implement `Error`. `ScriptError::Spawn`'s is a formatted `String`, so it is
    named `detail` instead.
  - A variant whose wording depends on an inner enum needs a function, not a
    format string. For example, `RevokeError::Signer` goes through
    `signer_detail`.
  - A variant that renders through a method of its own takes an expression:
    `#[error("{}", self.reason())]`.
- **`anyhow` without `.context()`.** Every `anyhow` error is built with
  `anyhow!("… {error}")`, so its message already contains its cause. That is
  what keeps `CliError::failed(error.to_string())` lossless.
- **`Problem` stays small.** Every constructor goes through a private
  `Problem::build`. The optional members (`identifier`, `subproblems`, and
  type-specific extras such as `badSignatureAlgorithm`'s `algorithms`) live
  behind an `Option<Box<_>>`. `identifier` renders only inside `subproblems`,
  because RFC 8555 §6.7.1 forbids it at the top level, and the serializer
  enforces that rather than trusting callers.
- **Error handling splits by phase.** A startup path (database connect,
  migrations, reading the configuration) may `panic!` or `unwrap` to fail fast.
  A request path returns `Result` and degrades:
  - a database error becomes a `500` `Problem`;
  - a nonce that fails to save means the response goes out without
    `Replay-Nonce`, and the failure is logged.

## Consequences

- A variant and its message sit on adjacent lines.
- Error types add one proc-macro crate to the audited graph. `syn`, `quote` and
  `proc-macro2` were already there, via `serde_derive` and `async-trait`.
- A startup error prints its whole chain on one line. Adding a `.context()`
  anywhere would silently start truncating that line.
- A handler that needs a dynamic status or header returns
  `Result<Response, Problem>` and builds the response itself. That is how
  `keyChange`'s `409` gets its `Location` header.

## Enforced by

- clippy's `result_large_err`, run with `-D warnings` in CI.
- `Problem::to_value`, for where `identifier` may appear.
- Otherwise review only: nothing mechanically forbids `.context()` or a
  hand-written `Display`.
