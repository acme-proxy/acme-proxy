## What this changes

<!-- And why. If it fixes an issue, "Fixes #123" here. -->

## Checklist

- [ ] `cargo fmt --all --check`
- [ ] `cargo clippy --all-targets -- -D warnings`
- [ ] `cargo nextest run` — **not** `cargo test`, which fails intermittently
      with `ETXTBSY` on the tests that exec a script they just wrote
- [ ] Tests cover the new behaviour, including the refusal paths
- [ ] Documentation updated (`doc/`, `config.toml.example`, `CHANGELOG.md`)
- [ ] `python3 doc/lint.py` passes, if `doc/` changed

## Things a reviewer will look for

- **A new configuration key** appears in `config.toml.example`, in the book, and
  — if it is array-valued — carries `deserialize_with = "string_list"`, or it
  cannot be set from the environment.
- **A schema change is a new migration file.** `crates/store/migrations/` is append-only;
  editing a committed file breaks every existing deployment at startup.
- **A new mutating web-admin route** is added to `mutating_endpoints()` or
  `mutating_page_endpoints()`, which is what proves its CSRF gate exists.
- **A new `event = "..."` name** is not a rename of one the e2e suite asserts on.
