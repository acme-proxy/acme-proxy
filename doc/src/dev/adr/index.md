# Architecture Decision Records

An architecture decision record (ADR) holds the *why* behind a design: the
problem it answers, the choice made, and what that choice rules out. The rest of
the documentation says what the server does. The module docs (`//!`) say what
each piece of code guarantees. The ADRs are where the argument lives, so that
the argument is not restated wherever the decision is mentioned.

Read the relevant ADR before changing something it covers. If a change reverses
a decision, write a new ADR that supersedes the old one and change the old one's
status. Do not rewrite its argument after the fact.

| ADR | Decision | Status |
|---|---|---|

## Writing an ADR

Name the file `NNNN-kebab-title.md`, taking the next free number, and list it
both in the table above and in `SUMMARY.md` under this page. `doc/lint.py`
refuses an ADR that is missing from either list, or that lacks one of the five
sections below.

The title is `# ADR NNNN: <decision>`, and the sections come in this order:

- **`## Status`**: `Accepted`, or `Superseded by ADR NNNN`. Name a
  proposal to replace it if one is on record.
- **`## Context`**: the problem, and the history that makes the rule
  necessary. History with no rule behind it does not belong here — git and
  `CHANGELOG.md` already keep it.
- **`## Decision`**: what was chosen, stated as rules.
- **`## Consequences`**: what the decision costs and what it rules out.
- **`## Enforced by`**: the tests, startup refusals and type-level constructs
  that hold the decision in place, named so that a grep finds them. Write
  "Review only" when nothing does.

Link to the page that owns a configuration key rather than restating its
default, since the book documents each key in exactly one file.
