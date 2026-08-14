# Policy: rules and conditions

A rule is a boolean expression over [check](checks.md) names plus what a match
means. `filter.rules` lists the rules to evaluate, in order, and **the first
match decides**.

```toml
[filter]
rules   = ["mgmt-bypass", "inventory-owned"]
default = "deny"

[filter.rule.mgmt-bypass]
when = "mgmt-net"
then = "allow"

[filter.rule.inventory-owned]
when    = "corp-names and (inventory or mgmt-net)"
then    = "allow"
message = "this address owns no such name in the inventory"
mode    = "enforce"
```

## The condition language

```text
expr   := term ( "or" term )*
term   := factor ( "and" factor )*
factor := "not" factor | "(" expr ")" | name
name   := [a-z0-9-]+
```

`not` binds tightest, then `and`, then `or`; `and` and `or` are
left-associative, so `a or b and c` means `a or (b and c)`. The three keywords
are matched case-insensitively and cannot be used as check names. A parse error
names the column it gave up at:

```text
filter.rule.r.when: expected a check name, `not` or `(` at column 9 in "net and )"
```

`acme-proxy filter show` re-prints every condition with the grouping made
explicit, which is the quickest way to confirm the parser read what you meant.

## Where a rule runs

A rule is evaluated at the **intersection** of the stages its checks can decide
at — never the union. Evaluating a rule at a stage where one of its checks
cannot run would silently treat that check as passing and change the boolean
answer, so the intersection is the only composition that cannot lie.

The consequence worth knowing: a rule combining a connection-only check with an
identifiers-only one has no stage at all. That is a **startup error** naming
both sides, not a rule that quietly never fires.

```text
filter.rule.strict combines `has-ptr` (connection only) and `corp-names`
(identifiers only), so there is no point in a request where both can be
evaluated. Give `has-ptr` stages = ["identifiers"] if it can decide there, or
split the rule in two.
```

Both stages must allow, and each evaluates its own applicable subset
independently. A stage no rule applies to allows without consulting
`filter.default`.

## When a check cannot decide

A check has three possible answers, not two: it passed, it failed, or it could
not decide. The third covers a DNS timeout, an unreachable inventory, a script
that would not spawn — cases where the server learned nothing, which is not the
same as learning "no".

Conditions combine them with three-valued logic, where an unknown propagates
only if it could change the answer:

| | `and` | `or` |
| --- | --- | --- |
| pass, pass | pass | pass |
| pass, fail | fail | pass |
| fail, fail | fail | fail |
| fail, unknown | **fail** | unknown |
| pass, unknown | unknown | **pass** |
| unknown, unknown | unknown | unknown |

The two bold rows are the point. `mgmt-net or inventory` keeps working through
an inventory outage, because a disjunction whose other side already passed does
not care what the unknown would have been. `inventory` on its own still becomes
a retryable `500` — the `or` buys resilience for the addresses it names and
nothing more.

The same principle applies at the rule level. A rule whose condition came back
unknown is not skipped: it is remembered, and once the policy reaches an answer
it is asked whether that would have mattered. If the unknown rule's effect
differs from the effect actually reached, the whole stage is a `500`. If it
agrees, the answer stands. This is what stops rule *order* from deciding
whether an outage is survivable.

## Warn mode

`mode = "warn"` makes a matching rule log `filter_rule_warned` and **not**
decide — evaluation continues to the next rule. It is how a tightened policy is
rolled out: deploy it in warn mode, watch for the event, and switch to
`enforce` once no legitimate client trips it.

```toml
[filter.rule.inventory-owned]
mode = "warn"
```

A policy of nothing but warn rules therefore falls through to `filter.default`.

Because rules are a map rather than an array of tables, a profile can dry-run
one rule and inherit the rest:

```toml
[profiles.staging.filter.rule.inventory-owned]
mode = "warn"
```

## What the client is told

In order: the matching rule's `message` if it has one; otherwise the first check
that actually refused, in evaluation order; otherwise a generic sentence. A
`message` is the way to say "ask the network team" instead of exposing which
check bit.

A check that could not decide never reaches the client — the response is a
plain `500`, and the specifics stay in the logs.

### Reference

**`filter.rule.<name>.when`** (`String`) — *Required | Env: `ACME_PROXY_FILTER__RULE__<NAME>__WHEN`*

The condition, in the language above. Empty is a startup error: a rule with no
condition is what `filter.default` is for.

**`filter.rule.<name>.then`** (`String`) — *Required | Env: `ACME_PROXY_FILTER__RULE__<NAME>__THEN`*

`"allow"` or `"deny"`. No default — a rule that does not say what a match means
is one whose author has not finished writing it.

**`filter.rule.<name>.message`** (`String`) — *Default: `""` | Env: `ACME_PROXY_FILTER__RULE__<NAME>__MESSAGE`*

Shown to the client verbatim in place of whichever check failed.

**`filter.rule.<name>.mode`** (`String`) — *Default: `"enforce"` | Env: `ACME_PROXY_FILTER__RULE__<NAME>__MODE`*

`"enforce"` or `"warn"`. A warn rule matches, logs and does not decide.

## Startup refusals

Every one of these stops the server rather than producing a policy that does
not mean what it says.

| Configuration | Refusal |
| --- | --- |
| `filter.rules` names a rule with no `[filter.rule.<name>]` | names the missing entry |
| `when` names a check with no `[filter.check.<name>]` | names the missing check |
| A rule is defined but `filter.rules` is empty | says to list the rules to evaluate |
| `when` will not parse | names the column, and quotes the expression |
| `then` missing, or not `allow`/`deny` | names the value |
| `mode` not `enforce`/`warn` | names the value |
| `filter.default` not `allow`/`deny` | names the value |
| A rule's checks share no stage | names both sides and suggests `stages` |
| A check is named `and`, `or` or `not` | says they are the language's own words |
