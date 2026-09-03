# iam-replay

Given an AWS principal and a *candidate* (usually tightened) IAM policy, `iam-replay`
replays that principal's historical CloudTrail activity against the candidate policy and
reports exactly which historical calls would now be denied.

The output is a reviewable list, not a recommendation. **The tool never applies a policy.**

![iam-replay replaying a role's CloudTrail history against a candidate policy: the policy in force produces no denies, the tightened candidate breaks two calls outright and leaves three it refuses to guess at](docs/media/demo.gif)

Recorded against the committed test fixture, so the run above reproduces from a clean clone:

```bash
iam-replay --principal arn:aws:iam::123456789012:role/iam-replay-fixture-workload \
           --policy tests/fixtures/cloudtrail/live/policy-candidate.json \
           --source files --path tests/fixtures/cloudtrail/live/workload_events.json \
           --days 3650
```

---

## Who this is for

**This tool is for principals whose work is control-plane:** CI/CD deploy roles, automation
and remediation roles, agent execution roles, break-glass roles.

Object-level and item-level operations — `s3:GetObject`, DynamoDB item operations,
`lambda:InvokeFunction` — are CloudTrail **data events**, which are off by default in most
trails. **For a role whose work is mostly data-plane, a clean result from this tool means
very little.**

This is not a theoretical caveat. The test fixture in `terraform/` calls `ListObjectsV2`
successfully on every run, and that call **never appears in the trail** — while every other
bucket-level S3 call it makes does. A replay of that workload will tell you nothing at all
about whether your candidate policy breaks object listing.

## Why it exists

GCP ships this as a first-party product. Policy Simulator's
[Replay](https://docs.cloud.google.com/policy-intelligence/docs/iam-simulator-overview)
re-evaluates the last 90 days of access attempts under a proposed policy and reports the
differences; there is even a
[`gcloud iam simulator replay-recent-access`](https://docs.cloud.google.com/sdk/gcloud/reference/iam/simulator/replay-recent-access)
command. AWS has no equivalent.

AWS's adjacent-but-different pieces:

| Thing | What it does | Why it isn't this |
|---|---|---|
| [Access Analyzer policy generation](https://aws.amazon.com/blogs/security/iam-access-analyzer-makes-it-easier-to-implement-least-privilege-permissions-by-generating-iam-policies-based-on-access-activity/) | Generates a policy *from* CloudTrail | Inverse direction; does not validate a policy you wrote |
| `CheckNoNewAccess` | Static comparison of two policies | No traffic involved |
| Unused access analyzer | Finds unused permissions | Service and action granularity, not resource or condition |
| `SimulateCustomPolicy` | Evaluates one request | One at a time, no log integration |
| [`AWSSupport-TroubleshootIAMAccessDeniedEvents`](https://docs.aws.amazon.com/systems-manager-automation-runbooks/latest/userguide/awssupport-troubleshootiamaccessdeniedevents.html) | Explains `AccessDenied` events found in CloudTrail | Explains denials that already happened; does not predict new ones |

Open source: [CloudTracker](https://github.com/duo-labs/cloudtracker) compares CloudTrail
against *current* policies at action level.
[access-undenied-aws](https://pypi.org/project/aws-access-undenied) explains existing
denials. [iamlive](https://github.com/iann0036/iamlive) and
[trailscraper](https://github.com/flosell/trailscraper) generate policies from observed
traffic.

As of September 2026, no open-source AWS tool takes a candidate policy and produces a
per-call allow/deny diff against historical CloudTrail at resource and condition
granularity. If you know of one, please open an issue — the comparison above is the honest
version of the claim, and it should be corrected if it is wrong.

**One difference from GCP's Replay worth naming.** GCP replays each access attempt twice,
under the current policy and the proposed one, and diffs the two. `iam-replay` replays only
against the candidate, and uses *what actually happened* as the current-policy baseline: a
call that succeeded was, by definition, allowed. That is cheaper and needs no access to the
current policy, but it means the baseline is only as complete as the log.

## Three-state output

Every replayed call resolves to one of three states.

| State | Meaning |
|---|---|
| `WOULD ALLOW` | The candidate policy permits this call. |
| `WOULD DENY` | The candidate policy denies it — explicitly, or by not allowing it. |
| `INDETERMINATE` | The candidate policy's answer depends on something CloudTrail did not record. |

`INDETERMINATE` is the point of the project. A wrong `ALLOW` breaks production; a wrong
`DENY` destroys trust in the report. Both are worse than a hundred honest
`INDETERMINATE`s.

The rule that produces it: **an unevaluable condition never resolves to `ALLOW`.** If a
matching statement depends on `aws:ResourceTag/Project` and the event does not carry it,
the tool says so and names the key, rather than assuming the tag was probably right.

This is stricter than real IAM in three specific places, and deliberately so. In AWS,
`Null` on an absent key, any `...IfExists` operator, and `ForAllValues:` over an absent key
all evaluate to *true*. Here they are unevaluable, because "absent from the log" and
"absent from the request" are different claims and only the second one would justify those
answers.

That strictness costs less than it sounds like, because it only bites when the key is
genuinely missing. What actually floods the output with unknowns is something else — see
[If your policy is tag-scoped](#if-your-policy-is-tag-scoped).

### If your policy is tag-scoped

**A policy conditioned on `aws:ResourceTag` returns 100% `INDETERMINATE`. Every call, no
exceptions.** Measured on the fixture workload:

| Policy shape | ALLOW | DENY | INDETERMINATE |
|---|---:|---:|---:|
| No conditions | 52 | 0 | 0 |
| **Tag-scoped (`aws:ResourceTag`)** | **0** | **0** | **52** |
| Tag-scoped with `IfExists` | 0 | 0 | 52 |
| `Deny` unless MFA (`BoolIfExists`) | 0 | 52 | 0 |
| `Deny` unless TLS (`Bool`) | 52 | 0 | 0 |
| Region-scoped (`aws:RequestedRegion`) | 52 | 0 | 0 |

ABAC policies are idiomatic and common, so this is worth stating plainly: **on a tag-scoped
policy this tool can tell you nothing at all.** CloudTrail records no tag on any event, so
every call reaching such a statement is unknowable. Reaching for `IfExists` is the natural
response and does not help — the key is missing from the log, not from the request.

Note what the table also shows. The `IfExists` and `Bool` guards in rows four and five
resolve *confidently*, because CloudTrail does record `mfaAuthenticated` and `tlsDetails`.
The strict semantics are not what causes the wall; tag unavailability is the whole of the
effect. `tests/test_policy_shapes.py` pins these numbers.

If your policy is tag-scoped, this tool is the wrong instrument, and it will say so rather
than pretend otherwise.

## Install

```bash
pip install iam-replay
```

## Use

```bash
# Zero setup. Uses CloudTrail Event history: no trail required, 90 days, management events.
iam-replay --principal arn:aws:iam::123456789012:role/DeployRole \
           --policy candidate.json

# Longer windows: sync the trail bucket and read it directly.
aws s3 sync s3://my-trail-bucket/AWSLogs/ ./trail-data/
iam-replay --principal arn:aws:iam::123456789012:role/DeployRole \
           --policy candidate.json \
           --source files --path ./trail-data --days 365

# In CI. Gate on both: see below for why --fail-on-deny alone is not enough.
iam-replay --principal ... --policy candidate.json \
           --fail-on-deny --fail-on-indeterminate
```

`--principal` accepts either a role ARN or an assumed-role session ARN and normalizes to
the role. Add `--boundary` to intersect with a permission boundary and `--format json` for
the audit artifact.

Exit codes: **0** ran cleanly, **1** a gate tripped, **2** the tool failed and nothing it
printed should be believed.

### The CI gate is both flags, not just `--fail-on-deny`

**`--fail-on-deny` on its own under-reports.** For `s3`, `kms`, `lambda` and `sts` — the
services whose resources can carry a policy that grants access independently of the identity
policy — an unmatched action resolves to `INDETERMINATE`, not `DENY`. Those calls sail past
the deny gate. A tightened policy that breaks an `sts:AssumeRole` or a `kms:Decrypt` can
therefore produce a green build.

Gate on both, and treat an unknown as a thing to resolve rather than a thing to ignore:

```bash
iam-replay --principal ... --policy candidate.json \
           --fail-on-deny --fail-on-indeterminate
```

## Limitations

Read this section. A user who reads only this README should come away knowing what the tool
cannot tell them.

1. **Data events are usually absent.** Object- and item-level calls are off by default in
   most trails, so they are not evaluated. A clean result for a data-plane role is close to
   meaningless. See "Who this is for".
2. **Only identity-based policies are evaluated**, but the tool no longer pretends
   otherwise. Service control policies and session policies are not evaluated at all.
   Resource-based policies are not evaluated either — instead, when no `Allow` matches and
   the target service is one whose resources can carry their own policy (`s3`, `kms`,
   `lambda`, `sts`, and `secretsmanager`/`sqs`/`sns` once those are in scope), the result is
   `INDETERMINATE` with reason `resource_policy_unevaluable` rather than a confident
   `WOULD DENY`. AWS's own evaluation logic makes this necessary: within one account it does
   not matter whether the `Allow` comes from the identity policy or the resource policy, and
   their worked example has a principal with *no* identity policy who still has full access.
   The fixture hit it immediately — Lambda decrypts environment variables under the execution
   role's credentials against a key granted by the key policy alone.

   Explicit denies and permission boundaries are unaffected: an explicit `Deny` in the
   identity policy wins regardless of service, and a boundary that omits an action denies it,
   because no resource policy overrides either.

   **`sts` is in that set because a role trust policy is a resource-based policy.** AWS
   documents that when a resource-based policy grants access to a principal in the same
   account, no additional identity-based policy is required; for one role to assume another
   within an account, the trust policy's grant is both necessary and sufficient, and the
   assuming role's identity policy is *not* sufficient on its own. An implicit deny on
   `sts:AssumeRole` therefore says nothing about whether the call would succeed, and is
   reported as `INDETERMINATE`.
3. **Six services.** `s3`, `iam`, `sts`, `ec2`, `lambda`, `kms`. Anything else resolves to
   `INDETERMINATE` with reason `unsupported_service` — a correct answer, not a failure.
4. **Tag-based conditions can never be evaluated.** `aws:ResourceTag/*`,
   `aws:PrincipalTag/*`, `aws:RequestTag/*` and `aws:TagKeys` are absent from every
   CloudTrail event. A tag-scoped policy comes back **100% `INDETERMINATE`** — measured, not
   estimated. See [If your policy is tag-scoped](#if-your-policy-is-tag-scoped).
5. **`iam:PassRole` is inferred, never observed.** It is not logged as its own event. Where
   a mapping asserts it (`lambda:CreateFunction`, `ec2:RunInstances` with an instance
   profile), the entry is marked `INFERRED`. No general PassRole detection is attempted.
6. **Already-denied calls are excluded from the regression set,** and that set is itself
   incomplete: CloudTrail does not log every denied request — denied cross-account
   `sts:AssumeRole` in the target account is one documented case — so the absence of denials
   proves nothing.
7. **The window is only as long as your logs.** `--source lookup` is capped at 90 days by
   the API and errors rather than silently clamping. The analyzed window is printed on every
   report, always, so a 90-day request served by 12 days of data cannot pass unnoticed.
8. **Unmapped events are skipped, not denied.** An event in a supported service with no
   mapping is reported in the header counts and evaluated no further.
9. **Most mappings are unvalidated against real traffic.** The ground-truth oracle exercises
   14 of 158 declared event mappings; the rest rest on hand-written fixtures. No `sts`
   mapping and no write path has been checked against a real call. See
   [What that number does not cover](#what-that-number-does-not-cover).

## How it is validated

The evaluation engine implements logic AWS documents publicly. The **mapper** —
`eventName` → IAM action → resource ARN → condition context — is the novel, high-risk part,
and hand-written fixtures checked against hand-written expectations would only prove the
mapper matches its author's beliefs.

So the primary validation is a ground-truth oracle. Every successful CloudTrail event was,
by definition, authorized under the policy in force at the time. `terraform/` deploys a
control-plane workload whose execution role carries a **deliberately tight** policy, and
`tests/test_ground_truth.py` replays that workload's successful calls against that same
policy:

> **0 false denies across 32 distinct authorization shapes** (173 calls, all six services,
> reads and writes) replayed against the live in-force policy. 31 resolve to `ALLOW`; one is
> honestly `INDETERMINATE` — a failed `kms:DeleteAlias` that CloudTrail recorded with no
> request parameters at all, so there is nothing to build a resource ARN from.

### What that number does not cover

Three things, and they matter more than the number does.

**It covers 15% of the mapping surface.** The fixture workload makes 27 calls, so the oracle
exercises 25 of the 164 event mappings this repo declares. The rest are backed only by
hand-written fixtures — the weaker instrument this section opens by warning about.

| Service | Oracle-validated | Declared |
|---|---:|---:|
| `ec2` | 5 | 35 |
| `iam` | 5 | 30 |
| `kms` | 4 | 24 |
| `lambda` | 4 | 32 |
| `s3` | 5 | 34 |
| `sts` | 2 | 9 |
| **Total** | **25** | **164** |


`sts:AssumeRole` now has real coverage: the workload assumes a second fixture role on every
run, and that role deliberately lives under a path, so `sessionIssuer` attribution is
exercised on traffic AWS produced rather than only on hand-built fixtures. Write paths are
covered too — the workload creates and deletes a security group, an inline role policy, a KMS
alias, bucket tags and function tags, returning the account to its starting state each run.

What remains asserted rather than tested: `ec2:RunInstances` and its multi-permission
expansion, which would need a real instance launch, and the great majority of every mapping
file. **139 of 164 mappings have still never met AWS.**

`pytest tests/test_ground_truth.py -s` prints this table from the code, so it cannot drift
from what is actually covered.

**And every run says which side of that line it landed on.** The header carries a mapping
provenance line next to the analyzed window:

```
Window analyzed:    1 days (2026-09-02 → 2026-09-03)
Mapping provenance: 10 of 42 mappings used are oracle-backed  (32 asserted, never tested against AWS)
```

The `--format json` output names the asserted mappings individually. A caveat someone might
not read becomes a number they cannot avoid — the same reason the analyzed window is printed
unconditionally.

**A negative control covers the false-*allow* direction.** The positive oracle alone cannot:
a mapping that lands on the wrong action still gets allowed whenever the baseline happens to
grant that action too. So `tests/test_negative_control.py` replays the same traffic against
a policy that allows everything *except* one permission — using the baseline's own literal
strings, not the mapper's output — and requires every hand-written permission to deny at
least one real request. If `GetRole` were mapped to `iam:ListRoles`, the positive oracle
returns ALLOW and says nothing; the `iam:GetRole` control pins nothing and fails. Two
deliberately sabotaged mappings, a wrong action and a widened resource, are in the suite to
prove the instrument itself works. Same captured traffic, no extra AWS spend.

What still escapes both: a missing context key the in-force policy does not reference.

**It is only as strong as the baseline is tight.**
`test_the_baseline_is_tight_enough_to_have_teeth` rejects any `service:*` on `*` statement in
the baseline, because replayed against `s3:*` on `*` everything allows and the test proves
nothing.

An unmapped event is *skipped*, not denied, so it passes the oracle by not being evaluated.
`test_no_allowlisted_service_event_is_left_unmapped` closes that hole separately. It is how
we found that CloudTrail records Lambda calls under API-versioned names like
`GetFunction20150331v2` — a mapping written for `GetFunction` would have looked clean while
covering nothing.

## Development

```bash
uv venv && uv pip install -e ".[dev]"
pytest
```

The suite runs offline against committed fixtures, including a scrubbed snapshot of real
events from the fixture account. To rebuild the fixture and re-derive the number above, see
[`terraform/README.md`](terraform/README.md) and
[`terraform/policies/README.md`](terraform/policies/README.md).

## License

Apache-2.0
