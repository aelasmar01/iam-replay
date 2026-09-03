# iam-replay

Given an AWS principal and a *candidate* (usually tightened) IAM policy, `iam-replay`
replays that principal's historical CloudTrail activity against the candidate policy and
reports exactly which historical calls would now be denied.

The output is a reviewable list, not a recommendation. **The tool never applies a policy.**

```
WOULD DENY  (3)
Action                        Resource                                    Calls  Seen        Why
iam:GetRole                   arn:aws:iam::…:role/deploy-role                 9  2026-09-03  implicit deny
iam:ListAttachedRolePolicies  arn:aws:iam::…:role/deploy-role                 9  2026-09-03  implicit deny
s3:GetBucketVersioning        arn:aws:s3:::acme-artifacts-prod                9  2026-09-03  implicit deny

INDETERMINATE  (1)
  never_available_condition_key
    s3:GetBucketLocation on arn:aws:s3:::acme-artifacts-prod ×9
      — unevaluable: aws:ResourceTag/Project
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

# In CI.
iam-replay --principal ... --policy candidate.json --fail-on-deny
```

`--principal` accepts either a role ARN or an assumed-role session ARN and normalizes to
the role. Add `--boundary` to intersect with a permission boundary, `--format json` for the
audit artifact, and `--fail-on-indeterminate` to gate on unknowns as well as denials.

Exit codes: **0** ran cleanly, **1** a gate tripped, **2** the tool failed and nothing it
printed should be believed.

## Limitations

Read this section. A user who reads only this README should come away knowing what the tool
cannot tell them.

1. **Data events are usually absent.** Object- and item-level calls are off by default in
   most trails, so they are not evaluated. A clean result for a data-plane role is close to
   meaningless. See "Who this is for".
2. **Only identity-based policies are evaluated.** Service control policies, session
   policies, and resource-based policies (S3 bucket policies, KMS key policies) are not. A
   call authorized *solely* by a resource-based policy appears here as a deny that would not
   actually occur. This is not hypothetical: the fixture hit it immediately, because Lambda
   decrypts environment variables under the execution role's credentials against a key it is
   granted by the key policy alone.
3. **Six services.** `s3`, `iam`, `sts`, `ec2`, `lambda`, `kms`. Anything else resolves to
   `INDETERMINATE` with reason `unsupported_service` — a correct answer, not a failure.
4. **Tag-based conditions can never be evaluated.** `aws:ResourceTag/*`,
   `aws:PrincipalTag/*`, `aws:RequestTag/*` and `aws:TagKeys` are absent from every
   CloudTrail event. Policies depending on them yield `INDETERMINATE`, always.
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

> **0 false denies across 13 distinct authorization shapes** (52 calls, 5 services)
> replayed against the live in-force policy.

**What that number does not cover.** The oracle proves the absence of false *denies*, not
the absence of false *allows*. A mapping that is too broad still resolves to `ALLOW` and
passes silently, as does a missing context key the in-force policy does not reference. It is
also only as strong as the baseline is tight — `test_the_baseline_is_tight_enough_to_have_teeth`
rejects any `service:*` on `*` statement in it, because replayed against `s3:*` on `*`
everything allows and the test proves nothing.

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
