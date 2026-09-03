# iam-replay

> **Status: in development.** Milestone 0 of 6. Not yet usable. See
> [`docs/implementation-plan.md`](docs/implementation-plan.md) for the full specification.

Given an AWS principal and a *candidate* (usually tightened) IAM policy, `iam-replay`
replays that principal's historical CloudTrail activity against the candidate policy and
reports exactly which historical calls would now be denied.

The output is a reviewable list, not a recommendation. **The tool never applies a policy.**

## Who this is for

This tool is for principals whose work is **control-plane**: CI/CD deploy roles, automation
and remediation roles, agent execution roles, break-glass roles.

Object-level and item-level operations — `s3:GetObject`, DynamoDB item operations,
`lambda:InvokeFunction` — are CloudTrail **data events**, which are off by default in most
trails. **For a role whose work is mostly data-plane, a clean result from this tool means
very little.**

## Why it exists

GCP ships this as a first-party product: Policy Simulator's
[Replay](https://cloud.google.com/policy-intelligence/docs/simulate-iam-policies)
re-evaluates past access attempts under a proposed policy and diffs the result. AWS has no
equivalent.

AWS's adjacent-but-different pieces: Access Analyzer policy generation works in the inverse
direction (generates a policy *from* CloudTrail); `CheckNoNewAccess` is a static comparison
of two policies with no traffic involved; the unused-access analyzer works at service and
action granularity, not resource or condition; `SimulateCustomPolicy` handles one request at
a time with no log integration.

## Three-state output

Every replayed call resolves to `WOULD ALLOW`, `WOULD DENY`, or `INDETERMINATE`.

`INDETERMINATE` exists because a wrong `ALLOW` breaks production and a wrong `DENY` destroys
trust in the report. Both are worse than a hundred honest `INDETERMINATE`s. When a matching
policy statement depends on a condition key that CloudTrail did not record, the tool says so
rather than guessing.

## License

Apache-2.0
