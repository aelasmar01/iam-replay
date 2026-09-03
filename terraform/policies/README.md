# Fixture policies

Three templates, rendered by Terraform into `../rendered/` with the account ID,
bucket names and key ARN filled in. IAM's policy grammar accepts only `Version`,
`Id` and `Statement`, so the explanations that belong next to these statements
live here instead of as comments inside them.

## `policy-tight-baseline.json` — the oracle baseline

**This is the policy actually attached to the workload role**, and the one every
`SUCCEEDED` event is replayed against by `test_ground_truth.py`.

It must be exactly sufficient for the workload and no wider. The oracle's power
is proportional to how tight it is: replayed against `s3:*` on `*`, every event
allows and the test proves nothing. Every wildcard added here is a mapper bug
the oracle can no longer catch.

**If the oracle reports a DENY, fix the mapping — never widen this file.**
Widening it to make the test pass is how the instrument silently loses its teeth.

Two statements use `"Resource": "*"` legitimately, because the actions have no
resource-level permissions at all: `ec2:Describe*`, `iam:ListRoles`,
`lambda:ListFunctions`, `kms:ListAliases` and `s3:ListAllMyBuckets` are
account-wide by AWS's own definition. That is a documented scope, not a widening.

The `WriteOwnLogs` statement is outside the oracle entirely: `logs` is not in the
v1 service allowlist, so those events resolve to `unsupported_service`. It is
present only because the function cannot run without it.

## `policy-candidate.json` — the policy under review

The tightened policy the README demo replays. It differs from the baseline in
exactly three places, chosen so the demo exercises all three output states:

| # | Change | Expected result |
|---|---|---|
| 1 | `s3:GetBucketVersioning` dropped from `ReadTheFixtureBucket` | **INDETERMINATE** (`resource_policy_unevaluable`) — no `Allow` matches, but an S3 bucket policy could grant it independently of the identity policy, so the tool will not call it a deny |
| 2 | `ReadOwnRole` scoped to `role/some-other-role` | **WOULD DENY** — `iam:GetRole` and `iam:ListAttachedRolePolicies` no longer match, and `iam` resources carry no resource-based policy, so the deny is confident |
| 3 | `aws:ResourceTag/Project` condition added to `ReadTheFixtureBucket` | **INDETERMINATE** (`never_available_condition_key`) — CloudTrail never carries resource tags, so `s3:GetBucketLocation` cannot be resolved either way |

Change 1 used to produce a `WOULD DENY`. It became indeterminate when `s3` was recognised as
resource-policy-capable, and the shift is the point rather than a regression: the tool stopped
claiming certainty it did not have.

The candidate is generated from the baseline with exactly these three edits applied, so the two
cannot drift apart as the workload grows. Everything else in the two files is identical.

Change 3 is the one worth dwelling on. The condition is almost certainly
satisfied in reality. A tool willing to assume that would report a clean result;
this one reports that it cannot tell, and names the key.

## `policy-overbroad.json` — the "before" state

The realistic starting point for a role like this: five services at `*` on `*`.

**Never attached.** It exists to show what these roles usually look like before
anyone tightens them. If this were the policy in force, the ground-truth oracle
would replay against `s3:*` on `*` and prove nothing at all.
