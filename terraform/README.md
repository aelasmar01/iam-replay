# The ground-truth fixture

This is an instrument, not a demo.

Its purpose is to produce real CloudTrail events from a workload whose permissions are known
exactly, so that replaying those events against the policy that actually authorized them
must yield `ALLOW` for every one. **Any `DENY` is a mapper bug.**

## What it deploys

| Resource | Why |
|---|---|
| IAM role `iam-replay-fixture-workload` | The principal under test. Carries `policy-tight-baseline.json` as an inline policy — see below. |
| IAM role `iam-replay-fixture-scratch` | A throwaway role that exists only to have an inline policy written to it and deleted again. Never assumed, grants nothing. |
| IAM role `iam-replay-fixture-roles/iam-replay-fixture-target` | Assumed by the workload, so `sts:AssumeRole` runs against a real target. **Under a path deliberately** — resolving its session ARN is only possible through `sessionIssuer`, so real traffic exercises the case that string-parsing gets wrong. |
| Lambda `iam-replay-fixture-workload` | Makes a fixed, deterministic set of 27 control-plane calls across all six allowlisted services, including create-then-delete write pairs. |
| EventBridge rule, `rate(5 minutes)` | Keeps producing events so the window stays populated. |
| S3 data bucket | Gives the workload a real bucket to make bucket-level calls against. |
| KMS key + alias | Gives the workload a resource-scoped `kms:DescribeKey` call. |
| S3 trail bucket + CloudTrail trail | Management events, multi-region. Needed for the `files` source. |

**Cost: roughly $1–2/month**, almost entirely the KMS key ($1/mo). Lambda and EventBridge
stay inside the free tier; S3 and the trail are cents.

The write paths added no measurable cost. Security groups, IAM role policies, KMS aliases,
bucket tags and function tags are all free to create and delete; `sts:AssumeRole` is free;
and the extra CloudTrail management events cost nothing on a first trail. The only
increments are a slightly longer Lambda duration and a few more objects in the trail
bucket, both far inside the free tier.

## Write paths and self-cleaning

Every write is a create-then-delete pair that leaves the account exactly as it found it, and
each pair also cleans up defensively *before* creating, so a run that died halfway does not
wedge the next one. `kms:CreateAlias` returning `AlreadyExists` is treated as "a previous run
left this behind" and still proceeds to the delete — an early return there once left an alias
in place permanently and broke every subsequent run.

The alias delete waits two seconds for the create to settle first. KMS aliases are eventually
consistent and measurably so: counted from the trail, a `DeleteAlias` issued immediately after
a successful `CreateAlias` came back `NotFound` on **92 of 142 runs**. Each of those attempts
is still a CloudTrail event, and AWS records a failed `DeleteAlias` with
`requestParameters: null` — nothing to build a resource ARN from — so they arrived in the
report as `unknown_resource` and became the largest single group of unknowns in the fixture.
The tool was handling them correctly; the workload was generating noise about itself. The
retry loop remains as a backstop rather than the normal path. The wait costs about 0.5% of the
Lambda free tier.

**The workload is not safe under concurrent invocation.** Every run uses the same scratch
alias, security group and inline policy names, so two overlapping runs race: one creates, the
other sees `AlreadyExists` and deletes, and the first one's delete finds nothing. The
`rate(5 minutes)` schedule runs them sequentially, so this does not occur in normal operation —
but firing `aws lambda invoke` several times in quick succession will reproduce it.

**`s3:PutObject` and `s3:DeleteObject` are deliberately absent.** Object-level calls are
CloudTrail data events, so they would never reach the trail, the baseline permission granting
them could never be pinned by a negative control, and keeping the suite green would mean
widening the not-recorded exemption set. `PutBucketTagging` / `DeleteBucketTagging` exercises
the same s3 write path and is actually recorded.

## The policy actually in force is the tight baseline

The spec this repo was built from is ambiguous here, and the resolution matters.
`policy-tight-baseline.json` is the policy Terraform attaches to the role.
`policy-overbroad.json` is **never attached** — it exists only as the illustrative "before"
state for the README.

If the overbroad policy were in force, the oracle would replay against `s3:*` on `*`,
everything would allow, and the test would prove nothing. The oracle's strength is
proportional to how tight the in-force policy is.

See [`policies/README.md`](policies/README.md) for what each policy contains and, for the
candidate, exactly which three changes it makes and what each is expected to produce.

## Deploy

```bash
export AWS_PROFILE=<your-lab-profile>
cd terraform
terraform init
terraform apply
```

The apply needs IAM write permissions scoped to `role/iam-replay-fixture-*` — including
`iam:PassRole` to `lambda.amazonaws.com` — plus the usual create rights for S3, KMS,
CloudTrail, Lambda, EventBridge and CloudWatch Logs.

Rendered policies land in `terraform/rendered/` with the account ID and resource names
filled in. That directory is gitignored, since it carries a real account ID.

## Capture events and run the oracle

The workload runs every five minutes. `LookupEvents` surfaces calls within a few minutes;
S3 trail delivery lags 5–15 minutes.

```bash
# Verify the baseline really is sufficient: every call must succeed.
aws lambda invoke --function-name iam-replay-fixture-workload /dev/stdout
# => {"ok": 27, "failed": {}}

# Snapshot real events into the committed test fixture, scrubbing the account ID.
python scripts/capture_live_events.py \
  --principal "$(terraform -chdir=terraform output -raw role_arn)" \
  --days 1 --out tests/fixtures/cloudtrail/live

# And the second principal: calls made under the assumed session, which prove
# sessionIssuer attribution on real traffic.
python scripts/capture_live_events.py \
  --principal "$(terraform -chdir=terraform output -raw target_role_arn)" \
  --days 1 --name assumed_session_events --out tests/fixtures/cloudtrail/live

python scripts/refresh_validation_manifest.py

pytest tests/test_ground_truth.py tests/test_negative_control.py -s
```

**Use `--since` rather than `--days` after changing the workload.** Older events in the
window no longer reflect what the workload does, and replaying them against a baseline
written for the current workload produces denies that are not mapper bugs.

## The demo

```bash
ROLE=$(terraform -chdir=terraform output -raw role_arn)

# The oracle. Zero WOULD DENY.
iam-replay --principal "$ROLE" --policy terraform/rendered/policy-tight-baseline.json \
           --source lookup --days 1

# The candidate. Three WOULD DENY and one INDETERMINATE, all by design.
iam-replay --principal "$ROLE" --policy terraform/rendered/policy-candidate.json \
           --source lookup --days 1

# The files source, over the synced trail bucket.
aws s3 sync "s3://$(terraform -chdir=terraform output -raw trail_bucket)/AWSLogs/" ./trail-data/
iam-replay --principal "$ROLE" --policy terraform/rendered/policy-candidate.json \
           --source files --path ./trail-data --days 7
```

## If the oracle reports a DENY

It is a mapper bug — a wrong action, a wrong resource ARN, or a missing context key. Fix the
mapping in `src/iam_replay/normalize/mappings/`.

**Do not widen `policy-tight-baseline.json` to make the test pass, and never add an
exception list.** Widening the baseline is how the instrument silently loses its teeth: every
wildcard added there is a mapper bug it can no longer catch.

The one legitimate exception is a call authorized by something this tool does not evaluate —
a resource-based policy, for instance. That is not a mapper bug and not something to hide
either: the fixture removes the confound rather than papering over it. See the comment at
the top of `workload/handler.py.tpl` for the case that actually came up.

## Teardown

```bash
terraform destroy
```

Both buckets are `force_destroy`, so the trail objects go with them. The KMS key enters a
7-day deletion window rather than disappearing immediately — that is the AWS minimum, and it
keeps costing ~$1/month until it finalizes.
