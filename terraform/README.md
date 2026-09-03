# The ground-truth fixture

This is an instrument, not a demo.

Its purpose is to produce real CloudTrail events from a workload whose permissions are known
exactly, so that replaying those events against the policy that actually authorized them
must yield `ALLOW` for every one. **Any `DENY` is a mapper bug.**

## What it deploys

| Resource | Why |
|---|---|
| IAM role `iam-replay-fixture-workload` | The principal under test. Carries `policy-tight-baseline.json` as an inline policy — see below. |
| Lambda `iam-replay-fixture-workload` | Makes a fixed, deterministic set of 15 control-plane calls across all six allowlisted services. |
| EventBridge rule, `rate(5 minutes)` | Keeps producing events so the window stays populated. |
| S3 data bucket | Gives the workload a real bucket to make bucket-level calls against. |
| KMS key + alias | Gives the workload a resource-scoped `kms:DescribeKey` call. |
| S3 trail bucket + CloudTrail trail | Management events, multi-region. Needed for the `files` source. |

**Cost: roughly $1–2/month**, almost entirely the KMS key ($1/mo). Lambda and EventBridge
stay inside the free tier; S3 and the trail are cents.

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
# => {"ok": 15, "failed": {}}

# Snapshot real events into the committed test fixture, scrubbing the account ID.
python scripts/capture_live_events.py \
  --principal "$(terraform -chdir=terraform output -raw role_arn)" \
  --days 1 --out tests/fixtures/cloudtrail/live

pytest tests/test_ground_truth.py -s
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
