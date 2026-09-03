"""A deliberately boring control-plane workload.

Every call here is read-only, deterministic, and scoped to a resource the
fixture created. That matters: the ground-truth oracle replays these calls
against the policy that authorized them, so the call list has to be knowable
exactly. A workload that varied its resources run to run would make a mapper
bug indistinguishable from a workload change.

Nothing here launches an instance. ec2:RunInstances is the most expensive
mapping in the allowlist (it expands to several permissions), but the expansion
is pure mapping logic and a hand-built fixture exercises it exactly as well as a
real instance would, for none of the money.
"""

import json
import time

import boto3

# Baked in by Terraform rather than passed as environment variables. Lambda
# encrypts env vars at rest and decrypts them at cold start under the execution
# role's own credentials, which emits a kms:Decrypt event against the
# AWS-managed aws/lambda key. That call is authorized by the key's
# *resource-based* key policy, not by the role's identity policy -- so the
# ground-truth oracle would see a SUCCEEDED event that the tight baseline does
# not allow, and report a DENY that is not a mapper bug.
#
# Rather than widen the baseline to hide it, or add the exception list the spec
# forbids, the fixture removes the confound. The underlying limitation is real
# and belongs in the README: this tool evaluates identity policies only, so any
# call authorized by a resource-based policy will look like a false deny.
DATA_BUCKET = "${data_bucket}"
ROLE_NAME = "${role_name}"
FUNCTION_NAME = "${function_name}"
FUNCTION_ARN = "${function_arn}"
KMS_KEY_ID = "${kms_key_id}"
SCRATCH_ROLE_NAME = "${scratch_role_name}"
TARGET_ROLE_ARN = "${target_role_arn}"
SCRATCH_SG_NAME = "${scratch_sg_name}"
SCRATCH_ALIAS = "${scratch_alias}"


def _read_only_calls(s3, iam, sts, ec2, lam, kms):
    """Calls that change nothing. Safe to run in any order, any number of times."""
    return [
        # s3 -- bucket-level calls are management events and land in the trail.
        ("s3:ListBuckets", lambda: s3.list_buckets()),
        ("s3:ListObjectsV2", lambda: s3.list_objects_v2(Bucket=DATA_BUCKET, MaxKeys=1)),
        ("s3:GetBucketLocation", lambda: s3.get_bucket_location(Bucket=DATA_BUCKET)),
        ("s3:GetBucketVersioning", lambda: s3.get_bucket_versioning(Bucket=DATA_BUCKET)),
        # iam
        ("iam:GetRole", lambda: iam.get_role(RoleName=ROLE_NAME)),
        ("iam:ListRoles", lambda: iam.list_roles(MaxItems=1)),
        ("iam:ListAttachedRolePolicies", lambda: iam.list_attached_role_policies(RoleName=ROLE_NAME)),
        # sts -- requires no IAM permission at all, which is exactly why it is
        # here: the mapper must not turn it into a request.
        ("sts:GetCallerIdentity", lambda: sts.get_caller_identity()),
        # ec2 -- Describe* has no resource-level permissions, so these authorize
        # against "*" and the tight baseline says so explicitly.
        ("ec2:DescribeInstances", lambda: ec2.describe_instances(MaxResults=5)),
        ("ec2:DescribeSecurityGroups", lambda: ec2.describe_security_groups(MaxResults=5)),
        ("ec2:DescribeVpcs", lambda: ec2.describe_vpcs(MaxResults=5)),
        # lambda
        ("lambda:GetFunction", lambda: lam.get_function(FunctionName=FUNCTION_NAME)),
        ("lambda:ListFunctions", lambda: lam.list_functions(MaxItems=1)),
        # kms
        ("kms:DescribeKey", lambda: kms.describe_key(KeyId=KMS_KEY_ID)),
        ("kms:ListAliases", lambda: kms.list_aliases(Limit=1)),
    ]


# --- write paths -------------------------------------------------------------
#
# Every one is a create-then-delete pair that leaves the account exactly as it
# found it. Each pair also cleans up defensively *before* creating, so a run
# that died halfway through last time does not wedge the next one.
#
# What is deliberately absent: s3:PutObject and s3:DeleteObject. Object-level
# calls are CloudTrail data events, so they would never reach the trail, the
# baseline permission granting them could never be pinned by a negative
# control, and the only way to keep the suite green would be to widen the
# not-recorded exemption set. A bucket-level write (PutBucketTagging) exercises
# the same s3 write path and is actually recorded.


def _security_group_pair(ec2, results):
    """ec2: create and delete a security group."""
    vpc_id = None
    try:
        vpcs = ec2.describe_vpcs(MaxResults=5).get("Vpcs", [])
        vpc_id = vpcs[0]["VpcId"] if vpcs else None
    except Exception as exc:  # noqa: BLE001
        results["ec2:CreateSecurityGroup"] = f"no vpc available: {exc}"
        return

    if vpc_id is None:
        results["ec2:CreateSecurityGroup"] = "skipped: account has no VPC"
        return

    group_id = _existing_security_group(ec2)
    if group_id is None:
        try:
            group_id = ec2.create_security_group(
                GroupName=SCRATCH_SG_NAME,
                Description="iam-replay fixture scratch group; created and deleted each run",
                VpcId=vpc_id,
            )["GroupId"]
            results["ec2:CreateSecurityGroup"] = "ok"
        except Exception as exc:  # noqa: BLE001
            results["ec2:CreateSecurityGroup"] = f"{type(exc).__name__}: {exc}"
            return
    else:
        results["ec2:CreateSecurityGroup"] = "reused leftover from a previous run"

    try:
        ec2.delete_security_group(GroupId=group_id)
        results["ec2:DeleteSecurityGroup"] = "ok"
    except Exception as exc:  # noqa: BLE001
        results["ec2:DeleteSecurityGroup"] = f"{type(exc).__name__}: {exc}"


def _existing_security_group(ec2):
    try:
        groups = ec2.describe_security_groups(
            Filters=[{"Name": "group-name", "Values": [SCRATCH_SG_NAME]}]
        ).get("SecurityGroups", [])
        return groups[0]["GroupId"] if groups else None
    except Exception:  # noqa: BLE001
        return None


def _inline_role_policy_pair(iam, results):
    """iam: put and delete an inline policy on a dedicated throwaway role."""
    document = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Deny", "Action": "s3:GetObject", "Resource": "*"}
            ],
        }
    )
    try:
        iam.put_role_policy(
            RoleName=SCRATCH_ROLE_NAME, PolicyName="scratch", PolicyDocument=document
        )
        results["iam:PutRolePolicy"] = "ok"
    except Exception as exc:  # noqa: BLE001
        results["iam:PutRolePolicy"] = f"{type(exc).__name__}: {exc}"
        return

    try:
        iam.delete_role_policy(RoleName=SCRATCH_ROLE_NAME, PolicyName="scratch")
        results["iam:DeleteRolePolicy"] = "ok"
    except Exception as exc:  # noqa: BLE001
        results["iam:DeleteRolePolicy"] = f"{type(exc).__name__}: {exc}"


def _kms_alias_pair(kms, results):
    """kms: create and delete an alias against the fixture key.

    KMS aliases are eventually consistent: a DeleteAlias issued immediately
    after a successful CreateAlias can come back NotFound. The delete therefore
    retries, and -- more importantly -- runs even when the create failed,
    because an AlreadyExists from a previous run's leftover is exactly the case
    that must still be cleaned up. An early return here left the alias behind
    permanently and wedged every later run.
    """
    try:
        kms.create_alias(AliasName=SCRATCH_ALIAS, TargetKeyId=KMS_KEY_ID)
        results["kms:CreateAlias"] = "ok"
    except Exception as exc:  # noqa: BLE001
        if type(exc).__name__ == "AlreadyExistsException":
            results["kms:CreateAlias"] = "alias left over from a previous run; cleaning up"
        else:
            results["kms:CreateAlias"] = f"{type(exc).__name__}: {exc}"

    last = None
    for attempt in range(4):
        try:
            kms.delete_alias(AliasName=SCRATCH_ALIAS)
            results["kms:DeleteAlias"] = "ok"
            return
        except Exception as exc:  # noqa: BLE001
            last = exc
            if type(exc).__name__ != "NotFoundException":
                break
            time.sleep(0.5 * (attempt + 1))

    results["kms:DeleteAlias"] = f"{type(last).__name__}: {last}"


def _bucket_tagging_pair(s3, results):
    """s3: a bucket-level write and its removal.

    DeleteBucketTagging is authorized by s3:PutBucketTagging, so one baseline
    permission covers both calls.
    """
    try:
        s3.put_bucket_tagging(
            Bucket=DATA_BUCKET,
            Tagging={"TagSet": [{"Key": "iam-replay-fixture", "Value": "scratch"}]},
        )
        results["s3:PutBucketTagging"] = "ok"
    except Exception as exc:  # noqa: BLE001
        results["s3:PutBucketTagging"] = f"{type(exc).__name__}: {exc}"
        return

    try:
        s3.delete_bucket_tagging(Bucket=DATA_BUCKET)
        results["s3:DeleteBucketTagging"] = "ok"
    except Exception as exc:  # noqa: BLE001
        results["s3:DeleteBucketTagging"] = f"{type(exc).__name__}: {exc}"


def _lambda_tag_pair(lam, results):
    """lambda: tag and untag the function."""
    try:
        lam.tag_resource(Resource=FUNCTION_ARN, Tags={"iam-replay-fixture": "scratch"})
        results["lambda:TagResource"] = "ok"
    except Exception as exc:  # noqa: BLE001
        results["lambda:TagResource"] = f"{type(exc).__name__}: {exc}"
        return

    try:
        lam.untag_resource(Resource=FUNCTION_ARN, TagKeys=["iam-replay-fixture"])
        results["lambda:UntagResource"] = "ok"
    except Exception as exc:  # noqa: BLE001
        results["lambda:UntagResource"] = f"{type(exc).__name__}: {exc}"


def _assume_role_and_call(sts, results):
    """sts: assume a second fixture role, then make a call under that session.

    Two things are being exercised. The AssumeRole event itself is attributed to
    *this* role and validates the sts:AssumeRole mapping, which until now had
    nothing behind it. The call made under the session is attributed to the
    target role, whose ARN carries a path -- so resolving it correctly proves
    sessionIssuer attribution works on real traffic, which is exactly the case
    string-parsing the session ARN gets wrong.
    """
    try:
        session = sts.assume_role(
            RoleArn=TARGET_ROLE_ARN, RoleSessionName="iam-replay-fixture-probe"
        )["Credentials"]
        results["sts:AssumeRole"] = "ok"
    except Exception as exc:  # noqa: BLE001
        results["sts:AssumeRole"] = f"{type(exc).__name__}: {exc}"
        return

    try:
        assumed = boto3.client(
            "s3",
            aws_access_key_id=session["AccessKeyId"],
            aws_secret_access_key=session["SecretAccessKey"],
            aws_session_token=session["SessionToken"],
        )
        assumed.list_buckets()
        results["assumed-session:s3:ListBuckets"] = "ok"
    except Exception as exc:  # noqa: BLE001
        results["assumed-session:s3:ListBuckets"] = f"{type(exc).__name__}: {exc}"


def handler(event, context):
    """Run every call, recording outcomes without letting one failure stop the rest.

    A call that fails still produces a CloudTrail event, and an AccessDenied
    here is itself useful signal -- it means the tight baseline is not actually
    sufficient for the workload, which would invalidate the oracle.
    """
    s3 = boto3.client("s3")
    iam = boto3.client("iam")
    sts = boto3.client("sts")
    ec2 = boto3.client("ec2")
    lam = boto3.client("lambda")
    kms = boto3.client("kms")

    results = {}
    for label, call in _read_only_calls(s3, iam, sts, ec2, lam, kms):
        try:
            call()
            results[label] = "ok"
        except Exception as exc:  # noqa: BLE001 - every outcome is data here
            results[label] = f"{type(exc).__name__}: {exc}"

    _security_group_pair(ec2, results)
    _inline_role_policy_pair(iam, results)
    _kms_alias_pair(kms, results)
    _bucket_tagging_pair(s3, results)
    _lambda_tag_pair(lam, results)
    _assume_role_and_call(sts, results)

    failed = {k: v for k, v in results.items() if v != "ok"}
    print(json.dumps({"results": results, "failed_count": len(failed)}))

    return {"ok": len(results) - len(failed), "failed": failed}
