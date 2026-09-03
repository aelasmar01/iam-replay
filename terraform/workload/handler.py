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
import os

import boto3

DATA_BUCKET = os.environ["DATA_BUCKET"]
ROLE_NAME = os.environ["ROLE_NAME"]
FUNCTION_NAME = os.environ["FUNCTION_NAME"]
KMS_KEY_ID = os.environ["KMS_KEY_ID"]


def _calls():
    """(label, callable) for every API call the workload makes."""
    s3 = boto3.client("s3")
    iam = boto3.client("iam")
    sts = boto3.client("sts")
    ec2 = boto3.client("ec2")
    lam = boto3.client("lambda")
    kms = boto3.client("kms")

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


def handler(event, context):
    """Run every call, recording outcomes without letting one failure stop the rest.

    A call that fails still produces a CloudTrail event, and an AccessDenied
    here is itself useful signal -- it means the tight baseline is not actually
    sufficient for the workload, which would invalidate the oracle.
    """
    results = {}
    for label, call in _calls():
        try:
            call()
            results[label] = "ok"
        except Exception as exc:  # noqa: BLE001 - every outcome is data here
            results[label] = f"{type(exc).__name__}: {exc}"

    failed = {k: v for k, v in results.items() if v != "ok"}
    print(json.dumps({"results": results, "failed_count": len(failed)}))

    return {"ok": len(results) - len(failed), "failed": failed}
