# iam-replay ground-truth fixture.
#
# This is an instrument, not a demo. Its purpose is to produce real CloudTrail
# events from a workload whose permissions are known exactly, so that replaying
# those events against the policy that was actually in force must yield ALLOW
# for every one of them. Any DENY is a mapper bug.
#
# The policy attached to the workload role is policy-tight-baseline, NOT
# policy-overbroad. The oracle's whole claim is that it replays "the policy
# actually in force", and its strength is proportional to how tight that policy
# is: replayed against s3:* on *, everything allows and the test proves nothing.
# policy-overbroad exists only as the illustrative "before" state for the README.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws    = { source = "hashicorp/aws", version = "~> 5.0" }
    random = { source = "hashicorp/random", version = "~> 3.5" }
    local  = { source = "hashicorp/local", version = "~> 2.4" }
  }
}

provider "aws" {
  region = var.region
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

resource "random_id" "suffix" {
  byte_length = 4
}

locals {
  suffix        = random_id.suffix.hex
  account_id    = data.aws_caller_identity.current.account_id
  partition     = data.aws_partition.current.partition
  role_name     = "${var.name_prefix}-workload"
  function_name = "${var.name_prefix}-workload"
  data_bucket   = "${var.name_prefix}-data-${local.suffix}"
  trail_bucket  = "${var.name_prefix}-trail-${local.suffix}"

  role_arn     = "arn:${local.partition}:iam::${local.account_id}:role/${local.role_name}"
  function_arn = "arn:${local.partition}:lambda:${var.region}:${local.account_id}:function:${local.function_name}"
  log_group_arn = "arn:${local.partition}:logs:${var.region}:${local.account_id}:log-group:/aws/lambda/${local.function_name}:*"

  # Substitutions shared by all three policy templates, so the tight baseline
  # and the candidate differ only where they are meant to.
  policy_vars = {
    partition     = local.partition
    account_id    = local.account_id
    region        = var.region
    data_bucket   = local.data_bucket
    role_arn      = local.role_arn
    function_arn  = local.function_arn
    key_arn       = aws_kms_key.fixture.arn
    log_group_arn = local.log_group_arn
  }
}

# --- buckets -----------------------------------------------------------------

resource "aws_s3_bucket" "data" {
  bucket        = local.data_bucket
  force_destroy = true
}

resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket" "trail" {
  bucket        = local.trail_bucket
  force_destroy = true
}

resource "aws_s3_bucket_policy" "trail" {
  bucket = aws_s3_bucket.trail.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.trail.arn
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.trail.arn}/AWSLogs/${local.account_id}/*"
        Condition = {
          StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" }
        }
      }
    ]
  })
}

# --- a KMS key, so the workload has a resource-scoped kms call to make -------
# This is the only line item with a standing cost (~$1/month).

resource "aws_kms_key" "fixture" {
  description             = "iam-replay fixture key: gives the workload a resource-scoped kms:DescribeKey call"
  deletion_window_in_days = 7
}

resource "aws_kms_alias" "fixture" {
  name          = "alias/${var.name_prefix}"
  target_key_id = aws_kms_key.fixture.key_id
}

# --- the trail ---------------------------------------------------------------
#
# Management events only. Data events are deliberately left off: that is the
# default almost everywhere, and the tool's central limitation is that it cannot
# see what the trail does not record. The fixture reproduces that condition
# rather than papering over it.

resource "aws_cloudtrail" "fixture" {
  name                          = var.name_prefix
  s3_bucket_name                = aws_s3_bucket.trail.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true

  depends_on = [aws_s3_bucket_policy.trail]
}

# --- the workload role -------------------------------------------------------

resource "aws_iam_role" "workload" {
  name = local.role_name

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

# The policy actually in force. This is the oracle baseline.
resource "aws_iam_role_policy" "tight_baseline" {
  name   = "tight-baseline"
  role   = aws_iam_role.workload.id
  policy = templatefile("${path.module}/policies/policy-tight-baseline.json.tpl", local.policy_vars)
}

# --- the workload ------------------------------------------------------------

# The handler is rendered from a template rather than given environment
# variables. See the comment at the top of workload/handler.py.tpl: Lambda
# decrypts env vars at cold start under the execution role's credentials,
# producing a kms:Decrypt event authorized by a resource-based key policy that
# the ground-truth oracle would necessarily read as a false deny.
data "archive_file" "workload" {
  type        = "zip"
  output_path = "${path.module}/.terraform/workload.zip"

  source {
    filename = "handler.py"
    content = templatefile("${path.module}/workload/handler.py.tpl", {
      data_bucket   = local.data_bucket
      role_name     = local.role_name
      function_name = local.function_name
      kms_key_id    = aws_kms_key.fixture.key_id
    })
  }
}

resource "aws_cloudwatch_log_group" "workload" {
  name              = "/aws/lambda/${local.function_name}"
  retention_in_days = 7
}

resource "aws_lambda_function" "workload" {
  function_name    = local.function_name
  role             = aws_iam_role.workload.arn
  handler          = "handler.handler"
  runtime          = "python3.12"
  timeout          = 60
  filename         = data.archive_file.workload.output_path
  source_code_hash = data.archive_file.workload.output_base64sha256

  # Deliberately no environment block -- see archive_file.workload above.

  depends_on = [aws_cloudwatch_log_group.workload]
}

resource "aws_cloudwatch_event_rule" "schedule" {
  name                = "${var.name_prefix}-schedule"
  schedule_expression = var.schedule_expression
}

resource "aws_cloudwatch_event_target" "workload" {
  rule = aws_cloudwatch_event_rule.schedule.name
  arn  = aws_lambda_function.workload.arn
}

resource "aws_lambda_permission" "events" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.workload.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.schedule.arn
}

# --- rendered policies for the CLI to replay against -------------------------
#
# The templates are the single source of truth; these are the concrete files
# the README demo points iam-replay at. They are gitignored because they carry
# a real account ID and bucket names.

resource "local_file" "rendered_policies" {
  for_each = toset(["policy-tight-baseline", "policy-candidate", "policy-overbroad"])

  filename = "${path.module}/rendered/${each.key}.json"
  content  = templatefile("${path.module}/policies/${each.key}.json.tpl", local.policy_vars)
}
