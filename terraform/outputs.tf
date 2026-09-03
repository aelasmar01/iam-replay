output "role_arn" {
  description = "Pass this to iam-replay --principal."
  value       = aws_iam_role.workload.arn
}

output "trail_bucket" {
  description = "aws s3 sync this to exercise the files source."
  value       = aws_s3_bucket.trail.id
}

output "data_bucket" {
  value = aws_s3_bucket.data.id
}

output "rendered_policy_dir" {
  description = "Concrete policies to replay against."
  value       = "${path.module}/rendered"
}

output "replay_command" {
  description = "The oracle. Expect zero WOULD DENY."
  value = join(" ", [
    "iam-replay --principal", aws_iam_role.workload.arn,
    "--policy terraform/rendered/policy-tight-baseline.json",
    "--source lookup --days 7"
  ])
}
