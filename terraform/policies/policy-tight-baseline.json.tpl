{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ListAllBuckets",
      "Effect": "Allow",
      "Action": "s3:ListAllMyBuckets",
      "Resource": "*"
    },
    {
      "Sid": "ReadTheFixtureBucket",
      "Effect": "Allow",
      "Action": [
        "s3:ListBucket",
        "s3:GetBucketLocation",
        "s3:GetBucketVersioning"
      ],
      "Resource": "arn:${partition}:s3:::${data_bucket}"
    },
    {
      "Sid": "ReadOwnRole",
      "Effect": "Allow",
      "Action": [
        "iam:GetRole",
        "iam:ListAttachedRolePolicies"
      ],
      "Resource": "${role_arn}"
    },
    {
      "Sid": "ListRoles",
      "Effect": "Allow",
      "Action": "iam:ListRoles",
      "Resource": "*"
    },
    {
      "Sid": "DescribeEc2",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeVpcs"
      ],
      "Resource": "*"
    },
    {
      "Sid": "ReadOwnFunction",
      "Effect": "Allow",
      "Action": "lambda:GetFunction",
      "Resource": "${function_arn}"
    },
    {
      "Sid": "ListFunctions",
      "Effect": "Allow",
      "Action": "lambda:ListFunctions",
      "Resource": "*"
    },
    {
      "Sid": "DescribeFixtureKey",
      "Effect": "Allow",
      "Action": "kms:DescribeKey",
      "Resource": "${key_arn}"
    },
    {
      "Sid": "ListAliases",
      "Effect": "Allow",
      "Action": "kms:ListAliases",
      "Resource": "*"
    },
    {
      "Sid": "CreateScratchSecurityGroup",
      "Effect": "Allow",
      "Action": "ec2:CreateSecurityGroup",
      "Resource": [
        "arn:${partition}:ec2:${region}:${account_id}:security-group/*",
        "arn:${partition}:ec2:${region}:${account_id}:vpc/*"
      ]
    },
    {
      "Sid": "DeleteScratchSecurityGroup",
      "Effect": "Allow",
      "Action": "ec2:DeleteSecurityGroup",
      "Resource": "arn:${partition}:ec2:${region}:${account_id}:security-group/*"
    },
    {
      "Sid": "WriteScratchRolePolicy",
      "Effect": "Allow",
      "Action": [
        "iam:PutRolePolicy",
        "iam:DeleteRolePolicy"
      ],
      "Resource": "${scratch_role_arn}"
    },
    {
      "Sid": "ManageScratchAlias",
      "Effect": "Allow",
      "Action": [
        "kms:CreateAlias",
        "kms:DeleteAlias"
      ],
      "Resource": "arn:${partition}:kms:${region}:${account_id}:${scratch_alias}"
    },
    {
      "Sid": "AliasTargetKey",
      "Effect": "Allow",
      "Action": [
        "kms:CreateAlias",
        "kms:DeleteAlias"
      ],
      "Resource": "${key_arn}"
    },
    {
      "Sid": "TagTheFixtureBucket",
      "Effect": "Allow",
      "Action": "s3:PutBucketTagging",
      "Resource": "arn:${partition}:s3:::${data_bucket}"
    },
    {
      "Sid": "TagOwnFunction",
      "Effect": "Allow",
      "Action": [
        "lambda:TagResource",
        "lambda:UntagResource"
      ],
      "Resource": "${function_arn}"
    },
    {
      "Sid": "AssumeTargetRole",
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "${target_role_arn}"
    },
    {
      "Sid": "WriteOwnLogs",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "${log_group_arn}"
    }
  ]
}
