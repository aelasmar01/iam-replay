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
        "s3:GetBucketLocation"
      ],
      "Resource": "arn:${partition}:s3:::${data_bucket}",
      "Condition": {
        "StringEquals": {
          "aws:ResourceTag/Project": "iam-replay"
        }
      }
    },
    {
      "Sid": "ReadOwnRole",
      "Effect": "Allow",
      "Action": [
        "iam:GetRole",
        "iam:ListAttachedRolePolicies"
      ],
      "Resource": "arn:${partition}:iam::${account_id}:role/some-other-role"
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
