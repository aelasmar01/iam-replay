{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "TheUsualStartingPoint",
      "Effect": "Allow",
      "Action": [
        "s3:*",
        "iam:*",
        "ec2:*",
        "lambda:*",
        "kms:*",
        "logs:*"
      ],
      "Resource": "*"
    }
  ]
}
