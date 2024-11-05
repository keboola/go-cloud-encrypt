resource "aws_iam_user" "go_cloud_encrypt" {
  name = "${var.name_prefix}-go-cloud-encrypt"
}

resource "aws_iam_role" "go_cloud_encrypt" {
  name = "${var.name_prefix}-go-cloud-encrypt-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
      },
    ]
  })
}

resource "aws_iam_access_key" "go_cloud_encrypt" {
  user = aws_iam_user.go_cloud_encrypt.name
}

data "aws_iam_policy_document" "kms_access" {
  statement {
    sid    = "UseKMSKeys"
    effect = "Allow"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey",
    ]
    resources = [
      aws_kms_key.go_cloud_encrypt.arn,
    ]
  }
}

data "aws_iam_policy_document" "sts_access" {
  statement {
    sid    = "AssumeRole"
    effect = "Allow"
    actions = [
      "sts:AssumeRole"
    ]
    resources = [
      aws_iam_role.go_cloud_encrypt.arn,
    ]
  }
}

resource "aws_iam_user_policy" "go_cloud_encrypt_tests_kms" {
  user        = aws_iam_user.go_cloud_encrypt.name
  name_prefix = "kms-access-"
  policy      = data.aws_iam_policy_document.kms_access.json
}

resource "aws_iam_user_policy" "go_cloud_encrypt_tests_sts" {
  user        = aws_iam_user.go_cloud_encrypt.name
  name_prefix = "sts-access-"
  policy      = data.aws_iam_policy_document.sts_access.json
}

resource "aws_iam_role_policy" "go_cloud_encrypt_tests" {
  role        = aws_iam_role.go_cloud_encrypt.name
  name_prefix = "kms-access-"
  policy      = data.aws_iam_policy_document.kms_access.json
}

output "aws_access_key_id" {
  value = aws_iam_access_key.go_cloud_encrypt.id
}

output "aws_access_key_secret" {
  value     = aws_iam_access_key.go_cloud_encrypt.secret
  sensitive = true
}

output "aws_role_arn" {
  value = aws_iam_role.go_cloud_encrypt.arn
}
