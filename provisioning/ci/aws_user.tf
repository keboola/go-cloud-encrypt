resource "aws_iam_user" "object_encryptor" {
  name = "${var.name_prefix}-object-encryptor"
}

resource "aws_iam_role" "object_encryptor" {
  name = "${var.name_prefix}-object-encryptor-role"
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

resource "aws_iam_access_key" "object_encryptor" {
  user = aws_iam_user.object_encryptor.name
}

data "aws_iam_policy_document" "kms_access" {
  statement {
    sid     = "UseKMSKeys"
    effect  = "Allow"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey",
    ]
    resources = [
      aws_kms_key.object_encryptor.arn,
    ]
  }
}

data "aws_iam_policy_document" "sts_access" {
  statement {
    sid = "AssumeRole"
    effect = "Allow"
    actions = [
      "sts:AssumeRole"
    ]
    resources = [
      aws_iam_role.object_encryptor.arn,
    ]
  }
}

resource "aws_iam_user_policy" "object_encryptor_user_kms_access" {
  user        = aws_iam_user.object_encryptor.name
  name_prefix = "kms-access-"
  policy      = data.aws_iam_policy_document.kms_access.json
}

resource "aws_iam_user_policy" "object_encryptor_user_sts_access" {
  user        = aws_iam_user.object_encryptor.name
  name_prefix = "sts-access-"
  policy      = data.aws_iam_policy_document.sts_access.json
}

resource "aws_iam_role_policy" "object_encryptor_role_kms_access" {
  role        = aws_iam_role.object_encryptor.name
  name_prefix = "kms-access-"
  policy      = data.aws_iam_policy_document.kms_access.json
}

output "aws_access_key_id" {
  value = aws_iam_access_key.object_encryptor.id
}

output "aws_access_key_secret" {
  value     = aws_iam_access_key.object_encryptor.secret
  sensitive = true
}

output "aws_role_arn" {
  value = aws_iam_role.object_encryptor.arn
}
