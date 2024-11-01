data "aws_iam_policy_document" "kms_key_policy" {
  statement {
    sid = "Enable IAM User Permissions"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = [
        "arn:aws:iam:${data.aws_caller_identity.current.account_id}:root"
      ]
    }
    actions = [
      "kms:*"
    ]
    resources = [
      "*"
    ]
  }
}

resource "aws_kms_key" "object_encryptor" {
  description = "Object Encryptor key - ${var.name_prefix}"
}

output "aws_kms_key_id" {
  value = aws_kms_key.object_encryptor.id
}
