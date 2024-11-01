provider "aws" {
  allowed_account_ids = ["480319613404"] # CI-Platform-Services-Team
  region  = "eu-central-1"

  default_tags {
    tags = {
      KebolaStack = "${var.name_prefix}-object-encryptor"
      KeboolaRole = "object-encryptor"
    }
  }
}

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}
