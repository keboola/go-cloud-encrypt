provider "aws" {
  allowed_account_ids = ["480319613404"] # CI-Platform-Services-Team
  region  = "eu-central-1"

  default_tags {
    tags = {
      KebolaStack = "${var.name_prefix}-go-cloud-encrypt"
      KeboolaRole = "go-cloud-encrypt"
    }
  }
}

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}
