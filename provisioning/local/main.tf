terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 3.74"
    }

    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 2.98"
    }

    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 2.18"
    }

    google = {
      source  = "hashicorp/google"
      version = "~> 4.74.0"
    }
  }

  backend "s3" {
    role_arn       = "arn:aws:iam::681277395786:role/kbc-local-dev-terraform"
    region         = "eu-central-1"
    bucket         = "local-dev-terraform-bucket"
    dynamodb_table = "local-dev-terraform-table"
  }
}

variable "name_prefix" {
  type = string
}
