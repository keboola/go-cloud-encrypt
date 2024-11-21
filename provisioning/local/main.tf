terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.76"
    }

    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.10"
    }

    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 3.0"
    }

    google = {
      source  = "hashicorp/google"
      version = "~> 6.12"
    }
  }

  backend "s3" {
    assume_role = {
      role_arn = "arn:aws:iam::681277395786:role/kbc-local-dev-terraform"
    }
    region         = "eu-central-1"
    bucket         = "local-dev-terraform-bucket"
    dynamodb_table = "local-dev-terraform-table"
    key            = "go-cloud-encrypt"
  }
}

variable "name_prefix" {
  type = string
}
