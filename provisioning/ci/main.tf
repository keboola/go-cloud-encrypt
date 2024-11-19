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

  backend "s3" {}
}

variable "name_prefix" {
  type = string
}

locals {
  github_repository = "keboola/go-cloud-encrypt"
}
