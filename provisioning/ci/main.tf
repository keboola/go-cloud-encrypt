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

  backend "s3" {}
}

variable "name_prefix" {
  type = string
}
