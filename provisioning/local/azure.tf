variable "az_tenant_id" {
  type    = string
  default = "9b85ee6f-4fb0-4a46-8cb7-4dcc6b262a89"
}

provider "azurerm" {
  features {}
  tenant_id       = var.az_tenant_id
  subscription_id = "c5182964-8dca-42c8-a77a-fa2a3c6946ea"
}

provider "azuread" {
  tenant_id = var.az_tenant_id
}

data "azurerm_client_config" "current" {}
data "azuread_client_config" "current" {}

data "azuread_group" "developers" {
  display_name = "Developers"
}

output "az_tenant_id" {
  value = var.az_tenant_id
}
