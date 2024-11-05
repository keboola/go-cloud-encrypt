resource "azurerm_resource_group" "go_cloud_encrypt" {
  name     = "${var.name_prefix}-go-cloud-encrypt"
  location = "eastus"
}
