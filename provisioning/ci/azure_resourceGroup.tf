resource "azurerm_resource_group" "object_encryptor" {
  name     = "${var.name_prefix}-object-encryptor"
  location = "eastus"
}
