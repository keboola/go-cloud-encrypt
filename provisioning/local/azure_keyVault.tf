resource "azurerm_key_vault" "object_encryptor" {
  name                = "${var.name_prefix}-object-encryptor"
  tenant_id           = data.azurerm_client_config.current.tenant_id
  resource_group_name = azurerm_resource_group.object_encryptor.name
  location            = azurerm_resource_group.object_encryptor.location
  sku_name            = "standard"

  access_policy {
    tenant_id = data.azurerm_client_config.current.tenant_id
    object_id = azuread_service_principal.object_encryptor.id

    secret_permissions = [
      "Get",
      "List",
      "Set",
      "Delete",
    ]
  }

  access_policy {
    tenant_id = data.azurerm_client_config.current.tenant_id
    object_id = data.azuread_group.developers.object_id

    key_permissions = [
      "Get",
      "List",
      "Update",
      "Create",
      "Import",
      "Delete",
      "Recover",
      "Backup",
      "Restore",
    ]

    secret_permissions = [
      "Get",
      "List",
      "Set",
      "Delete",
    ]
  }
}

output "az_key_vault_url" {
  value = azurerm_key_vault.object_encryptor.vault_uri
}
