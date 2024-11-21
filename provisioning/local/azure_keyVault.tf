resource "azurerm_key_vault" "go_cloud_encrypt" {
  name                = "${var.name_prefix}-go-cloud-encrypt"
  tenant_id           = data.azurerm_client_config.current.tenant_id
  resource_group_name = azurerm_resource_group.go_cloud_encrypt.name
  location            = azurerm_resource_group.go_cloud_encrypt.location
  sku_name            = "standard"

  access_policy {
    tenant_id = data.azurerm_client_config.current.tenant_id
    object_id = azuread_service_principal.go_cloud_encrypt.object_id

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
      "Purge",
      "Encrypt",
      "Decrypt",
      "GetRotationPolicy",
      "SetRotationPolicy",
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
      "Purge",
      "Encrypt",
      "Decrypt",
      "GetRotationPolicy",
      "SetRotationPolicy",
    ]
  }
}

resource "azurerm_key_vault_key" "go_cloud_encrypt" {
  name         = "${var.name_prefix}-go-cloud-encrypt"
  key_vault_id = azurerm_key_vault.go_cloud_encrypt.id
  key_type     = "RSA"
  key_size     = 2048
  key_opts     = [
    "decrypt",
    "encrypt",
  ]
}

output "az_key_vault_url" {
  value = azurerm_key_vault.go_cloud_encrypt.vault_uri
}

output "az_key_name" {
  value = azurerm_key_vault_key.go_cloud_encrypt.name
}
