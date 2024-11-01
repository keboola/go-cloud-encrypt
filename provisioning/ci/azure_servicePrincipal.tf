resource "azuread_application" "object_encryptor" {
  display_name = "${var.name_prefix}-object-encryptor"
  owners       = [data.azuread_client_config.current.object_id]
}

resource "azuread_service_principal" "object_encryptor" {
  application_id = azuread_application.object_encryptor.application_id
  owners         = [data.azuread_client_config.current.object_id]
}

resource "azuread_service_principal_password" "object_encryptor" {
  service_principal_id = azuread_service_principal.object_encryptor.id
}

output "az_application_id" {
  value = azuread_application.object_encryptor.application_id
}

output "az_application_secret" {
  value     = azuread_service_principal_password.object_encryptor.value
  sensitive = true
}
