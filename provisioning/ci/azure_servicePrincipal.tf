resource "azuread_application" "go_cloud_encrypt" {
  display_name = "${var.name_prefix}-go-cloud-encrypt"
  owners       = [data.azuread_client_config.current.object_id]
}

resource "azuread_service_principal" "go_cloud_encrypt" {
  client_id = azuread_application.go_cloud_encrypt.client_id
  owners    = [data.azuread_client_config.current.object_id]
}

resource "azuread_service_principal_password" "go_cloud_encrypt" {
  service_principal_id = azuread_service_principal.go_cloud_encrypt.id
}

output "az_client_id" {
  value = azuread_application.go_cloud_encrypt.client_id
}

output "az_application_secret" {
  value     = azuread_service_principal_password.go_cloud_encrypt.value
  sensitive = true
}
