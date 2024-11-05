resource "google_service_account" "go_cloud_encrypt_service_account" {
  account_id   = "${var.name_prefix}-go-cloud-encrypt"
  display_name = "${var.name_prefix} Go Cloud Encrypt DEV"
}

resource "google_kms_crypto_key_iam_binding" "go_cloud_encrypt_iam" {
  crypto_key_id = google_kms_crypto_key.go_cloud_encrypt_key.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"

  members = [
    google_service_account.go_cloud_encrypt_service_account.member,
  ]
}

resource "google_service_account_key" "go_cloud_encrypt_key" {
  service_account_id = google_service_account.go_cloud_encrypt_service_account.name
  public_key_type    = "TYPE_X509_PEM_FILE"
  private_key_type   = "TYPE_GOOGLE_CREDENTIALS_FILE"
}

output "gcp_private_key" {
  value     = google_service_account_key.go_cloud_encrypt_key.private_key
  sensitive = true
}
