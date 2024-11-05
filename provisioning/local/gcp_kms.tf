resource "google_kms_key_ring" "go_cloud_encrypt_keyring" {
  name     = "${var.name_prefix}-go-cloud-encrypt"
  location = "global"
}

resource "google_kms_crypto_key" "go_cloud_encrypt_key" {
  name     = "${var.name_prefix}-go-cloud-encrypt"
  key_ring = google_kms_key_ring.go_cloud_encrypt_keyring.id
  purpose  = "ENCRYPT_DECRYPT"

  lifecycle {
    prevent_destroy = false
  }
}

output "gcp_kms_key_id" {
  value = google_kms_crypto_key.go_cloud_encrypt_key.id
}
