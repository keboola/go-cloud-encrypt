resource "google_kms_key_ring" "object_encryptor_keyring" {
  name     = "${var.name_prefix}-object-encryptor"
  location = "global"
}

resource "google_kms_crypto_key" "object_encryptor_key" {
  name     = "${var.name_prefix}-object-encryptor"
  key_ring = google_kms_key_ring.object_encryptor_keyring.id
  purpose  = "ENCRYPT_DECRYPT"

  lifecycle {
    prevent_destroy = false
  }
}

output "gcp_kms_key_id" {
  value = google_kms_crypto_key.object_encryptor_key.id
}
