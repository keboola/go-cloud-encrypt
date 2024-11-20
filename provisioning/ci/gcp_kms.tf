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

  labels = {
    "stack" = "${var.name_prefix}-go-cloud-encrypt"
    "role"  = "go-cloud-encrypt"
  }
}

resource "google_kms_crypto_key_iam_binding" "go_cloud_encrypt_iam" {
  crypto_key_id = google_kms_crypto_key.go_cloud_encrypt_key.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"

  members = [
    local.github_actions_principal
  ]
}


output "gcp_kms_key_id" {
  value = google_kms_crypto_key.go_cloud_encrypt_key.id
}
