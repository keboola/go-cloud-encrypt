resource "google_iam_workload_identity_pool" "go_cloud_encrypt" {
  workload_identity_pool_id = "${var.name_prefix}-go-cloud-encrypt"
}

resource "google_iam_workload_identity_pool_provider" "go_cloud_encrypt" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.go_cloud_encrypt.workload_identity_pool_id
  workload_identity_pool_provider_id = "go-cloud-encrypt"
  attribute_condition = <<EOT
    attribute.repository == "${local.github_repository}"
EOT
  attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.actor"      = "assertion.actor"
    "attribute.aud"        = "assertion.aud"
    "attribute.repository" = "assertion.repository"
  }
  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}

resource "google_service_account_iam_member" "go_cloud_encrypt" {
  service_account_id = google_service_account.go_cloud_encrypt_service_account.name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "principalSet://iam.googleapis.com/projects/${local.gcp_project_id}/locations/global/workloadIdentityPools/${google_iam_workload_identity_pool.go_cloud_encrypt.workload_identity_pool_id}/attribute.repository/${local.github_repository}"
}
