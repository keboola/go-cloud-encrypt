locals {
  gcp_project = "go-team-ci"
  gcp_project_id = 592579407407
}

provider "google" {
  project = local.gcp_project
}
