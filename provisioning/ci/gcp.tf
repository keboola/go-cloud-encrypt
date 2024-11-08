locals {
  gcp_project = "go-team-ci"
}

provider "google" {
  project = local.gcp_project
}
