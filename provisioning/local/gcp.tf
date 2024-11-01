locals {
  gcp_project = "go-team-dev"
}

provider "google" {
  project = local.gcp_project
}
