locals {
  gcp_project = "kbc-ci-platform-services"
}

provider "google" {
  project = local.gcp_project
}
