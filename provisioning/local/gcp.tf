locals {
  gcp_project = "kbc-dev-platform-services"
}

provider "google" {
  project = local.gcp_project
}
