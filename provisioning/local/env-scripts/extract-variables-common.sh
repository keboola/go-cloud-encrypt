#!/usr/bin/env bash
set -Eeuo pipefail

cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source ./functions.sh

# output variables
output_var 'AZURE_TENANT_ID' "$(terraform_output 'az_tenant_id')"
output_var 'AZURE_CLIENT_ID' "$(terraform_output 'az_application_id')"
output_var 'AZURE_CLIENT_SECRET' "$(terraform_output 'az_application_secret')"
output_var 'AZURE_KEY_VAULT_URL' "$(terraform_output 'az_key_vault_url')"
output_var 'AZURE_KEY_NAME' "$(terraform_output 'az_key_name')"
echo ""

output_var 'AWS_ACCESS_KEY_ID' "$(terraform_output 'aws_access_key_id')"
output_var 'AWS_SECRET_ACCESS_KEY' "$(terraform_output 'aws_access_key_secret')"
output_var 'AWS_REGION' "$(terraform_output 'aws_region')"
output_var 'AWS_KMS_KEY_ID' "$(terraform_output 'aws_kms_key_id')"
output_var 'AWS_ROLE_ID' "$(terraform_output 'aws_role_arn')"
echo ""

output_var 'GCP_KMS_KEY_ID' "$(terraform_output 'gcp_kms_key_id')"
PRIVATE_KEY_ENCODED="$(terraform_output 'gcp_private_key')"
PRIVATE_KEY=$(printf "%s" "$PRIVATE_KEY_ENCODED" | base64 --decode)

output_file 'var/gcp-private-key.json' "$PRIVATE_KEY"
output_var 'GOOGLE_APPLICATION_CREDENTIALS' '/code/var/gcp-private-key.json'

echo ""
