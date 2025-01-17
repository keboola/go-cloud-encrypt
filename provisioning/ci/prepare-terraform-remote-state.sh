#!/usr/bin/env bash
set -Eeuo pipefail

cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

CI_ACCOUNT_ID=831559560923
PROFILE_NAME="Keboola-CI-KAC-Team-AWSAdministratorAccess"
CURRENT_ACCOUNT_ID=$(aws sts get-caller-identity --query "Account" --output text --profile ${PROFILE_NAME})
if [ "${CI_ACCOUNT_ID}" != "${CURRENT_ACCOUNT_ID}" ]; then
  echo "Currently configured AWS CLI account (${CURRENT_ACCOUNT_ID}) does not match account (${CI_ACCOUNT_ID})"
  echo "Use correct AWS CLI profile"
  exit 1;
fi

TERRAFORM_BACKEND_STACK_PREFIX=ci-go-cloud-encrypt
TERRAFORM_BACKEND_STACK_NAME="${TERRAFORM_BACKEND_STACK_PREFIX}-terraform"

aws cloudformation deploy --stack-name "${TERRAFORM_BACKEND_STACK_NAME}" \
  --parameter-overrides \
    "BackendPrefix=${TERRAFORM_BACKEND_STACK_PREFIX}" \
  --template-file ./resources/aws.yaml \
  --no-fail-on-empty-changeset \
  --capabilities CAPABILITY_NAMED_IAM \
  --output text \
  --profile ${PROFILE_NAME}

cat <<EOF > s3.tfbackend
region = "$(aws cloudformation describe-stacks --stack-name "${TERRAFORM_BACKEND_STACK_NAME}" --query "Stacks[0].Outputs[?OutputKey=='Region'].OutputValue" --output text --profile ${PROFILE_NAME})"
dynamodb_table = "$(aws cloudformation describe-stacks --stack-name "${TERRAFORM_BACKEND_STACK_NAME}" --query "Stacks[0].Outputs[?OutputKey=='LockDynamoDBTableName'].OutputValue" --output text --profile ${PROFILE_NAME})"
bucket = "$(aws cloudformation describe-stacks --stack-name "${TERRAFORM_BACKEND_STACK_NAME}" --query "Stacks[0].Outputs[?OutputKey=='S3BucketName'].OutputValue" --output text --profile ${PROFILE_NAME})"
key = "terraform.tfstate"
encrypt = true
EOF
