[![GitHub Actions](https://github.com/keboola/go-cloud-encrypt/actions/workflows/push.yml/badge.svg)](https://github.com/keboola/go-cloud-encrypt/actions/workflows/push.yml)

# Cloud Encrypt

Library designed for symmetric encryption using AWS, GCP or Azure services.

## Usage

It is recommended to use the `AESWrapEncryptor` which encrypts the given input using `AESEncryptor` and then the secret
key using the given encryptor. You may also want to use `CachedEncryptor` to avoid decrypting the same value repeatedly.

```go
package main

import (
	"context"
	"os"
	"time"

	"github.com/dgraph-io/ristretto/v2"
	"github.com/keboola/go-cloud-encrypt/pkg/cloudencrypt"
)

func CreateEncryptor(ctx context.Context) (*cloudencrypt.Encryptor, error) {
	config := &ristretto.Config[[]byte, []byte]{
		NumCounters: 1e6,
		MaxCost:     1 << 20,
		BufferItems: 64,
	}

	cache, err := ristretto.NewCache(config)
	if err != nil {
		return nil, err
	}

	var encryptor cloudencrypt.Encryptor

	encryptor, err = cloudencrypt.NewGCPEncryptor(ctx, os.Getenv("GCP_KMS_KEY_ID"))
	if err != nil {
		return nil, err
	}

	encryptor, err = cloudencrypt.NewAESWrapEncryptor(ctx, encryptor)
	if err != nil {
		return nil, err
	}

	encryptor, err = cloudencrypt.NewCachedEncryptor(ctx, encryptor, time.Hour, cache)
	if err != nil {
		return nil, err
	}

	return encryptor, nil
}
```

## Development

Prerequisites:
* configured access to cloud providers
    * installed Azure CLI `az` (and run `az login`)
    * installed AWS CLI `aws` (and run `aws configure --profile YOUR_AWS_PROFILE_NAME`)
    * installed GCP CLI `gcloud` (and run `gcloud auth login` or `gcloud auth application-default login`)
* installed `terraform` (https://www.terraform.io) and `jq` (https://stedolan.github.io/jq) to setup local env
* installed `docker` to run & develop the app

```bash
export NAME_PREFIX= # your name/nickname to make your resource unique & recognizable
export AWS_PROFILE= # your AWS profile name e.g. Keboola-Dev-KAC-Team-AWSAdministratorAccess

cat <<EOF > ./provisioning/local/terraform.tfvars
name_prefix = "${NAME_PREFIX}"
EOF

terraform -chdir=./provisioning/local init -backend-config="key=go-cloud-encrypt/${NAME_PREFIX}.tfstate"
terraform -chdir=./provisioning/local apply
./provisioning/local/update-env.sh

docker compose run --rm dev
```

Important: The existing encryptors should not be changed in a way that they would no longer be able to decrypt values
encrypted using the older version. If you need to make such change, add it as a new encryptor instead.

## License

MIT licensed, see [LICENSE](./LICENSE) file.
