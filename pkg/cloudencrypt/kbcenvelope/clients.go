package kbcenvelope

import (
	"context"

	gcpkms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/googleapis/gax-go/v2"
)

// KMSClient is the subset of the AWS KMS client this package needs.
type KMSClient interface {
	Decrypt(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error)
}

// AKVClient is the subset of the Azure Key Vault secrets client this package needs.
type AKVClient interface {
	GetSecret(ctx context.Context, secretName string, version string, options *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error)
}

// GKMSClient is the subset of the Google Cloud KMS client this package needs.
type GKMSClient interface {
	Decrypt(ctx context.Context, req *kmspb.DecryptRequest, opts ...gax.CallOption) (*kmspb.DecryptResponse, error)
}

// Ensure the real SDK clients satisfy the interfaces above.
var (
	_ KMSClient  = (*kms.Client)(nil)
	_ AKVClient  = (*azsecrets.Client)(nil)
	_ GKMSClient = (*gcpkms.KeyManagementClient)(nil)
)
