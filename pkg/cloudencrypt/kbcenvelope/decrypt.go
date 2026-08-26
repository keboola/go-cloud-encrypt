package kbcenvelope

import (
	"context"
	"errors"
	"fmt"

	"github.com/keboola/go-cloud-encrypt/pkg/cloudencrypt"
)

// Clients bundles the cloud KMS clients and key IDs used to build the per-cloud crypto engines
// DecryptCipherText dispatches to. A zero-value field means that cloud isn't configured; a
// cipher text for an unconfigured cloud is rejected with ErrProviderNotConfigured rather than
// dereferencing a nil client.
type Clients struct {
	AWS      KMSClient
	AWSKeyID string

	Azure AKVClient

	GCP        GKMSClient
	GCPKeyName string
}

// ErrUnknownPrefix is returned (wrapped) when a value isn't a recognised KBC:: cipher text.
var ErrUnknownPrefix = errors.New("unknown cipher prefix")

// ErrProviderNotConfigured is returned (wrapped) when a cipher text's cloud has no client in Clients.
var ErrProviderNotConfigured = errors.New("cloud provider not configured")

// ErrLegacyCipherFormat is returned (wrapped) for one of the pre-KBC:: legacy prefixes, which
// no Encryptor has ever implemented.
var ErrLegacyCipherFormat = errors.New("legacy cipher format is no longer supported")

// DecryptCipherText decrypts a full "KBC::<Scope><Cloud>::"-prefixed cipher text. It resolves
// the prefix to a (cloud, scope) pair via PrefixTable, builds that scope's Metadata from
// stackID and in, and decrypts using clients' matching cloud engine — composing this package's
// per-cloud Encryptor with cloudencrypt's own Base64Encryptor and PrefixEncryptor for the wire
// format, rather than each caller re-implementing prefix stripping and base64 decoding.
func DecryptCipherText(ctx context.Context, cipherText string, clients Clients, stackID string, in ScopeInputs) (string, error) {
	for _, legacy := range LegacyPrefixes {
		if len(cipherText) >= len(legacy) && cipherText[:len(legacy)] == legacy {
			return "", fmt.Errorf("legacy cipher format %s is no longer supported: %w", legacy, ErrLegacyCipherFormat)
		}
	}

	prefix, info, ok := LookupPrefix(cipherText)
	if !ok {
		return "", fmt.Errorf("unrecognised cipher prefix in %q: %w", truncate(cipherText, 32), ErrUnknownPrefix)
	}

	engine, err := clients.engineFor(info.Provider, prefix)
	if err != nil {
		return "", err
	}

	base64Decryptor, err := cloudencrypt.NewBase64Encryptor(engine)
	if err != nil {
		return "", err
	}

	prefixDecryptor, err := cloudencrypt.NewPrefixEncryptor(base64Decryptor, []byte(prefix))
	if err != nil {
		return "", err
	}

	plaintext, err := prefixDecryptor.Decrypt(ctx, []byte(cipherText), MetadataForScope(info.Scope, stackID, in))
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

func (c Clients) engineFor(p Provider, prefix string) (cloudencrypt.Encryptor, error) {
	var configured bool

	var engine cloudencrypt.Encryptor

	switch p {
	case ProviderAWS:
		configured = c.AWS != nil
		if configured {
			engine = NewAWSEncryptor(c.AWS, c.AWSKeyID)
		}
	case ProviderAzure:
		configured = c.Azure != nil
		if configured {
			engine = NewAzureEncryptor(c.Azure)
		}
	case ProviderGoogle:
		configured = c.GCP != nil
		if configured {
			engine = NewGCPEncryptor(c.GCP, c.GCPKeyName)
		}
	case ProviderUnknown:
		return nil, fmt.Errorf("unknown cipher prefix: %s: %w", prefix, ErrUnknownPrefix)
	}

	if !configured {
		return nil, fmt.Errorf("cipher prefix %s belongs to a cloud provider this stack is not configured for: %w", prefix, ErrProviderNotConfigured)
	}

	return engine, nil
}

// truncate keeps error messages bounded: cipherText is attacker-controlled (it arrives inside a
// user's configuration value) and can be arbitrarily long.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}

	return s[:n] + "..."
}
