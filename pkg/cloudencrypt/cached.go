package cloudencrypt

import (
	"context"
	"time"

	"github.com/dgraph-io/ristretto/v2"

	"github.com/keboola/go-cloud-encrypt/internal/metadata"
)

// CachedEncryptor wraps another Encryptor and adds a caching mechanism.
type CachedEncryptor struct {
	encryptor Encryptor
	cache     *ristretto.Cache[[]byte, []byte]
	ttl       time.Duration
}

func NewCachedEncryptor(encryptor Encryptor, ttl time.Duration, cache *ristretto.Cache[[]byte, []byte]) *CachedEncryptor {
	return &CachedEncryptor{
		encryptor: encryptor,
		cache:     cache,
		ttl:       ttl,
	}
}

func (encryptor *CachedEncryptor) Encrypt(ctx context.Context, plaintext []byte, meta Metadata) ([]byte, error) {
	key, err := metadata.Encode(meta)
	if err != nil {
		return nil, err
	}

	encryptedValue, err := encryptor.encryptor.Encrypt(ctx, plaintext, meta)
	if err != nil {
		return nil, err
	}

	key = append(key, encryptedValue...)

	encryptor.cache.SetWithTTL(key, plaintext, 1, encryptor.ttl)

	return encryptedValue, nil
}

func (encryptor *CachedEncryptor) Decrypt(ctx context.Context, ciphertext []byte, meta Metadata) ([]byte, error) {
	key, err := metadata.Encode(meta)
	if err != nil {
		return nil, err
	}

	key = append(key, ciphertext...)

	cached, ok := encryptor.cache.Get(key)
	if ok {
		return cached, nil
	}

	plaintext, err := encryptor.encryptor.Decrypt(ctx, ciphertext, meta)
	if err != nil {
		return nil, err
	}

	encryptor.cache.SetWithTTL(key, plaintext, 1, encryptor.ttl)

	return plaintext, nil
}

func (encryptor *CachedEncryptor) Close() error {
	return encryptor.encryptor.Close()
}
