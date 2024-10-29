package cloudencrypt

import (
	"context"
	"time"

	"github.com/dgraph-io/ristretto/v2"
)

// CacheEncryptor wraps another Encryptor and adds a caching mechanism.
type CacheEncryptor struct {
	encryptor Encryptor
	cache     *ristretto.Cache[[]byte, []byte]
	ttl       time.Duration
}

func NewCacheEncryptor(ctx context.Context, encryptor Encryptor, ttl time.Duration, config *ristretto.Config[[]byte, []byte]) (*CacheEncryptor, error) {
	cache, err := ristretto.NewCache(config)
	if err != nil {
		return nil, err
	}

	return &CacheEncryptor{
		encryptor: encryptor,
		cache:     cache,
		ttl:       ttl,
	}, nil
}

func (encryptor *CacheEncryptor) Encrypt(ctx context.Context, value []byte, metadata ...MetadataKV) ([]byte, error) {
	encryptedValue, err := encryptor.encryptor.Encrypt(ctx, value, metadata...)
	if err != nil {
		return nil, err
	}

	encryptor.cache.SetWithTTL(encryptedValue, value, 1, encryptor.ttl)

	return encryptedValue, nil
}

func (encryptor *CacheEncryptor) Decrypt(ctx context.Context, encryptedValue []byte, metadata ...MetadataKV) ([]byte, error) {
	cached, ok := encryptor.cache.Get(encryptedValue)
	if ok {
		return cached, nil
	}

	decrypted, err := encryptor.encryptor.Decrypt(ctx, encryptedValue, metadata...)
	if err != nil {
		return nil, err
	}

	encryptor.cache.SetWithTTL(encryptedValue, decrypted, 1, encryptor.ttl)

	return decrypted, nil
}

func (encryptor *CacheEncryptor) Close() error {
	return encryptor.encryptor.Close()
}
