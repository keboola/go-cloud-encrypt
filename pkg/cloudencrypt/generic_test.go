package cloudencrypt_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/keboola/go-cloud-encrypt/internal/random"
	"github.com/keboola/go-cloud-encrypt/pkg/cloudencrypt"
)

type myStruct struct {
	Number int
	Text   string
}

func TestGenericEncryptor(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	secretKey, err := random.SecretKey()
	assert.NoError(t, err)

	encryptor, err := cloudencrypt.NewNativeEncryptor(secretKey)
	assert.NoError(t, err)

	myStructEncryptor := cloudencrypt.NewGenericEncryptor[myStruct](encryptor)

	meta := cloudencrypt.Metadata{}
	meta["metakey"] = "metavalue"

	data := myStruct{
		Number: 42,
		Text:   "Lorem ipsum",
	}

	ciphertext, err := myStructEncryptor.Encrypt(ctx, data, meta)
	assert.NoError(t, err)

	_, err = myStructEncryptor.Decrypt(ctx, ciphertext, cloudencrypt.Metadata{})
	assert.ErrorContains(t, err, "cipher: message authentication failed")

	decrypted, err := myStructEncryptor.Decrypt(ctx, ciphertext, meta)
	assert.NoError(t, err)

	assert.Equal(t, data, decrypted)
}
