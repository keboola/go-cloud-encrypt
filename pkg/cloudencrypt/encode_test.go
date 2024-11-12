package cloudencrypt

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncodeDecode(t *testing.T) {
	t.Parallel()

	secretKey, err := generateSecretKey()
	assert.NoError(t, err)

	data := make(map[string][]byte)
	data["test"] = secretKey

	encoded, err := encode(data)
	assert.NoError(t, err)
	assert.NotNil(t, encoded)

	decoded, err := decode[map[string][]byte](encoded)
	assert.NoError(t, err)
	assert.NotNil(t, decoded)

	assert.Equal(t, data, decoded)
}
