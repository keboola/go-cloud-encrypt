package encode

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/keboola/go-cloud-encrypt/internal/random"
)

func TestEncodeDecode(t *testing.T) {
	t.Parallel()

	secretKey, err := random.SecretKey()
	assert.NoError(t, err)

	data := make(map[string][]byte)
	data["test"] = secretKey

	encoded, err := Encode(data)
	assert.NoError(t, err)
	assert.NotNil(t, encoded)

	decoded, err := Decode[map[string][]byte](encoded)
	assert.NoError(t, err)
	assert.NotNil(t, decoded)

	assert.Equal(t, data, decoded)
}
