package serialize_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keboola/go-cloud-encrypt/internal/random"
	"github.com/keboola/go-cloud-encrypt/internal/serialize"
)

func TestEncodeDecode(t *testing.T) {
	t.Parallel()

	secretKey, err := random.SecretKey()
	require.NoError(t, err)

	data := make(map[string][]byte)
	data["test"] = secretKey

	encoded, err := serialize.Serialize(data)
	require.NoError(t, err)
	assert.NotNil(t, encoded)

	decoded, err := serialize.Deserialize[map[string][]byte](encoded)
	require.NoError(t, err)
	assert.NotNil(t, decoded)

	assert.Equal(t, data, decoded)
}
