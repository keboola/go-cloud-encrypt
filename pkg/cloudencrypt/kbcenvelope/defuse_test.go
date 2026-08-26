package kbcenvelope

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// validDefuseKeyHex builds a well-formed Defuse Key: hex(header:4 + key:32 + checksum:32),
// checksum = SHA256(header + key), matching decodeDefuseKey's expected format exactly.
func validDefuseKeyHex(t *testing.T, keyByte byte) string {
	t.Helper()

	header := []byte{0xDE, 0xF0, 0x00, 0x00}
	key := make([]byte, 32)

	for i := range key {
		key[i] = keyByte
	}

	checksum := sha256.Sum256(append(append([]byte{}, header...), key...))

	return hex.EncodeToString(append(append(append([]byte{}, header...), key...), checksum[:]...))
}

func TestDecodeDefuseKey_Valid(t *testing.T) {
	t.Parallel()

	encoded := validDefuseKeyHex(t, 0x42)

	key, err := decodeDefuseKey(encoded)
	require.NoError(t, err)
	assert.Len(t, key, 32)
	assert.Equal(t, byte(0x42), key[0])
}

// A Defuse Key is documented as exactly 68 decoded bytes; extra trailing bytes must be
// rejected, not silently truncated away.
func TestDecodeDefuseKey_RejectsTrailingBytes(t *testing.T) {
	t.Parallel()

	encoded := validDefuseKeyHex(t, 0x42) + hex.EncodeToString([]byte{0xAA, 0xBB})

	_, err := decodeDefuseKey(encoded)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "wrong length")
}

func TestDecodeDefuseKey_RejectsShortInput(t *testing.T) {
	t.Parallel()

	_, err := decodeDefuseKey(hex.EncodeToString([]byte{0xDE, 0xF0, 0x00, 0x00}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "wrong length")
}
