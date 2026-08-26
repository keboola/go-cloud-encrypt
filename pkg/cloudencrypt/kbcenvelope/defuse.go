package kbcenvelope

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// decryptDefuse decrypts data encrypted by the defuse/php-encryption PHP library. Despite the
// legacy Go port's name for this function, the format is AES-256-CTR + a separate HMAC, not
// AES-GCM. Wire format: [HEADER:4][SALT:32][IV:16][CIPHERTEXT][HMAC:32].
func decryptDefuse(encryptedData, masterKey []byte) ([]byte, error) {
	if len(masterKey) != 32 {
		return nil, errors.New("key must be 32 bytes for AES-256")
	}

	// Minimum size: 4 (header) + 32 (salt) + 16 (IV) + 0 (ciphertext) + 32 (HMAC).
	if len(encryptedData) < 84 {
		return nil, fmt.Errorf("encrypted data too short (min 84 bytes, got %d)", len(encryptedData))
	}

	header := encryptedData[0:4]
	salt := encryptedData[4:36]
	iv := encryptedData[36:52]
	ciphertext := encryptedData[52 : len(encryptedData)-32]
	expectedHMAC := encryptedData[len(encryptedData)-32:]

	expectedHeader := []byte{0xDE, 0xF5, 0x02, 0x00} // Defuse format version 2
	if !bytes.Equal(header, expectedHeader) {
		return nil, fmt.Errorf("invalid Defuse header: got %x, expected %x", header, expectedHeader)
	}

	encKey, err := deriveKeyHKDF(masterKey, salt, []byte("DefusePHP|V2|KeyForEncryption"), 32)
	if err != nil {
		return nil, fmt.Errorf("failed to derive encryption key: %w", err)
	}

	authKey, err := deriveKeyHKDF(masterKey, salt, []byte("DefusePHP|V2|KeyForAuthentication"), 32)
	if err != nil {
		return nil, fmt.Errorf("failed to derive authentication key: %w", err)
	}

	dataToVerify := encryptedData[:len(encryptedData)-32]
	if !verifyHMAC(dataToVerify, expectedHMAC, authKey) {
		return nil, errors.New("HMAC verification failed")
	}

	plaintext, err := decryptAES256CTR(ciphertext, encKey, iv)
	if err != nil {
		return nil, fmt.Errorf("AES-CTR decryption failed: %w", err)
	}

	return plaintext, nil
}

func deriveKeyHKDF(masterKey, salt, info []byte, keyLen int) ([]byte, error) {
	r := hkdf.New(sha256.New, masterKey, salt, info)

	key := make([]byte, keyLen)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}

	return key, nil
}

func verifyHMAC(data, expectedHMAC, key []byte) bool {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	computedHMAC := h.Sum(nil)

	return hmac.Equal(computedHMAC, expectedHMAC)
}

func decryptAES256CTR(ciphertext, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	stream := cipher.NewCTR(block, iv)
	plaintext := make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)

	return plaintext, nil
}

// decodeDefuseKey decodes a Defuse Key from its ASCII-safe hex string format:
// hex([header:4][key:32][checksum:32]). Returns the raw 32-byte encryption key.
func decodeDefuseKey(encodedKey string) ([]byte, error) {
	decoded, err := hex.DecodeString(encodedKey)
	if err != nil {
		return nil, fmt.Errorf("invalid hex encoding: %w", err)
	}

	if len(decoded) != 68 {
		return nil, fmt.Errorf("encoded key has wrong length: expected exactly 68 bytes, got %d", len(decoded))
	}

	header := decoded[0:4]
	keyBytes := decoded[4:36]
	checksum := decoded[36:68]

	expectedHeader := []byte{0xDE, 0xF0, 0x00, 0x00} // Defuse Key format version
	if !bytes.Equal(header, expectedHeader) {
		return nil, fmt.Errorf("invalid Defuse Key header: got %x, expected %x", header, expectedHeader)
	}

	computedChecksum := sha256.Sum256(decoded[0:36])
	if !bytes.Equal(checksum, computedChecksum[:]) {
		return nil, errors.New("checksum verification failed")
	}

	return keyBytes, nil
}
