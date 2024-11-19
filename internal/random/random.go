package random

import (
	"crypto/rand"

	"github.com/pkg/errors"
)

func Bytes(size int) ([]byte, error) {
	bytes := make([]byte, size)
	_, err := rand.Read(bytes)
	if err != nil {
		return nil, errors.Wrapf(err, "can't generate random bytes: %s", err.Error())
	}

	return bytes, err
}

func SecretKey() ([]byte, error) {
	return Bytes(32)
}
