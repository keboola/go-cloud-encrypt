package serialize

import (
	"bytes"
	"compress/gzip"
	"encoding/gob"

	"github.com/pkg/errors"
)

func Serialize(data any) ([]byte, error) {
	var buffer bytes.Buffer

	// Gzip compress
	writer := gzip.NewWriter(&buffer)

	// gob encode
	err := gob.NewEncoder(writer).Encode(data)
	if err != nil {
		return nil, errors.Wrapf(err, "gob encoder failed: %s", err.Error())
	}

	err = writer.Close()
	if err != nil {
		return nil, errors.Wrapf(err, "can't close gzip writer: %s", err.Error())
	}

	return buffer.Bytes(), nil
}

func Deserialize[T any](data []byte) (T, error) {
	var decoded T

	// Gzip uncompress
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return decoded, errors.Wrapf(err, "can't create gzip reader: %s", err.Error())
	}

	defer reader.Close()

	// gob decode
	err = gob.NewDecoder(reader).Decode(&decoded)
	if err != nil {
		return decoded, errors.Wrapf(err, "gob decoder failed: %s", err.Error())
	}

	return decoded, nil
}
