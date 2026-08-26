package kbcenvelope

/*
#cgo LDFLAGS: -lz
#include <zlib.h>
#include <stdlib.h>

// zlibCompress compresses data using system libz (matches PHP's gzcompress).
int zlibCompress(unsigned char *source, unsigned long sourceLen, unsigned char *dest, unsigned long *destLen) {
    return compress(dest, destLen, source, sourceLen);
}
*/
import "C"

import (
	"errors"
	"fmt"
	"unsafe"
)

// zlibCompressPHPCompatible compresses data using system libz to match PHP's gzcompress()
// byte-for-byte. Go's standard compress/zlib writer adds sync-flush markers PHP's gzcompress()
// doesn't, which breaks the Google KMS AAD comparison (see gcp.go) since AAD must match the
// exact bytes the encryptor computed. CGO + libz is required here, not optional: this package
// needs a C toolchain and libz-dev available at build time for Google KMS support to work.
func zlibCompressPHPCompatible(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("cannot compress empty data")
	}

	sourceLen := C.ulong(len(data))
	// zlib documentation's overhead bound: sourceLen + (sourceLen>>12) + (sourceLen>>14) + (sourceLen>>25) + 13.
	destLen := C.ulong(len(data)*2 + 20)

	dest := make([]byte, destLen)

	ret := C.zlibCompress(
		(*C.uchar)(unsafe.Pointer(&data[0])),
		sourceLen,
		(*C.uchar)(unsafe.Pointer(&dest[0])),
		&destLen,
	)
	if ret != C.Z_OK {
		return nil, fmt.Errorf("zlib compression failed with code %d", ret)
	}

	return dest[:destLen], nil
}
