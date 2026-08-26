//go:build !cgo

package kbcenvelope

import "errors"

// ErrCGORequired is returned by zlibCompressPHPCompatible in a build without CGO. Only GCP's
// AAD construction (see gcp.go) needs byte-exact PHP gzcompress() compatibility; the AWS and
// Azure encryptors never call this, so a CGO-disabled build can still use them.
var ErrCGORequired = errors.New("kbcenvelope: Google Cloud KMS support requires CGO (a C toolchain and libz-dev) to reproduce PHP's gzcompress() byte-for-byte; rebuild with CGO_ENABLED=1, or use AWSEncryptor/AzureEncryptor instead")

func zlibCompressPHPCompatible(_ []byte) ([]byte, error) {
	return nil, ErrCGORequired
}
