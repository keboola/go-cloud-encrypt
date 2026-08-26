// Package kbcenvelope implements the KBC:: cipher-text envelope produced and consumed by
// PHP's keboola/object-encryptor: a scope+cloud prefix (e.g. "KBC::ComponentSecure::") over
// base64(zlib(phpserialize([encryptedPayload, encryptedKey]))), with the payload itself
// encrypted using the "Defuse" (defuse/php-encryption) AES-256-CTR+HMAC scheme and the
// per-value key wrapped by AWS KMS, Azure Key Vault, or Google Cloud KMS.
//
// Each cloud is exposed as a plain cloudencrypt.Encryptor operating on the bytes between the
// "KBC::<Scope><Cloud>::" prefix and its base64 encoding — callers compose it with
// cloudencrypt.Base64Encryptor and cloudencrypt.PrefixEncryptor/MultiplexEncryptor for the
// full wire format, and supply the scope (component/project/configuration/branch-type/...)
// as the Metadata passed to Encrypt/Decrypt.
//
// This package is decrypt-only for now: Encrypt returns ErrEncryptNotImplemented on every
// cloud. The PHP producer (Storage API / Connection) is the only writer of the 24 existing
// KBC::...Secure...:: prefixes; a caller that wants to write its own envelope should mint a
// new, unclaimed prefix and use it, once Encrypt is implemented.
package kbcenvelope

import "errors"

// ErrEncryptNotImplemented is returned by every Encryptor in this package. The envelope's
// producer today is PHP's keboola/object-encryptor; this package only needs to read it.
var ErrEncryptNotImplemented = errors.New("kbcenvelope: Encrypt is not implemented yet (this package only decrypts the PHP object-encryptor envelope)")

// BackendError marks a failure of the remote KMS / Key Vault / Cloud KMS call, as opposed to
// a local, deterministic step (envelope decode, encryption-context verification, or AES).
// Callers use this position-based classification (backend vs. local) to distinguish an
// infrastructure failure from a data/config failure without inspecting provider error codes,
// and errors.As still reaches the wrapped Cause for transient-vs-terminal classification.
type BackendError struct {
	Cause error
}

func (e *BackendError) Error() string {
	if e.Cause == nil {
		return "kbcenvelope: backend error"
	}

	return e.Cause.Error()
}

func (e *BackendError) Unwrap() error {
	return e.Cause
}
