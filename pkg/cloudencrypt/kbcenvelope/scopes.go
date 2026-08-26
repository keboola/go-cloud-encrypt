package kbcenvelope

import "strings"

// Provider identifies which cloud KMS backs a KBC:: prefix.
type Provider int

const (
	ProviderUnknown Provider = iota
	ProviderAWS
	ProviderAzure
	ProviderGoogle
)

// Scope identifies which encryption-context shape a KBC:: prefix carries.
type Scope int

const (
	ScopeGeneric Scope = iota
	ScopeComponent
	ScopeProject
	ScopeConfiguration
	ScopeProjectWide
	ScopeBranchType
	ScopeBranchTypeConfiguration
	ScopeBranchTypeProjectWide
)

// Cipher prefix constants recognised by PHP keboola/object-encryptor's KBC:: envelope. Each of
// the 8 encryption-context scopes exists once per cloud (AWS KMS / Azure Key Vault / Google
// Cloud KMS) — 24 prefixes in total.
const (
	PrefixGenericKMS                 = "KBC::Secure::"
	PrefixComponentKMS               = "KBC::ComponentSecure::"
	PrefixProjectKMS                 = "KBC::ProjectSecure::"
	PrefixConfigurationKMS           = "KBC::ConfigSecure::"
	PrefixProjectWideKMS             = "KBC::ProjectWideSecure::"
	PrefixBranchTypeKMS              = "KBC::BranchTypeSecure::"
	PrefixBranchTypeConfigurationKMS = "KBC::BranchTypeConfigSecure::"
	PrefixBranchTypeProjectWideKMS   = "KBC::ProjectWideBranchTypeSecure::"

	PrefixGenericAKV                 = "KBC::SecureKV::"
	PrefixComponentAKV               = "KBC::ComponentSecureKV::"
	PrefixProjectAKV                 = "KBC::ProjectSecureKV::"
	PrefixConfigurationAKV           = "KBC::ConfigSecureKV::"
	PrefixProjectWideAKV             = "KBC::ProjectWideSecureKV::"
	PrefixBranchTypeAKV              = "KBC::BranchTypeSecureKV::"
	PrefixBranchTypeConfigurationAKV = "KBC::BranchTypeConfigSecureKV::"
	PrefixBranchTypeProjectWideAKV   = "KBC::ProjectWideBranchTypeSecureKV::"

	PrefixGenericGKMS                 = "KBC::SecureGKMS::"
	PrefixComponentGKMS               = "KBC::ComponentSecureGKMS::"
	PrefixProjectGKMS                 = "KBC::ProjectSecureGKMS::"
	PrefixConfigurationGKMS           = "KBC::ConfigSecureGKMS::"
	PrefixProjectWideGKMS             = "KBC::ProjectWideSecureGKMS::"
	PrefixBranchTypeGKMS              = "KBC::BranchTypeSecureGKMS::"
	PrefixBranchTypeConfigurationGKMS = "KBC::BranchTypeConfigSecureGKMS::"
	PrefixBranchTypeProjectWideGKMS   = "KBC::ProjectWideBranchTypeSecureGKMS::"
)

// Legacy cipher prefix constants. These are recognised so callers can reject them with a
// specific message; no Encryptor implements them, matching keboola/object-encryptor, which
// lists the same prefixes purely to avoid double-encrypting an already-encrypted value.
const (
	PrefixLegacyEncrypted          = "KBC::Encrypted=="
	PrefixLegacyComponentEncrypted = "KBC::ComponentEncrypted=="
	PrefixLegacyProjectEncrypted   = "KBC::ComponentProjectEncrypted=="
)

// LegacyPrefixes lists every legacy prefix, for callers that want to reject them explicitly
// before treating an unmatched value as merely "not a KBC:: cipher text".
var LegacyPrefixes = []string{PrefixLegacyEncrypted, PrefixLegacyComponentEncrypted, PrefixLegacyProjectEncrypted} //nolint:gochecknoglobals // read-only reference data, not mutable state

// PrefixInfo describes the cloud and encryption-context scope a KBC:: prefix carries.
type PrefixInfo struct {
	Provider Provider
	Scope    Scope
}

// PrefixTable maps each of the 24 recognised KBC:: prefixes to the cloud and encryption-context
// scope it carries. Any consumer decrypting Storage-API-produced secrets — not just
// keboola-operator — needs this same table; it is Keboola-platform knowledge, not specific to
// any one service.
var PrefixTable = map[string]PrefixInfo{ //nolint:gochecknoglobals // read-only reference data, not mutable state
	PrefixGenericKMS:                 {ProviderAWS, ScopeGeneric},
	PrefixComponentKMS:               {ProviderAWS, ScopeComponent},
	PrefixProjectKMS:                 {ProviderAWS, ScopeProject},
	PrefixConfigurationKMS:           {ProviderAWS, ScopeConfiguration},
	PrefixProjectWideKMS:             {ProviderAWS, ScopeProjectWide},
	PrefixBranchTypeKMS:              {ProviderAWS, ScopeBranchType},
	PrefixBranchTypeConfigurationKMS: {ProviderAWS, ScopeBranchTypeConfiguration},
	PrefixBranchTypeProjectWideKMS:   {ProviderAWS, ScopeBranchTypeProjectWide},

	PrefixGenericAKV:                 {ProviderAzure, ScopeGeneric},
	PrefixComponentAKV:               {ProviderAzure, ScopeComponent},
	PrefixProjectAKV:                 {ProviderAzure, ScopeProject},
	PrefixConfigurationAKV:           {ProviderAzure, ScopeConfiguration},
	PrefixProjectWideAKV:             {ProviderAzure, ScopeProjectWide},
	PrefixBranchTypeAKV:              {ProviderAzure, ScopeBranchType},
	PrefixBranchTypeConfigurationAKV: {ProviderAzure, ScopeBranchTypeConfiguration},
	PrefixBranchTypeProjectWideAKV:   {ProviderAzure, ScopeBranchTypeProjectWide},

	PrefixGenericGKMS:                 {ProviderGoogle, ScopeGeneric},
	PrefixComponentGKMS:               {ProviderGoogle, ScopeComponent},
	PrefixProjectGKMS:                 {ProviderGoogle, ScopeProject},
	PrefixConfigurationGKMS:           {ProviderGoogle, ScopeConfiguration},
	PrefixProjectWideGKMS:             {ProviderGoogle, ScopeProjectWide},
	PrefixBranchTypeGKMS:              {ProviderGoogle, ScopeBranchType},
	PrefixBranchTypeConfigurationGKMS: {ProviderGoogle, ScopeBranchTypeConfiguration},
	PrefixBranchTypeProjectWideGKMS:   {ProviderGoogle, ScopeBranchTypeProjectWide},
}

// LookupPrefix extracts the KBC:: prefix from cipherText (everything up to and including the
// second "::", e.g. "KBC::ComponentSecure::") and reports whether it's one of the 24 recognised
// prefixes. It does not check the legacy prefixes — those don't end in "::" at all, so they
// never match here; check LegacyPrefixes first if you need to report them specifically.
func LookupPrefix(cipherText string) (prefix string, info PrefixInfo, ok bool) {
	if !strings.HasPrefix(cipherText, "KBC::") {
		return "", PrefixInfo{}, false
	}

	rest := cipherText[len("KBC::"):]

	end := strings.Index(rest, "::")
	if end < 0 {
		return "", PrefixInfo{}, false
	}

	prefix = cipherText[:len("KBC::")+end+len("::")]

	info, ok = PrefixTable[prefix]

	return prefix, info, ok
}

// ScopeInputs carries the caller-supplied scope IDs a secret may be bound to. Which fields
// MetadataForScope actually reads depends on the Scope it's building for.
type ScopeInputs struct {
	ComponentID     string
	ProjectID       string
	ConfigurationID string
	BranchType      string
}

// MetadataForScope builds the exact encryption-context Metadata a scope binds, from the stack
// ID and whichever of in's fields that scope uses. ScopeGeneric carries no context at all — not
// even stackId — mirroring PHP keboola/object-encryptor: unscoped secrets are encrypted with no
// bound context. The Metadata returned must match byte-for-byte what the producer bound at
// encrypt time, or AWS/GCP KMS reject the decrypt and Azure's stored-secret check fails.
func MetadataForScope(s Scope, stackID string, in ScopeInputs) map[string]string {
	switch s {
	case ScopeGeneric:
		return nil
	case ScopeComponent:
		return map[string]string{"stackId": stackID, "componentId": in.ComponentID}
	case ScopeProject:
		return map[string]string{"stackId": stackID, "componentId": in.ComponentID, "projectId": in.ProjectID}
	case ScopeConfiguration:
		return map[string]string{
			"stackId": stackID, "componentId": in.ComponentID, "projectId": in.ProjectID, "configurationId": in.ConfigurationID,
		}
	case ScopeProjectWide:
		return map[string]string{"stackId": stackID, "projectId": in.ProjectID}
	case ScopeBranchType:
		return map[string]string{"stackId": stackID, "componentId": in.ComponentID, "projectId": in.ProjectID, "branchType": in.BranchType}
	case ScopeBranchTypeConfiguration:
		return map[string]string{
			"stackId": stackID, "componentId": in.ComponentID, "projectId": in.ProjectID,
			"configurationId": in.ConfigurationID, "branchType": in.BranchType,
		}
	case ScopeBranchTypeProjectWide:
		return map[string]string{"stackId": stackID, "projectId": in.ProjectID, "branchType": in.BranchType}
	default:
		return nil
	}
}
