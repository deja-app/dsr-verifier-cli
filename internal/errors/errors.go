// Package dsrerrors defines auditor-friendly typed errors for verification failures.
//
// Every failure carries three things:
//   - Class: a stable machine-readable identifier (safe to match in scripts)
//   - HumanMessage: why the failure matters in plain language
//   - TechnicalDetail: algorithm names, computed values, expected values
//
// Error messages are written for a CPA or compliance professional reading an
// audit report — not for the developer who built the CLI.
package dsrerrors

// ErrorClass is a stable, machine-readable identifier for a failure category.
// Callers may switch on these values; they will not change within a major version.
type ErrorClass string

const (
	// SignatureInvalid means the cryptographic signature does not verify against
	// the provided public key and the receipt's canonical signed payload. The receipt
	// may have been produced by a different key, or the signed fields were modified
	// after issuance.
	SignatureInvalid ErrorClass = "signature_invalid"

	// KeyAuthorityMismatch means the signing_key_id embedded in the receipt does
	// not match the key_id declared in the provided public key file. The auditor
	// is using the wrong key for this receipt.
	KeyAuthorityMismatch ErrorClass = "key_authority_mismatch"

	// HashChainBroken means the prior_hash on a receipt does not equal the
	// SHA-256 of the previous receipt's canonical payload. The receipts in this
	// bundle do not form a consistent signed chain — one may have been substituted
	// or the bundle is missing entries.
	HashChainBroken ErrorClass = "hash_chain_broken"

	// MalformedReceipt means the receipt file could not be parsed as a valid
	// DSR receipt. The file may be corrupt, truncated, or not a DSR receipt.
	MalformedReceipt ErrorClass = "malformed_receipt"

	// MalformedCausalRef means one or more causal artifact references in the
	// receipt contain malformed values (e.g. invalid PR URL or commit SHA format).
	MalformedCausalRef ErrorClass = "malformed_causal_ref"

	// KeyParseError means the public key file could not be parsed. Supported
	// formats: PKIX PEM ("BEGIN PUBLIC KEY"), base64 raw Ed25519 (32 bytes).
	KeyParseError ErrorClass = "key_parse_error"

	// UnsupportedAlgorithm means the receipt declares a signing algorithm that
	// this verifier does not implement. Supported: sha256-legacy, ed25519-v1,
	// rsa-pss-sha256, ecdsa-sha256.
	UnsupportedAlgorithm ErrorClass = "unsupported_algorithm"

	// ContentHashMismatch is kept for backward compatibility with bundle output
	// that may reference this class; it is no longer produced by the single-receipt
	// verifier (the ExternalDSREnvelope format does not carry a separate content_hash).
	ContentHashMismatch ErrorClass = "content_hash_mismatch"
)

// VerificationError is a typed, auditor-friendly verification failure.
type VerificationError struct {
	// Class is the stable machine-readable error category.
	Class ErrorClass `json:"error_class"`

	// HumanMessage explains why the failure matters in plain language.
	// Written for a CPA or compliance professional, not a developer.
	HumanMessage string `json:"human_message"`

	// TechnicalDetail provides algorithm names, computed values, and expected
	// values so the failure is reproducible and self-documenting.
	TechnicalDetail string `json:"technical_detail"`
}

func (e *VerificationError) Error() string { return e.HumanMessage }

// New constructs a VerificationError.
func New(class ErrorClass, human, detail string) *VerificationError {
	return &VerificationError{
		Class:           class,
		HumanMessage:    human,
		TechnicalDetail: detail,
	}
}

// ParseErrorDetail carries line and column information for JSON parse failures.
type ParseErrorDetail struct {
	Offset int64
	Msg    string
}
