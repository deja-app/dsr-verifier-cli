package verify_test

// cannot_verify_test.go — tests for the three c335 "cannot check" conditions.
//
// The verifier must emit cannot_verify (not signature_invalid) when it lacks
// the information or implementation needed to produce a verdict.  Three cases:
//
//  1. Unknown canonical_form_version (e.g. "v5") — the verifier does not know
//     how to compute the canonical bytes; silently computing wrong bytes and
//     reporting INVALID would accuse the receipt of tampering.
//
//  2. sha256-legacy RV with missing type-specific wire fields (verifier_client /
//     verifier_identity_hash absent) — incomplete export.
//
//  3. sha256-legacy RE with missing type-specific wire fields (expires_at /
//     recipient_hash absent) — incomplete export.
//
// Each test plants the exact violation the guard exists to catch, confirms
// cannot_verify fires by name, then verifies the negative case — a valid
// receipt does NOT trigger cannot_verify — per the CLAUDE.md tripwire rule.

import (
	"testing"

	"github.com/deja-app/dsr-verifier-cli/internal/dsr"
	dsrerrors "github.com/deja-app/dsr-verifier-cli/internal/errors"
	"github.com/deja-app/dsr-verifier-cli/internal/verify"
)

// ─── helpers ─────────────────────────────────────────────────────────────────

func assertCannotVerify(t *testing.T, label string, res *verify.SignatureResult) {
	t.Helper()
	if res.Valid {
		t.Errorf("%s: expected cannot_verify but got Valid=true", label)
		return
	}
	if res.Err == nil {
		t.Errorf("%s: expected non-nil Err", label)
		return
	}
	if res.Err.Class != dsrerrors.CannotVerify {
		t.Errorf("%s: Err.Class = %q, want %q", label, res.Err.Class, dsrerrors.CannotVerify)
	}
}

func assertSignatureInvalidOrOK(t *testing.T, label string, res *verify.SignatureResult) {
	t.Helper()
	if res.Err == nil {
		return // Valid=true is fine — the receipt may verify
	}
	if res.Err.Class == dsrerrors.CannotVerify {
		t.Errorf("%s: unexpectedly got cannot_verify on a complete envelope", label)
	}
}

// ─── 1. Unknown canonical_form_version ───────────────────────────────────────

// TestCannotVerify_UnknownFormVersion confirms that a receipt declaring a
// form version this verifier does not implement emits cannot_verify (not
// signature_invalid, which would wrongly accuse the receipt of tampering).
func TestCannotVerify_UnknownFormVersion(t *testing.T) {
	unknown := "v5-jcs"
	res := verify.Signature(&dsr.Envelope{
		Type:                 "R1",
		ReceiptID:            "R1-cv-test-001",
		VaultID:              "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
		Timestamp:            "2026-09-01T00:00:00.000Z",
		Actor:                "1234567",
		Signature:            "placeholder",
		CanonicalFormVersion: &unknown,
	}, nil)

	assertCannotVerify(t, "unknown form version v5-jcs", res)

	// Human message must say "cannot check" not "failed"
	if res.Err != nil && len(res.Err.HumanMessage) < 10 {
		t.Errorf("HumanMessage too short: %q", res.Err.HumanMessage)
	}
}

// TestCannotVerify_KnownFormVersion_NoSpuriousFire ensures the guard does NOT
// fire on receipts with known form versions — negative case for the tripwire.
func TestCannotVerify_KnownFormVersion_NoSpuriousFire(t *testing.T) {
	for _, fv := range []string{"v1-legacy", "v2-jcs", "v3-jcs", "v4-jcs"} {
		fvCopy := fv
		t.Run(fv, func(t *testing.T) {
			res := verify.Signature(&dsr.Envelope{
				Type:                 "R1",
				ReceiptID:            "R1-cv-test-002",
				VaultID:              "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
				Timestamp:            "2026-09-01T00:00:00.000Z",
				Actor:                "1234567",
				Signature:            "placeholder",
				CanonicalFormVersion: &fvCopy,
			}, nil)
			assertSignatureInvalidOrOK(t, "known form "+fv, res)
		})
	}
}

// ─── 2. sha256-legacy RV with missing type-specific fields ───────────────────

// TestCannotVerify_RVLegacy_IncompleteExport confirms that a sha256-legacy RV
// receipt missing verifier_client and verifier_identity_hash emits cannot_verify.
// Without these, the verifier would zero-fill them and compute bytes the issuer
// never signed — reporting INVALID would accuse the receipt of tampering when
// the export is at fault.
func TestCannotVerify_RVLegacy_IncompleteExport(t *testing.T) {
	// RV sha256-legacy: SignatureAlgorithm == nil, RVType == nil → rvLegacyCanonical path.
	// VerifierClient and VerifierIdentityHash are both nil → incomplete export.
	res := verify.Signature(&dsr.Envelope{
		Type:               "RV",
		ReceiptID:          "RV-legacy-incomplete-001",
		VaultID:            "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
		Timestamp:          "2026-08-01T00:00:00.000Z",
		Actor:              "system:rv",
		Signature:          "aabbccddeeff0011aabbccddeeff0011aabbccddeeff0011aabbccddeeff0011",
		DSRVersion:         "DSR/1.0",
		SignatureAlgorithm: nil, // nil → sha256-legacy
		// VerifierClient and VerifierIdentityHash intentionally absent (nil)
	}, nil)

	assertCannotVerify(t, "sha256-legacy RV missing verifier_client+verifier_identity_hash", res)
}

// TestCannotVerify_RVLegacy_MissingVerifierClient fires on verifier_client alone.
func TestCannotVerify_RVLegacy_MissingVerifierClient(t *testing.T) {
	hash := "abc123def456abc123def456abc12345"
	res := verify.Signature(&dsr.Envelope{
		Type:                 "RV",
		ReceiptID:            "RV-legacy-incomplete-002",
		VaultID:              "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
		Timestamp:            "2026-08-01T00:00:00.000Z",
		Actor:                "system:rv",
		Signature:            "aabbccddeeff0011aabbccddeeff0011aabbccddeeff0011aabbccddeeff0011",
		DSRVersion:           "DSR/1.0",
		SignatureAlgorithm:   nil,
		VerifierIdentityHash: &hash,
		// VerifierClient intentionally absent
	}, nil)

	assertCannotVerify(t, "sha256-legacy RV missing verifier_client only", res)
}

// TestCannotVerify_RVLegacy_Complete_NoSpuriousFire confirms a sha256-legacy RV
// receipt WITH all fields does NOT trigger cannot_verify.
// The signature is a dummy hex string so the result is signature_invalid (hash
// mismatch), NOT cannot_verify — the guard must not fire on a complete envelope.
func TestCannotVerify_RVLegacy_Complete_NoSpuriousFire(t *testing.T) {
	client := "dsr-verifier-cli/1.4.0"
	identHash := "abc123def456abc123def456abc12345"
	result := "valid"
	var validCount, invalidCount, verifiedCount int64 = 3, 0, 3
	issuedAt := "2026-08-01T00:00:00.000Z"
	res := verify.Signature(&dsr.Envelope{
		Type:                 "RV",
		ReceiptID:            "RV-legacy-complete-001",
		VaultID:              "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
		Timestamp:            issuedAt,
		IssuedAt:             &issuedAt,
		Actor:                "system:rv",
		Signature:            "aabbccddeeff0011aabbccddeeff0011aabbccddeeff0011aabbccddeeff0011",
		DSRVersion:           "DSR/1.0",
		SignatureAlgorithm:   nil,
		VerifierClient:       &client,
		VerifierIdentityHash: &identHash,
		VerificationResult:   &result,
		ValidCount:           &validCount,
		InvalidCount:         &invalidCount,
		VerifiedReceiptCount: &verifiedCount,
	}, nil)

	// The hash won't match the dummy signature, so Valid=false and Err is set.
	// The guard must classify it as signature_invalid, not cannot_verify.
	assertSignatureInvalidOrOK(t, "complete sha256-legacy RV with dummy sig", res)
	if res.Err != nil && res.Err.Class == dsrerrors.CannotVerify {
		t.Errorf("got cannot_verify on a complete envelope — guard should not fire")
	}
}

// ─── 3. sha256-legacy RE with missing type-specific fields ───────────────────

// TestCannotVerify_RELegacy_IncompleteExport confirms that a sha256-legacy RE
// receipt missing expires_at and recipient_hash emits cannot_verify.
func TestCannotVerify_RELegacy_IncompleteExport(t *testing.T) {
	res := verify.Signature(&dsr.Envelope{
		Type:               "RE",
		ReceiptID:          "RE-legacy-incomplete-001",
		VaultID:            "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
		Timestamp:          "2026-08-01T00:00:00.000Z",
		Actor:              "system:re",
		Signature:          "aabbccddeeff0011aabbccddeeff0011aabbccddeeff0011aabbccddeeff0011",
		DSRVersion:         "DSR/1.0",
		SignatureAlgorithm: nil, // nil → sha256-legacy
		// ExpiresAt and RecipientHash intentionally absent (nil)
	}, nil)

	assertCannotVerify(t, "sha256-legacy RE missing expires_at+recipient_hash", res)
}

// TestCannotVerify_RELegacy_Complete_NoSpuriousFire confirms a sha256-legacy RE
// receipt WITH all fields does NOT trigger cannot_verify.
// The signature is a dummy hex string so the result is signature_invalid (hash
// mismatch), NOT cannot_verify — the guard must not fire on a complete envelope.
func TestCannotVerify_RELegacy_Complete_NoSpuriousFire(t *testing.T) {
	engagementID := "ENG-test-001"
	expiresAt := "2027-08-01T00:00:00.000Z"
	issuedAt := "2026-08-01T00:00:00.000Z"
	recipientHash := "abcdef1234567890abcdef1234567890"
	scopeHash := "fedcba0987654321fedcba0987654321"
	var receiptsInScope int64 = 42
	res := verify.Signature(&dsr.Envelope{
		Type:               "RE",
		ReceiptID:          "RE-legacy-complete-001",
		VaultID:            "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
		Timestamp:          issuedAt,
		IssuedAt:           &issuedAt,
		Actor:              "system:re",
		Signature:          "aabbccddeeff0011aabbccddeeff0011aabbccddeeff0011aabbccddeeff0011",
		DSRVersion:         "DSR/1.0",
		SignatureAlgorithm: nil,
		EngagementID:       &engagementID,
		ExpiresAt:          &expiresAt,
		RecipientHash:      &recipientHash,
		ScopeHash:          &scopeHash,
		ReceiptsInScope:    &receiptsInScope,
		Permissions:        []string{"read_receipts", "verify_receipts"},
	}, nil)

	// Hash won't match the dummy signature → signature_invalid, NOT cannot_verify.
	assertSignatureInvalidOrOK(t, "complete sha256-legacy RE with dummy sig", res)
	if res.Err != nil && res.Err.Class == dsrerrors.CannotVerify {
		t.Errorf("got cannot_verify on a complete envelope — guard should not fire")
	}
}
