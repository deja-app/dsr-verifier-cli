package verify_test

// rv_test.go — End-to-end RV receipt verification tests.
//
// Tests cover:
//   1. Parse RV receipt (DSR/1.0 accepted)
//   2. Verify a real RV receipt signature (canonical form matches)
//   3. Tamper detection (flip a byte, fails)
//   4. Mixed bundle: standard R1 + RV receipts verify together
//   5. Canonical byte-match against the protocol test vector
//
// The test vector matches docs/dsr/rv-canonical-vector.json and the
// TypeScript test rv-canonical-vector.test.ts.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/deja-dev/dsr-verifier-cli/internal/dsr"
	dsrerrors "github.com/deja-dev/dsr-verifier-cli/internal/errors"
	"github.com/deja-dev/dsr-verifier-cli/internal/verify"
)

// ─────────────────────────────────────────────────────────────────────────────
// Fixtures
// ─────────────────────────────────────────────────────────────────────────────

const rvTestKeyID = "key_rv_test_2026q2"
const rvTestVaultID = "vault_01HWVLT0001"

// buildSignedRVReceipt constructs a complete, correctly-signed RV receipt.
// The signed payload uses CanonicalRvSignedPayload (the 10-field RV form).
func buildSignedRVReceipt(
	t *testing.T,
	priv ed25519.PrivateKey,
	keyID, vaultID string,
	receiptType string, // TypeRV, TypeRVi, or TypeRVf
) []byte {
	t.Helper()

	issuedAt := time.Date(2026, 5, 26, 0, 4, 24, 0, time.UTC)
	issuedAtStr := "2026-05-26T00:04:24.000Z"

	content := json.RawMessage(`{"anomalies":0,"scan_at":"2026-05-26T00:00:00.000Z"}`)
	sum := sha256.Sum256(content)
	contentHash := hex.EncodeToString(sum[:])

	rvTyp := "rv-f"
	if receiptType == dsr.TypeRVi {
		rvTyp = "rv-i"
	}

	r := &dsr.Receipt{
		ID:                      "rv_test_sig_001",
		Version:                 dsr.VersionRV,
		Type:                    receiptType,
		VaultID:                 vaultID,
		IssuedAt:                issuedAt,
		IssuedAtRaw:             issuedAtStr,
		Content:                 content,
		ContentHash:             contentHash,
		SigningKeyID:            keyID,
		SigningAlgorithm:        dsr.SigningAlgorithmED25519,
		ChecksPassed:            []string{"chain_integrity", "signature_validity", "content_hash", "key_authority", "cross_vault_isolation"},
		ReceiptsAttestedCount:   1250,
		RvType:                  rvTyp,
		VerificationRunID:       "run_01HWRUN0001",
		VerificationMode:        "full",
		VerificationStartedAt:   "2026-05-26T00:00:00.000Z",
		VerificationCompletedAt: "2026-05-26T00:04:23.000Z",
	}

	payload, err := dsr.CanonicalRvSignedPayload(r)
	if err != nil {
		t.Fatalf("CanonicalRvSignedPayload: %v", err)
	}

	sig := ed25519.Sign(priv, payload)

	full := map[string]interface{}{
		"id":                       "rv_test_sig_001",
		"version":                  dsr.VersionRV,
		"type":                     receiptType,
		"vault_id":                 vaultID,
		"issued_at":                issuedAtStr,
		"content":                  json.RawMessage(content),
		"content_hash":             contentHash,
		"signing_key_id":           keyID,
		"signing_algorithm":        dsr.SigningAlgorithmED25519,
		"signature":                hex.EncodeToString(sig),
		"checks_passed":            []string{"chain_integrity", "signature_validity", "content_hash", "key_authority", "cross_vault_isolation"},
		"receipts_attested_count":  1250,
		"rv_type":                  rvTyp,
		"verification_run_id":      "run_01HWRUN0001",
		"verification_mode":        "full",
		"verification_started_at":  "2026-05-26T00:00:00.000Z",
		"verification_completed_at": "2026-05-26T00:04:23.000Z",
	}

	b, err := json.Marshal(full)
	if err != nil {
		t.Fatalf("marshal RV receipt: %v", err)
	}
	return b
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 1: Parse RV receipt (DSR/1.0 accepted)
// ─────────────────────────────────────────────────────────────────────────────

func TestRVParseAccepted(t *testing.T) {
	pub, priv := newTestKey(t)
	keyPEM := marshalPublicKeyPEM(t, pub, rvTestKeyID)
	receiptJSON := buildSignedRVReceipt(t, priv, rvTestKeyID, rvTestVaultID, dsr.TypeRV)

	r, parseErr := dsr.Parse(receiptJSON)
	if parseErr != nil {
		t.Fatalf("Parse RV receipt: %v", parseErr)
	}
	if r.Version != dsr.VersionRV {
		t.Errorf("Version = %q, want %q", r.Version, dsr.VersionRV)
	}
	if r.Type != dsr.TypeRV {
		t.Errorf("Type = %q, want %q", r.Type, dsr.TypeRV)
	}
	_ = keyPEM
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 2: Verify a real RV receipt signature (canonical form matches server)
// ─────────────────────────────────────────────────────────────────────────────

func TestRVSignatureVerifies(t *testing.T) {
	pub, priv := newTestKey(t)
	keyPEM := marshalPublicKeyPEM(t, pub, rvTestKeyID)
	receiptJSON := buildSignedRVReceipt(t, priv, rvTestKeyID, rvTestVaultID, dsr.TypeRV)

	r, parseErr := dsr.Parse(receiptJSON)
	if parseErr != nil {
		t.Fatalf("Parse: %v", parseErr)
	}

	provided, keyErr := verify.ParsePublicKeyFile(keyPEM)
	if keyErr != nil {
		t.Fatalf("ParsePublicKeyFile: %v", keyErr)
	}

	authRes := verify.KeyAuthority(r, provided)
	assertValid(t, "KeyAuthority", authRes.Valid, authRes.Err)

	sigRes := verify.Signature(r, provided)
	assertValid(t, "RV Signature", sigRes.Valid, sigRes.Err)

	hashRes := verify.ContentHash(r)
	assertValid(t, "ContentHash", hashRes.Valid, hashRes.Err)

	causalRes := verify.CausalRefs(r)
	assertValid(t, "CausalRefs (RV skips)", causalRes.Valid, causalRes.Err)
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 3: Tamper detection — flip a byte in the signature → fails
// ─────────────────────────────────────────────────────────────────────────────

func TestRVTamperSignatureDetected(t *testing.T) {
	pub, priv := newTestKey(t)
	keyPEM := marshalPublicKeyPEM(t, pub, rvTestKeyID)
	receiptJSON := buildSignedRVReceipt(t, priv, rvTestKeyID, rvTestVaultID, dsr.TypeRV)

	// Flip the first byte of the signature.
	var raw map[string]json.RawMessage
	json.Unmarshal(receiptJSON, &raw)
	var sigHex string
	json.Unmarshal(raw["signature"], &sigHex)
	sigBytes, _ := hex.DecodeString(sigHex)
	sigBytes[0] ^= 0xFF
	raw["signature"], _ = json.Marshal(hex.EncodeToString(sigBytes))
	tampered, _ := json.Marshal(raw)

	r, parseErr := dsr.Parse(tampered)
	if parseErr != nil {
		t.Fatalf("Parse tampered receipt: %v", parseErr)
	}

	provided, _ := verify.ParsePublicKeyFile(keyPEM)
	sigRes := verify.Signature(r, provided)
	assertInvalid(t, "RV tampered Signature", sigRes.Valid, sigRes.Err, dsrerrors.SignatureInvalid)
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 4: Tamper an RV-specific field → signature fails (canonical form covers them)
// ─────────────────────────────────────────────────────────────────────────────

func TestRVTamperFieldDetected(t *testing.T) {
	pub, priv := newTestKey(t)
	keyPEM := marshalPublicKeyPEM(t, pub, rvTestKeyID)
	receiptJSON := buildSignedRVReceipt(t, priv, rvTestKeyID, rvTestVaultID, dsr.TypeRV)

	// Tamper: change receipts_attested_count from 1250 to 0.
	// The signature was computed over receipts_attested_count=1250 in the canonical payload.
	tamperedJSON := strings.Replace(string(receiptJSON),
		`"receipts_attested_count":1250`, `"receipts_attested_count":0`, 1)

	r, parseErr := dsr.Parse([]byte(tamperedJSON))
	if parseErr != nil {
		t.Fatalf("Parse tampered RV receipt: %v", parseErr)
	}

	provided, _ := verify.ParsePublicKeyFile(keyPEM)

	// Signature must fail — the canonical form uses receipts_attested_count.
	sigRes := verify.Signature(r, provided)
	assertInvalid(t, "RV field-tampered Signature", sigRes.Valid, sigRes.Err, dsrerrors.SignatureInvalid)
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 5: Mixed bundle — standard R1 + RV receipts verify correctly
// ─────────────────────────────────────────────────────────────────────────────

func TestMixedBundleR1AndRV(t *testing.T) {
	pub, priv := newTestKey(t)
	keyPEM := marshalPublicKeyPEM(t, pub, rvTestKeyID)

	// Build a standard R1 receipt.
	r1JSON := buildSignedReceipt(t, priv, rvTestKeyID, rvTestVaultID)

	// Build an RV receipt.
	rvJSON := buildSignedRVReceipt(t, priv, rvTestKeyID, rvTestVaultID, dsr.TypeRV)

	provided, keyErr := verify.ParsePublicKeyFile(keyPEM)
	if keyErr != nil {
		t.Fatalf("ParsePublicKeyFile: %v", keyErr)
	}

	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"R1", r1JSON},
		{"RV", rvJSON},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, parseErr := dsr.Parse(tc.data)
			if parseErr != nil {
				t.Fatalf("Parse %s: %v", tc.name, parseErr)
			}

			authRes := verify.KeyAuthority(r, provided)
			assertValid(t, tc.name+" KeyAuthority", authRes.Valid, authRes.Err)

			sigRes := verify.Signature(r, provided)
			assertValid(t, tc.name+" Signature", sigRes.Valid, sigRes.Err)

			hashRes := verify.ContentHash(r)
			assertValid(t, tc.name+" ContentHash", hashRes.Valid, hashRes.Err)
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 6: Protocol test vector canonical byte match.
//
// This test asserts that CanonicalRvSignedPayload produces the exact bytes
// stored in docs/dsr/rv-canonical-vector.json and the TypeScript vector test.
// Both sides pin to the same expected string.
// ─────────────────────────────────────────────────────────────────────────────

func TestRVCanonicalVectorByteMatch(t *testing.T) {
	// The expected canonical JSON matches the TypeScript test vector exactly.
	const expectedCanonical = `{"checks_passed":["chain_integrity","signature_validity","content_hash","key_authority","cross_vault_isolation"],"issued_at":"2026-05-26T00:04:24.000Z","receipt_id":"rv_01HWTEST0001","receipts_attested_count":1250,"rv_type":"rv-f","vault_id":"vault_01HWVLT0001","verification_completed_at":"2026-05-26T00:04:23.000Z","verification_mode":"full","verification_run_id":"run_01HWRUN0001","verification_started_at":"2026-05-26T00:00:00.000Z"}`

	issuedAt, err := time.Parse(time.RFC3339Nano, "2026-05-26T00:04:24.000Z")
	if err != nil {
		t.Fatalf("parse issued_at: %v", err)
	}

	r := &dsr.Receipt{
		ID:                      "rv_01HWTEST0001",
		Version:                 dsr.VersionRV,
		Type:                    dsr.TypeRVf,
		VaultID:                 "vault_01HWVLT0001",
		IssuedAt:                issuedAt,
		IssuedAtRaw:             "2026-05-26T00:04:24.000Z",
		ChecksPassed:            []string{"chain_integrity", "signature_validity", "content_hash", "key_authority", "cross_vault_isolation"},
		ReceiptsAttestedCount:   1250,
		RvType:                  "rv-f",
		VerificationRunID:       "run_01HWRUN0001",
		VerificationMode:        "full",
		VerificationStartedAt:   "2026-05-26T00:00:00.000Z",
		VerificationCompletedAt: "2026-05-26T00:04:23.000Z",
	}

	got, err := dsr.CanonicalRvSignedPayload(r)
	if err != nil {
		t.Fatalf("CanonicalRvSignedPayload: %v", err)
	}

	if string(got) != expectedCanonical {
		t.Errorf("canonical byte mismatch (does not match rv-canonical-vector.json)\ngot:  %s\nwant: %s", got, expectedCanonical)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 7: RV receipt round-trip via JSON — IssuedAtRaw is preserved
// ─────────────────────────────────────────────────────────────────────────────

func TestRVReceiptRoundTripPreservesIssuedAtRaw(t *testing.T) {
	pub, priv := newTestKey(t)
	keyPEM := marshalPublicKeyPEM(t, pub, rvTestKeyID)
	receiptJSON := buildSignedRVReceipt(t, priv, rvTestKeyID, rvTestVaultID, dsr.TypeRVf)

	r, parseErr := dsr.Parse(receiptJSON)
	if parseErr != nil {
		t.Fatalf("Parse: %v", parseErr)
	}

	// IssuedAtRaw must be the exact string from the JSON (with .000Z).
	if r.IssuedAtRaw != "2026-05-26T00:04:24.000Z" {
		t.Errorf("IssuedAtRaw = %q, want %q", r.IssuedAtRaw, "2026-05-26T00:04:24.000Z")
	}

	// Signature must verify — proving the round-trip canonical form is correct.
	provided, _ := verify.ParsePublicKeyFile(keyPEM)
	sigRes := verify.Signature(r, provided)
	assertValid(t, "RV-f round-trip Signature", sigRes.Valid, sigRes.Err)
}
