package verify_test

// rv_fixtures_test.go — RV-i and RV-f fixture round-trip tests.
//
// These tests generate RV receipt + key pairs on-the-fly and verify them
// through the full parse → canonical → signature pipeline.

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/deja-dev/dsr-verifier-cli/internal/dsr"
	"github.com/deja-dev/dsr-verifier-cli/internal/verify"
)

// generateRVFixture creates an RV receipt + ed25519 key fixture in dir.
// receiptType is TypeRVi or TypeRVf; rvTyp is "rv-i" or "rv-f".
func generateRVFixture(t *testing.T, dir, receiptType, rvTyp, verificationMode string, receiptsCount int) (receiptPath, keyPath string) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}

	const keyID = "key_rv_fixture_2026"
	const vaultID = "vlt_fixture_rv"
	const receiptID = "rv_fixture_001"

	// Build content.
	content := json.RawMessage(`{"anomalies":0,"scan_at":"2026-05-01T00:00:00.000Z"}`)
	sum := sha256.Sum256(content)
	contentHash := hex.EncodeToString(sum[:])

	// The issued_at string with milliseconds — preserved verbatim in canonical form.
	// Use IssuedAtRaw rather than time.Time to avoid reformatting dropping ".000Z".
	const issuedAtStr = "2026-05-01T00:01:00.000Z"

	r := &dsr.Receipt{
		ID:                      receiptID,
		Version:                 dsr.VersionRV,
		Type:                    receiptType,
		VaultID:                 vaultID,
		IssuedAtRaw:             issuedAtStr,
		Content:                 content,
		ContentHash:             contentHash,
		SigningKeyID:             keyID,
		SigningAlgorithm:         dsr.SigningAlgorithmED25519,
		ChecksPassed:             []string{"chain_integrity", "signature_validity", "content_hash", "key_authority"},
		ReceiptsAttestedCount:    receiptsCount,
		RvType:                   rvTyp,
		VerificationRunID:        "run_fixture_001",
		VerificationMode:         verificationMode,
		VerificationStartedAt:    "2026-05-01T00:00:00.000Z",
		VerificationCompletedAt:  "2026-05-01T00:00:55.000Z",
	}

	payload, err := dsr.CanonicalRvSignedPayload(r)
	if err != nil {
		t.Fatalf("CanonicalRvSignedPayload: %v", err)
	}

	sig := ed25519.Sign(priv, payload)

	// Write receipt JSON.
	receipt := map[string]interface{}{
		"id":                       receiptID,
		"version":                  dsr.VersionRV,
		"type":                     receiptType,
		"vault_id":                 vaultID,
		"issued_at":                issuedAtStr,
		"content":                  content,
		"content_hash":             contentHash,
		"signing_key_id":           keyID,
		"signing_algorithm":        dsr.SigningAlgorithmED25519,
		"signature":                hex.EncodeToString(sig),
		"checks_passed":            []string{"chain_integrity", "signature_validity", "content_hash", "key_authority"},
		"receipts_attested_count":  receiptsCount,
		"rv_type":                  rvTyp,
		"verification_run_id":      "run_fixture_001",
		"verification_mode":        verificationMode,
		"verification_started_at":  "2026-05-01T00:00:00.000Z",
		"verification_completed_at": "2026-05-01T00:00:55.000Z",
	}

	receiptBytes, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		t.Fatalf("marshal receipt: %v", err)
	}

	receiptPath = filepath.Join(dir, receiptType+"_receipt.dsr")
	if err := os.WriteFile(receiptPath, receiptBytes, 0644); err != nil {
		t.Fatalf("WriteFile receipt: %v", err)
	}

	// Write public key PEM.
	keyPath = filepath.Join(dir, receiptType+"_key.pub")
	writeFixturePEMKey(t, keyPath, pub, keyID)

	return receiptPath, keyPath
}

// ─────────────────────────────────────────────────────────────────────────────
// Test: RV-i fixture round-trip
// ─────────────────────────────────────────────────────────────────────────────

func TestRViFixtureRoundtrip(t *testing.T) {
	dir := t.TempDir()
	receiptPath, keyPath := generateRVFixture(t, dir, dsr.TypeRVi, "rv-i", "incremental", 100)

	receiptData, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatalf("ReadFile receipt: %v", err)
	}
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("ReadFile key: %v", err)
	}

	r, parseErr := dsr.Parse(receiptData)
	if parseErr != nil {
		t.Fatalf("Parse RV-i fixture: %v", parseErr)
	}
	if r.Type != dsr.TypeRVi {
		t.Errorf("Type = %q, want %q", r.Type, dsr.TypeRVi)
	}
	if r.Version != dsr.VersionRV {
		t.Errorf("Version = %q, want %q", r.Version, dsr.VersionRV)
	}

	provided, keyErr := verify.ParsePublicKeyFile(keyData)
	if keyErr != nil {
		t.Fatalf("ParsePublicKeyFile (RV-i): %v", keyErr)
	}

	if res := verify.KeyAuthority(r, provided); !res.Valid {
		t.Errorf("KeyAuthority: %v", res.Err)
	}
	if res := verify.Signature(r, provided); !res.Valid {
		t.Errorf("Signature: %v", res.Err)
	}
	if res := verify.ContentHash(r); !res.Valid {
		t.Errorf("ContentHash: %v", res.Err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Test: RV-f fixture round-trip
// ─────────────────────────────────────────────────────────────────────────────

func TestRVfFixtureRoundtrip(t *testing.T) {
	dir := t.TempDir()
	receiptPath, keyPath := generateRVFixture(t, dir, dsr.TypeRVf, "rv-f", "full", 1250)

	receiptData, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatalf("ReadFile receipt: %v", err)
	}
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("ReadFile key: %v", err)
	}

	r, parseErr := dsr.Parse(receiptData)
	if parseErr != nil {
		t.Fatalf("Parse RV-f fixture: %v", parseErr)
	}
	if r.Type != dsr.TypeRVf {
		t.Errorf("Type = %q, want %q", r.Type, dsr.TypeRVf)
	}

	provided, keyErr := verify.ParsePublicKeyFile(keyData)
	if keyErr != nil {
		t.Fatalf("ParsePublicKeyFile (RV-f): %v", keyErr)
	}

	if res := verify.KeyAuthority(r, provided); !res.Valid {
		t.Errorf("KeyAuthority: %v", res.Err)
	}
	if res := verify.Signature(r, provided); !res.Valid {
		t.Errorf("Signature: %v", res.Err)
	}
	if res := verify.ContentHash(r); !res.Valid {
		t.Errorf("ContentHash: %v", res.Err)
	}
}
