package dsr_test

// rv_test.go — RV receipt tests: parse, canonical form, version acceptance.
//
// Test vector matches docs/dsr/rv-canonical-vector.json and the TypeScript
// test in packages/api/src/lib/integrity/__tests__/rv-canonical-vector.test.ts.

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/deja-dev/dsr-verifier-cli/internal/dsr"
	dsrerrors "github.com/deja-dev/dsr-verifier-cli/internal/errors"
)

// ─────────────────────────────────────────────────────────────────────────────
// Shared test helpers
// ─────────────────────────────────────────────────────────────────────────────

// validRVReceiptJSON is a complete DSR/1.0 RV receipt for parse tests.
// Signature and content_hash are placeholder hex values — parse tests
// do not verify cryptographic correctness.
const validRVReceiptJSON = `{
	"id": "rv_01HWTEST0001",
	"version": "DSR/1.0",
	"type": "RV",
	"vault_id": "vault_01HWVLT0001",
	"issued_at": "2026-05-26T00:04:24.000Z",
	"content": {"scan_at": "2026-05-26T00:00:00.000Z", "anomalies": 0},
	"content_hash": "4d8a2c9e7b3f1a2d4c5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c",
	"signing_key_id": "key_rv_test",
	"signing_algorithm": "ed25519",
	"signature": "b2e9c4a7f1d3e6a8b2e9c4a7f1d3e6a8b2e9c4a7f1d3e6a8b2e9c4a7f1d3e6a8b2e9c4a7f1d3e6a8b2e9c4a7f1d3e6a8b2e9c4a7f1d3e6a8b2e9c4a7f1d3e6a8",
	"checks_passed": ["chain_integrity","signature_validity","content_hash","key_authority","cross_vault_isolation"],
	"receipts_attested_count": 1250,
	"rv_type": "rv-f",
	"verification_run_id": "run_01HWRUN0001",
	"verification_mode": "full",
	"verification_started_at": "2026-05-26T00:00:00.000Z",
	"verification_completed_at": "2026-05-26T00:04:23.000Z"
}`

// ─────────────────────────────────────────────────────────────────────────────
// Test 1: Parse an RV receipt with DSR/1.0 — must be accepted.
// ─────────────────────────────────────────────────────────────────────────────

func TestParseRVReceiptDSR10Accepted(t *testing.T) {
	r, err := dsr.Parse([]byte(validRVReceiptJSON))
	if err != nil {
		t.Fatalf("Parse RV receipt with DSR/1.0: unexpected error: %v", err)
	}
	if r.Version != dsr.VersionRV {
		t.Errorf("Version = %q, want %q", r.Version, dsr.VersionRV)
	}
	if r.Type != dsr.TypeRV {
		t.Errorf("Type = %q, want %q", r.Type, dsr.TypeRV)
	}
	if r.ID != "rv_01HWTEST0001" {
		t.Errorf("ID = %q, want %q", r.ID, "rv_01HWTEST0001")
	}
	if r.VaultID != "vault_01HWVLT0001" {
		t.Errorf("VaultID = %q", r.VaultID)
	}
	if r.RvType != "rv-f" {
		t.Errorf("RvType = %q, want %q", r.RvType, "rv-f")
	}
	if r.ReceiptsAttestedCount != 1250 {
		t.Errorf("ReceiptsAttestedCount = %d, want 1250", r.ReceiptsAttestedCount)
	}
	if len(r.ChecksPassed) != 5 {
		t.Errorf("ChecksPassed len = %d, want 5", len(r.ChecksPassed))
	}
	if r.VerificationRunID != "run_01HWRUN0001" {
		t.Errorf("VerificationRunID = %q", r.VerificationRunID)
	}
	if r.VerificationMode != "full" {
		t.Errorf("VerificationMode = %q", r.VerificationMode)
	}
	if r.VerificationStartedAt != "2026-05-26T00:00:00.000Z" {
		t.Errorf("VerificationStartedAt = %q", r.VerificationStartedAt)
	}
	if r.VerificationCompletedAt != "2026-05-26T00:04:23.000Z" {
		t.Errorf("VerificationCompletedAt = %q", r.VerificationCompletedAt)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 2: RV receipt with DSR/1.0.1 must be rejected.
// ─────────────────────────────────────────────────────────────────────────────

func TestParseRVReceiptDSR101Rejected(t *testing.T) {
	input := strings.Replace(validRVReceiptJSON, `"version": "DSR/1.0"`, `"version": "DSR/1.0.1"`, 1)
	_, err := dsr.Parse([]byte(input))
	if err == nil {
		t.Fatal("expected error for RV receipt with DSR/1.0.1, got nil")
	}
	if err.Class != dsrerrors.MalformedReceipt {
		t.Errorf("error class = %q, want %q", err.Class, dsrerrors.MalformedReceipt)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 3: Standard receipt with DSR/1.0 must be rejected.
// ─────────────────────────────────────────────────────────────────────────────

func TestParseStandardReceiptDSR10Rejected(t *testing.T) {
	// validReceiptJSON has type R1 and version DSR/1.0.1. Change version to DSR/1.0.
	input := strings.Replace(validReceiptJSON, `"version": "DSR/1.0.1"`, `"version": "DSR/1.0"`, 1)
	_, err := dsr.Parse([]byte(input))
	if err == nil {
		t.Fatal("expected error for standard R1 receipt with DSR/1.0, got nil")
	}
	if err.Class != dsrerrors.MalformedReceipt {
		t.Errorf("error class = %q, want %q", err.Class, dsrerrors.MalformedReceipt)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 4: RV-i and RV-f types also accepted with DSR/1.0.
// ─────────────────────────────────────────────────────────────────────────────

func TestParseRViRVfTypesDSR10Accepted(t *testing.T) {
	for _, tc := range []struct {
		typ   string
		rvTyp string
	}{
		{dsr.TypeRVi, "rv-i"},
		{dsr.TypeRVf, "rv-f"},
	} {
		t.Run(tc.typ, func(t *testing.T) {
			input := strings.Replace(validRVReceiptJSON, `"type": "RV"`, `"type": "`+tc.typ+`"`, 1)
			input = strings.Replace(input, `"rv_type": "rv-f"`, `"rv_type": "`+tc.rvTyp+`"`, 1)
			r, err := dsr.Parse([]byte(input))
			if err != nil {
				t.Errorf("Parse %s with DSR/1.0: unexpected error: %v", tc.typ, err)
				return
			}
			if r.Type != tc.typ {
				t.Errorf("Type = %q, want %q", r.Type, tc.typ)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 5: Protocol test vector — CanonicalRvSignedPayload byte match.
//
// This is the authoritative byte-identity check. The expected canonical string
// matches docs/dsr/rv-canonical-vector.json and the TypeScript test in
// packages/api/src/lib/integrity/__tests__/rv-canonical-vector.test.ts.
//
// If this test fails, the implementation diverges from rv-receipt-canonical.ts.
// ─────────────────────────────────────────────────────────────────────────────

// EXPECTED_CANONICAL is the exact JSON output that canonicaliseRvReceipt()
// in rv-receipt-canonical.ts produces for the vector input.
const EXPECTED_CANONICAL = `{"checks_passed":["chain_integrity","signature_validity","content_hash","key_authority","cross_vault_isolation"],"issued_at":"2026-05-26T00:04:24.000Z","receipt_id":"rv_01HWTEST0001","receipts_attested_count":1250,"rv_type":"rv-f","vault_id":"vault_01HWVLT0001","verification_completed_at":"2026-05-26T00:04:23.000Z","verification_mode":"full","verification_run_id":"run_01HWRUN0001","verification_started_at":"2026-05-26T00:00:00.000Z"}`

func TestCanonicalRvSignedPayloadMatchesVector(t *testing.T) {
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

	if string(got) != EXPECTED_CANONICAL {
		t.Errorf("canonical payload mismatch\ngot:  %s\nwant: %s", got, EXPECTED_CANONICAL)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 6: IssuedAtRaw preserves milliseconds — no timestamp truncation.
// ─────────────────────────────────────────────────────────────────────────────

func TestRvCanonicalPreservesMilliseconds(t *testing.T) {
	// Parse an RV receipt whose issued_at has milliseconds.
	r, err := dsr.Parse([]byte(validRVReceiptJSON))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if r.IssuedAtRaw != "2026-05-26T00:04:24.000Z" {
		t.Errorf("IssuedAtRaw = %q, want %q", r.IssuedAtRaw, "2026-05-26T00:04:24.000Z")
	}

	payload, err := dsr.CanonicalRvSignedPayload(r)
	if err != nil {
		t.Fatalf("CanonicalRvSignedPayload: %v", err)
	}

	// The canonical payload must contain the raw issued_at with milliseconds.
	canonical := string(payload)
	if !strings.Contains(canonical, `"issued_at":"2026-05-26T00:04:24.000Z"`) {
		t.Errorf("canonical payload does not contain raw issued_at with .000Z: %s", canonical)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 7: checks_passed is serialized as a JSON array (not a string).
// ─────────────────────────────────────────────────────────────────────────────

func TestRvCanonicalCheckPassedIsArray(t *testing.T) {
	r, err := dsr.Parse([]byte(validRVReceiptJSON))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	payload, err := dsr.CanonicalRvSignedPayload(r)
	if err != nil {
		t.Fatalf("CanonicalRvSignedPayload: %v", err)
	}

	// Unmarshal and check that checks_passed is an array.
	var parsed map[string]json.RawMessage
	if err := json.Unmarshal(payload, &parsed); err != nil {
		t.Fatalf("unmarshal canonical: %v", err)
	}

	var checks []string
	if err := json.Unmarshal(parsed["checks_passed"], &checks); err != nil {
		t.Fatalf("checks_passed is not an array: %v", err)
	}
	if len(checks) != 5 {
		t.Errorf("checks_passed len = %d, want 5", len(checks))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 8: receipts_attested_count is a JSON number (not a string).
// ─────────────────────────────────────────────────────────────────────────────

func TestRvCanonicalReceiptsAttestedCountIsNumber(t *testing.T) {
	r, err := dsr.Parse([]byte(validRVReceiptJSON))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	payload, err := dsr.CanonicalRvSignedPayload(r)
	if err != nil {
		t.Fatalf("CanonicalRvSignedPayload: %v", err)
	}

	var parsed map[string]json.RawMessage
	if err := json.Unmarshal(payload, &parsed); err != nil {
		t.Fatalf("unmarshal canonical: %v", err)
	}

	// json.Number / float64 check — should unmarshal as number.
	var count json.Number
	if err := json.Unmarshal(parsed["receipts_attested_count"], &count); err != nil {
		t.Fatalf("receipts_attested_count is not a number: %v", err)
	}
	if count.String() != "1250" {
		t.Errorf("receipts_attested_count = %s, want 1250", count)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 9: Canonical output has exactly 10 keys in the expected sort order.
// ─────────────────────────────────────────────────────────────────────────────

func TestRvCanonical10FieldsSortOrder(t *testing.T) {
	r, err := dsr.Parse([]byte(validRVReceiptJSON))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	payload, err := dsr.CanonicalRvSignedPayload(r)
	if err != nil {
		t.Fatalf("CanonicalRvSignedPayload: %v", err)
	}

	// Use json.Decoder to preserve key order.
	dec := json.NewDecoder(strings.NewReader(string(payload)))
	dec.Token() // {
	var keys []string
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		if delim, ok := tok.(json.Delim); ok {
			if delim == '}' {
				break
			}
		}
		if key, ok := tok.(string); ok {
			keys = append(keys, key)
			// Skip the value token(s).
			var val json.RawMessage
			if err := dec.Decode(&val); err != nil {
				t.Fatalf("decode value for key %q: %v", key, err)
			}
		}
	}

	wantKeys := []string{
		"checks_passed",
		"issued_at",
		"receipt_id",
		"receipts_attested_count",
		"rv_type",
		"vault_id",
		"verification_completed_at",
		"verification_mode",
		"verification_run_id",
		"verification_started_at",
	}

	if len(keys) != len(wantKeys) {
		t.Errorf("got %d fields, want %d", len(keys), len(wantKeys))
	}
	for i, want := range wantKeys {
		if i >= len(keys) {
			break
		}
		if keys[i] != want {
			t.Errorf("field[%d] = %q, want %q", i, keys[i], want)
		}
	}
}
