package dsr

import (
	"encoding/json"
	"fmt"
)

// CanonicalContent returns the canonical byte representation of a receipt's
// content field. This is the input to SHA-256 when computing content_hash,
// and the input to ed25519 when constructing the signed payload.
//
// Canonical form: the content object re-serialized with lexicographically
// sorted keys at every level, compact (no extra whitespace). Go's
// encoding/json marshals map keys in sorted order as of Go 1.12, so
// unmarshaling to interface{} and re-marshaling produces the canonical form.
//
// This definition must match the canonical serialization used by the Déjà
// signing infrastructure. Both sides sort object keys lexicographically and
// produce compact JSON with no trailing newline.
func CanonicalContent(content json.RawMessage) ([]byte, error) {
	if len(content) == 0 {
		return nil, fmt.Errorf("content is empty")
	}
	var v interface{}
	if err := json.Unmarshal(content, &v); err != nil {
		return nil, fmt.Errorf("content is not valid JSON: %w", err)
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("failed to re-serialize content: %w", err)
	}
	return b, nil
}

// CanonicalRvSignedPayload returns the bytes that are covered by the signature
// on an RV (verification run) receipt. The RV canonical form is a distinct
// 10-field payload matching rv-receipt-canonical.ts on the server.
//
// Algorithm (v1-legacy, mirrors rv-receipt-canonical.ts):
//  1. Map camelCase TypeScript fields to their snake_case wire names.
//  2. Construct a Go struct with explicit json tags — encoding/json marshals
//     struct fields in declaration order, which must be alphabetical by key
//     to match the TypeScript Object.keys().sort() step.
//  3. Return compact JSON.Marshal of the struct (no extra whitespace).
//
// Covered fields (JSON keys in Unicode code-point / alphabetical order):
//
//	checks_passed, issued_at, receipt_id, receipts_attested_count, rv_type,
//	vault_id, verification_completed_at, verification_mode,
//	verification_run_id, verification_started_at
//
// issued_at, verification_started_at, and verification_completed_at must be
// ISO 8601 strings as stored on the receipt (no reformatting is applied).
//
// This function must produce byte-identical output to canonicaliseRvReceipt()
// in rv-receipt-canonical.ts. The shared test vector at
// docs/dsr/rv-canonical-vector.json pins both sides to the same bytes.
func CanonicalRvSignedPayload(r *Receipt) ([]byte, error) {
	// Struct field declaration order determines JSON key order in encoding/json.
	// Fields are listed in strict Unicode code-point / alphabetical order so that
	// the output matches the TypeScript sort (a < b ? -1 : a > b ? 1 : 0).
	payload := struct {
		ChecksPassed            []string `json:"checks_passed"`
		IssuedAt                string   `json:"issued_at"`
		ReceiptID               string   `json:"receipt_id"`
		ReceiptsAttestedCount   int      `json:"receipts_attested_count"`
		RvType                  string   `json:"rv_type"`
		VaultID                 string   `json:"vault_id"`
		VerificationCompletedAt string   `json:"verification_completed_at"`
		VerificationMode        string   `json:"verification_mode"`
		VerificationRunID       string   `json:"verification_run_id"`
		VerificationStartedAt   string   `json:"verification_started_at"`
	}{
		ChecksPassed:            r.ChecksPassed,
		IssuedAt:                r.RvIssuedAt(),
		ReceiptID:               r.ID,
		ReceiptsAttestedCount:   r.ReceiptsAttestedCount,
		RvType:                  r.RvType,
		VaultID:                 r.VaultID,
		VerificationCompletedAt: r.VerificationCompletedAt,
		VerificationMode:        r.VerificationMode,
		VerificationRunID:       r.VerificationRunID,
		VerificationStartedAt:   r.VerificationStartedAt,
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize RV signed payload: %w", err)
	}
	return b, nil
}

// RvIssuedAt returns the issued_at string for use in the RV canonical payload.
//
// Priority:
//  1. IssuedAtRaw — the verbatim string from the receipt JSON, preserving
//     millisecond precision (e.g. "2026-01-01T00:04:24.000Z"). This is the
//     byte-exact value used by canonicaliseRvReceipt() in rv-receipt-canonical.ts.
//  2. Fallback: reformat from the parsed time.Time. This loses sub-second
//     precision but is used for receipts constructed in tests without a raw string.
func (r *Receipt) RvIssuedAt() string {
	if r.IssuedAtRaw != "" {
		return r.IssuedAtRaw
	}
	// "2006-01-02T15:04:05.000Z07:00" produces millisecond-precision with UTC "Z" suffix.
	return r.IssuedAt.UTC().Format("2006-01-02T15:04:05.000Z07:00")
}

// CanonicalSignedPayload returns the bytes that are covered by the ed25519
// signature. The signed payload binds together the receipt's identity fields
// and its content_hash, so that any modification to id, version, type,
// vault_id, issued_at, or content causes signature verification to fail.
//
// Construction: sorted-key JSON of the six covered fields, compact.
//
// Covered fields (JSON keys in sort order):
//
//	content_hash, id, issued_at, signing_algorithm, signing_key_id, type,
//	vault_id, version
//
// issued_at is serialized as an RFC3339 UTC timestamp ("Z" suffix).
func CanonicalSignedPayload(r *Receipt) ([]byte, error) {
	// Construct only the covered fields. Use a struct with explicit JSON tags
	// so the key names are stable regardless of field order in the source.
	payload := struct {
		ContentHash      string `json:"content_hash"`
		ID               string `json:"id"`
		IssuedAt         string `json:"issued_at"`
		SigningAlgorithm  string `json:"signing_algorithm"`
		SigningKeyID     string `json:"signing_key_id"`
		Type             string `json:"type"`
		VaultID          string `json:"vault_id"`
		Version          string `json:"version"`
	}{
		ContentHash:      r.ContentHash,
		ID:               r.ID,
		IssuedAt:         r.IssuedAt.UTC().Format("2006-01-02T15:04:05Z"),
		SigningAlgorithm:  r.SigningAlgorithm,
		SigningKeyID:     r.SigningKeyID,
		Type:             r.Type,
		VaultID:          r.VaultID,
		Version:          r.Version,
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize signed payload: %w", err)
	}
	return b, nil
}
