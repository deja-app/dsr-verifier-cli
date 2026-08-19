package dsr_test

// canonical_golden_test.go — golden vector tests for all DSR receipt canonical forms.
//
// Each vector pins fixed inputs → expected canonical bytes → expected SHA-256 hex.
// These vectors are cross-checked against the TypeScript server implementation
// (packages/api/src/utils/__tests__/canonical-golden-vectors.test.ts in the wallow
// monorepo). Both suites must agree byte-for-byte or a canonical drift has occurred.
//
// H-CLI-CANONICAL resolution: this file is the CI gate. Any change to a
// canonicalisation function that alters output for an existing receipt type
// will fail here before it reaches signature tests in production.
//
// To add a new optional field: add a new "full" vector for the affected type.
// Do NOT change existing vectors — they represent the byte contract for receipts
// already on disk in production.

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/deja-app/dsr-verifier-cli/internal/dsr"
)

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func strPtr(s string) *string { return &s }
func boolPtr(b bool) *bool    { return &b }
func int64Ptr(n int64) *int64 { return &n }

// ─── RG governance canonical — 9-field SHA-256 ────────────────────────────────

// rgMinimalEnvelope returns the fixed test envelope for RG golden vectors.
func rgMinimalEnvelope() *dsr.Envelope {
	priorStateHash := strings.Repeat("1", 64)
	newStateHash := strings.Repeat("a", 64)
	changeType := "source_control_connected:github"
	issuedAt := "2026-01-01T00:00:00.000Z"
	return &dsr.Envelope{
		DSRVersion:     "DSR/1.0",
		Type:           dsr.TypeRG,
		ReceiptID:      "RG-00000000-0000-0000-0000-000000000001",
		OrganizationID: "aaaabbbb-cccc-dddd-eeee-ffffaaaabbbb",
		Actor:          "system:onboarding",
		Origin:         "production",
		Signature:      "placeholder",
		IssuedAt:       &issuedAt,
		ChangeType:     &changeType,
		PriorStateHash: &priorStateHash,
		NewStateHash:   &newStateHash,
	}
}

func TestGolden_RG_CanonicalBytes(t *testing.T) {
	e := rgMinimalEnvelope()
	canonical, err := dsr.CanonicalPayload(e)
	if err != nil {
		t.Fatalf("CanonicalPayload: %v", err)
	}

	// Field order: actor, change_type, issued_at, new_state_hash, organization_id,
	//              prior_state_hash, receipt_id, type, version
	want := `{"actor":"system:onboarding","change_type":"source_control_connected:github",` +
		`"issued_at":"2026-01-01T00:00:00.000Z",` +
		`"new_state_hash":"` + strings.Repeat("a", 64) + `",` +
		`"organization_id":"aaaabbbb-cccc-dddd-eeee-ffffaaaabbbb",` +
		`"prior_state_hash":"` + strings.Repeat("1", 64) + `",` +
		`"receipt_id":"RG-00000000-0000-0000-0000-000000000001",` +
		`"type":"RG","version":"DSR/1.0"}`

	if canonical != want {
		t.Errorf("canonical mismatch\n got: %s\nwant: %s", canonical, want)
	}
	if len(canonical) != 430 {
		t.Errorf("canonical length = %d, want 430", len(canonical))
	}
}

func TestGolden_RG_SHA256(t *testing.T) {
	e := rgMinimalEnvelope()
	canonical, err := dsr.CanonicalPayload(e)
	if err != nil {
		t.Fatalf("CanonicalPayload: %v", err)
	}
	const wantHash = "d0ebfaeb46acafa7db8a23128754e57b53c37805177da1cfd43def9e846efd2e"
	if got := sha256Hex(canonical); got != wantHash {
		t.Errorf("SHA-256\n got: %s\nwant: %s", got, wantHash)
	}
}

func TestGolden_RG_ExcludesVaultID(t *testing.T) {
	e := rgMinimalEnvelope()
	canonical, err := dsr.CanonicalPayload(e)
	if err != nil {
		t.Fatalf("CanonicalPayload: %v", err)
	}
	if strings.Contains(canonical, "vault_id") {
		t.Error("RG canonical form must not contain vault_id; governance receipts are org-scoped")
	}
}

func TestGolden_RG_ExcludesPriorHash(t *testing.T) {
	// prior_hash is storage-level chain linkage, not part of the signed canonical form.
	priorHash := "someprevhash"
	e := rgMinimalEnvelope()
	e.PriorHash = &priorHash
	canonical, err := dsr.CanonicalPayload(e)
	if err != nil {
		t.Fatalf("CanonicalPayload: %v", err)
	}
	if strings.Contains(canonical, "prior_hash") {
		t.Error("prior_hash must not appear in RG canonical form; it is storage-level linkage only")
	}
	// Same canonical bytes regardless of prior_hash value
	e2 := rgMinimalEnvelope()
	canonical2, _ := dsr.CanonicalPayload(e2)
	if canonical != canonical2 {
		t.Error("canonical bytes must not change when prior_hash is set or absent")
	}
}

// ─── Confirmation RG canonical — "confirmation-rg-v1" ed25519-v1 ─────────────
//
// Confirmation RG receipts (R1L_CONFIRMED / R1L_REJECTED) use an 8-field form
// with confirmed_receipt_id instead of prior_state_hash + new_state_hash.
// They are dispatched by ConfirmedReceiptID != nil before governanceCanonical.
//
// Mirror of canonicaliseConfirmationRgReceipt() in
// packages/api/src/utils/canonical-receipt.ts.

func confirmationRGEnvelope() *dsr.Envelope {
	cfv := "confirmation-rg-v1"
	algo := "ed25519-v1"
	kid := "deja-managed-v1"
	changeType := "R1L_CONFIRMED"
	confirmedID := "R1L-00000000-0000-4000-8000-000000000001"
	issuedAt := "2026-08-01T00:00:00.000Z"
	return &dsr.Envelope{
		DSRVersion:           "DSR/1.0",
		Type:                 dsr.TypeRG,
		ReceiptID:            "RG-00000000-0000-4000-8000-000000000001",
		OrganizationID:       "aaaabbbb-cccc-dddd-eeee-ffffaaaabbbb",
		Actor:                "user-uuid-reviewer",
		Origin:               "staging",
		Signature:            "placeholder",
		IssuedAt:             &issuedAt,
		ChangeType:           &changeType,
		ConfirmedReceiptID:   &confirmedID,
		CanonicalFormVersion: &cfv,
		SignatureAlgorithm:   &algo,
		SigningKeyID:         &kid,
	}
}

func TestGolden_ConfirmationRG_CanonicalBytes(t *testing.T) {
	e := confirmationRGEnvelope()
	canonical, err := dsr.CanonicalPayload(e)
	if err != nil {
		t.Fatalf("CanonicalPayload: %v", err)
	}

	// Field order (Unicode sort):
	//   actor, change_type, confirmed_receipt_id, issued_at, organization_id,
	//   receipt_id, type, version
	want := `{"actor":"user-uuid-reviewer","change_type":"R1L_CONFIRMED",` +
		`"confirmed_receipt_id":"R1L-00000000-0000-4000-8000-000000000001",` +
		`"issued_at":"2026-08-01T00:00:00.000Z",` +
		`"organization_id":"aaaabbbb-cccc-dddd-eeee-ffffaaaabbbb",` +
		`"receipt_id":"RG-00000000-0000-4000-8000-000000000001",` +
		`"type":"RG","version":"DSR/1.0"}`

	if canonical != want {
		t.Errorf("canonical mismatch\n got: %s\nwant: %s", canonical, want)
	}
	if len(canonical) != 309 {
		t.Errorf("canonical length = %d, want 309", len(canonical))
	}
}

func TestGolden_ConfirmationRG_SHA256(t *testing.T) {
	e := confirmationRGEnvelope()
	canonical, err := dsr.CanonicalPayload(e)
	if err != nil {
		t.Fatalf("CanonicalPayload: %v", err)
	}
	const wantHash = "a4968935b5a1405b04dd9d33862daa287255016bb15b80e62d4242eca89610cf"
	if got := sha256Hex(canonical); got != wantHash {
		t.Errorf("SHA-256\n got: %s\nwant: %s", got, wantHash)
	}
}

func TestGolden_ConfirmationRG_ExcludesStateHashes(t *testing.T) {
	e := confirmationRGEnvelope()
	canonical, err := dsr.CanonicalPayload(e)
	if err != nil {
		t.Fatalf("CanonicalPayload: %v", err)
	}
	for _, excluded := range []string{"prior_state_hash", "new_state_hash", "vault_id", "prior_hash"} {
		if strings.Contains(canonical, excluded) {
			t.Errorf("confirmation RG canonical must not contain %q", excluded)
		}
	}
}

func TestGolden_ConfirmationRG_Rejected_DispatchRegression(t *testing.T) {
	// Standard RG (no ConfirmedReceiptID) must still use governanceCanonical.
	// This guards the dispatch: adding ConfirmedReceiptID must not change the
	// canonical path for existing receipts without it.
	e := rgMinimalEnvelope()
	if e.ConfirmedReceiptID != nil {
		t.Fatal("rgMinimalEnvelope must not have ConfirmedReceiptID set")
	}
	canonical, err := dsr.CanonicalPayload(e)
	if err != nil {
		t.Fatalf("standard RG CanonicalPayload: %v", err)
	}
	// Standard RG canonical contains prior_state_hash — proof it used governanceCanonical
	if !strings.Contains(canonical, "prior_state_hash") {
		t.Error("standard RG canonical must contain prior_state_hash (governanceCanonical path)")
	}
}

func TestGolden_ConfirmationRG_RejectedVariant_CanonicalBytes(t *testing.T) {
	// R1L_REJECTED uses the same 8-field form; only change_type differs.
	cfv := "confirmation-rg-v1"
	algo := "ed25519-v1"
	kid := "deja-managed-v1"
	changeType := "R1L_REJECTED"
	confirmedID := "R1L-00000000-0000-4000-8000-000000000001"
	issuedAt := "2026-08-01T00:00:00.000Z"
	e := &dsr.Envelope{
		DSRVersion:           "DSR/1.0",
		Type:                 dsr.TypeRG,
		ReceiptID:            "RG-00000000-0000-4000-8000-000000000002",
		OrganizationID:       "aaaabbbb-cccc-dddd-eeee-ffffaaaabbbb",
		Actor:                "user-uuid-reviewer",
		Origin:               "staging",
		Signature:            "placeholder",
		IssuedAt:             &issuedAt,
		ChangeType:           &changeType,
		ConfirmedReceiptID:   &confirmedID,
		CanonicalFormVersion: &cfv,
		SignatureAlgorithm:   &algo,
		SigningKeyID:         &kid,
	}
	canonical, err := dsr.CanonicalPayload(e)
	if err != nil {
		t.Fatalf("CanonicalPayload: %v", err)
	}
	if !strings.Contains(canonical, `"change_type":"R1L_REJECTED"`) {
		t.Errorf("R1L_REJECTED canonical must contain change_type=R1L_REJECTED; got: %s", canonical)
	}
	if !strings.Contains(canonical, `"confirmed_receipt_id"`) {
		t.Errorf("R1L_REJECTED canonical must contain confirmed_receipt_id; got: %s", canonical)
	}
}

// ─── R1 attribution canonical — v1-legacy sha256-legacy ──────────────────────

func TestGolden_R1_Minimal_CanonicalBytes(t *testing.T) {
	// 9-field minimal: no optional fields. Pre-C3 receipt shape.
	errorClass := (*string)(nil)
	missingField := (*string)(nil)
	_ = errorClass
	_ = missingField

	e := &dsr.Envelope{
		DSRVersion:  "DSR/1.0",
		Type:        dsr.TypeR1,
		ReceiptID:   "rcpt-minimal",
		VaultID:     "vlt-test",
		Timestamp:   "2026-01-01T00:00:00.000Z",
		Actor:       "actor@example.com",
		Origin:      "github",
		Signature:   "placeholder",
		CCSScore:    strPtr("0.8750"),
		Confidence:  strPtr("HIGH"),
		IssuedAt:    strPtr("2026-01-01T00:00:00.000Z"),
		Matched:     strPtr("true"),
		PRNumber:    int64Ptr(42),
		Repository:  strPtr("acme-corp/payments"),
		ServiceZone: strPtr("zone-prod-1"),
		// ErrorClass and MissingField absent → null in canonical
	}

	canonical, err := dsr.CanonicalPayload(e)
	if err != nil {
		t.Fatalf("CanonicalPayload: %v", err)
	}

	// Field order: ccs_score, confidence, error_class, issued_at, matched,
	//              missing_field, pr_number, repository, service_zone
	want := `{"ccs_score":"0.8750","confidence":"HIGH","error_class":null,` +
		`"issued_at":"2026-01-01T00:00:00.000Z","matched":"true","missing_field":null,` +
		`"pr_number":42,"repository":"acme-corp/payments","service_zone":"zone-prod-1"}`

	if canonical != want {
		t.Errorf("canonical mismatch\n got: %s\nwant: %s", canonical, want)
	}
	if len(canonical) != 216 {
		t.Errorf("canonical length = %d, want 216", len(canonical))
	}
}

func TestGolden_R1_Minimal_SHA256(t *testing.T) {
	e := &dsr.Envelope{
		DSRVersion:  "DSR/1.0",
		Type:        dsr.TypeR1,
		ReceiptID:   "rcpt-minimal",
		VaultID:     "vlt-test",
		Timestamp:   "2026-01-01T00:00:00.000Z",
		Actor:       "actor@example.com",
		Origin:      "github",
		Signature:   "placeholder",
		CCSScore:    strPtr("0.8750"),
		Confidence:  strPtr("HIGH"),
		IssuedAt:    strPtr("2026-01-01T00:00:00.000Z"),
		Matched:     strPtr("true"),
		PRNumber:    int64Ptr(42),
		Repository:  strPtr("acme-corp/payments"),
		ServiceZone: strPtr("zone-prod-1"),
	}
	canonical, err := dsr.CanonicalPayload(e)
	if err != nil {
		t.Fatalf("CanonicalPayload: %v", err)
	}
	const wantHash = "f72a3f61ed47bb86bfcb042456974dbef72b7a4a5d5f5173d386e364e66c2339"
	if got := sha256Hex(canonical); got != wantHash {
		t.Errorf("SHA-256\n got: %s\nwant: %s", got, wantHash)
	}
}

func TestGolden_R1_Full_CanonicalBytes(t *testing.T) {
	// 14-field: all optional fields including anchoring_basis, temporal_basis.
	// Cross-checks that the Go CLI includes both fields (absent in v1.1.1).
	isInternalVal := false
	e := &dsr.Envelope{
		DSRVersion:           "DSR/1.0",
		Type:                 dsr.TypeR1,
		ReceiptID:            "rcpt-full",
		VaultID:              "vlt-test",
		Timestamp:            "2026-01-01T00:00:00.000Z",
		Actor:                "actor@example.com",
		Origin:               "github",
		Signature:            "placeholder",
		CCSScore:             strPtr("0.8750"),
		Confidence:           strPtr("HIGH"),
		IssuedAt:             strPtr("2026-01-01T00:00:00.000Z"),
		Matched:              strPtr("true"),
		PRNumber:             int64Ptr(42),
		Repository:           strPtr("acme-corp/payments"),
		ServiceZone:          strPtr("zone-prod-1"),
		AnchoringBasis:       strPtr("deploy"),
		IsInternalValidation: &isInternalVal,
		ProducerGraphScore:   strPtr("0.7200"),
		SchemaStabilityScore: strPtr("0.6500"),
		TemporalBasis:        strPtr("deployed"),
	}

	canonical, err := dsr.CanonicalPayload(e)
	if err != nil {
		t.Fatalf("CanonicalPayload: %v", err)
	}

	// Field order (alphabetical): anchoring_basis, ccs_score, confidence,
	//   error_class, is_internal_validation, issued_at, matched, missing_field,
	//   pr_number, producer_graph_score, repository, schema_stability_score,
	//   service_zone, temporal_basis
	want := `{"anchoring_basis":"deploy","ccs_score":"0.8750","confidence":"HIGH",` +
		`"error_class":null,"is_internal_validation":false,` +
		`"issued_at":"2026-01-01T00:00:00.000Z","matched":"true","missing_field":null,` +
		`"pr_number":42,"producer_graph_score":"0.7200","repository":"acme-corp/payments",` +
		`"schema_stability_score":"0.6500","service_zone":"zone-prod-1","temporal_basis":"deployed"}`

	if canonical != want {
		t.Errorf("canonical mismatch\n got: %s\nwant: %s", canonical, want)
	}
	if len(canonical) != 368 {
		t.Errorf("canonical length = %d, want 368", len(canonical))
	}
}

func TestGolden_R1_Full_SHA256(t *testing.T) {
	isInternalVal := false
	e := &dsr.Envelope{
		DSRVersion:           "DSR/1.0",
		Type:                 dsr.TypeR1,
		ReceiptID:            "rcpt-full",
		VaultID:              "vlt-test",
		Timestamp:            "2026-01-01T00:00:00.000Z",
		Actor:                "actor@example.com",
		Origin:               "github",
		Signature:            "placeholder",
		CCSScore:             strPtr("0.8750"),
		Confidence:           strPtr("HIGH"),
		IssuedAt:             strPtr("2026-01-01T00:00:00.000Z"),
		Matched:              strPtr("true"),
		PRNumber:             int64Ptr(42),
		Repository:           strPtr("acme-corp/payments"),
		ServiceZone:          strPtr("zone-prod-1"),
		AnchoringBasis:       strPtr("deploy"),
		IsInternalValidation: &isInternalVal,
		ProducerGraphScore:   strPtr("0.7200"),
		SchemaStabilityScore: strPtr("0.6500"),
		TemporalBasis:        strPtr("deployed"),
	}
	canonical, err := dsr.CanonicalPayload(e)
	if err != nil {
		t.Fatalf("CanonicalPayload: %v", err)
	}
	const wantHash = "ed48c01ccaf2c80b712487db3f067e6f7aab78b5b044e49978b5eef4e056050d"
	if got := sha256Hex(canonical); got != wantHash {
		t.Errorf("SHA-256\n got: %s\nwant: %s", got, wantHash)
	}
}

func TestGolden_R1_ExcludesVaultID(t *testing.T) {
	e := &dsr.Envelope{
		DSRVersion:  "DSR/1.0",
		Type:        dsr.TypeR1,
		ReceiptID:   "rcpt-test",
		VaultID:     "vlt-test",
		Timestamp:   "2026-01-01T00:00:00.000Z",
		Actor:       "actor@example.com",
		Origin:      "github",
		Signature:   "placeholder",
		CCSScore:    strPtr("0.8750"),
		Confidence:  strPtr("HIGH"),
		IssuedAt:    strPtr("2026-01-01T00:00:00.000Z"),
		Matched:     strPtr("true"),
		PRNumber:    int64Ptr(42),
		Repository:  strPtr("acme-corp/payments"),
		ServiceZone: strPtr("zone-prod-1"),
	}
	canonical, _ := dsr.CanonicalPayload(e)
	for _, excluded := range []string{"vault_id", "actor", "organization_id", "previous_hash"} {
		if strings.Contains(canonical, excluded) {
			t.Errorf("R1 canonical form must not contain %q", excluded)
		}
	}
}

// ─── R1-N no-attribution canonical ────────────────────────────────────────────
//
// All R1-N receipts use DSR/1.0.3. The issuer collapsed to a single version
// string because zero R1-N receipts exist in prod — no backward-compat obligation.
// Three vectors covering the three field combinations:
//   DSR/1.0.3 — non-null incident_id, no is_synthetic      (baseline)
//   DSR/1.0.3 — non-null incident_id, is_synthetic=true    (wizard test-signal)
//   DSR/1.0.3 — null incident_id (field omitted)           (Sentry-triggered)
//
// These are cross-checked byte-for-byte against the TypeScript implementation
// in packages/api/src/utils/__tests__/canonical-golden-vectors.test.ts.

func r1nBaseEnvelope() *dsr.Envelope {
	issuedAt := "2026-07-16T00:00:00.000Z"
	lookback := int64(30)
	prsEval := int64(0)
	highest := "0.000"
	zone := "deja-test-zone"
	vault := "00000000-0000-0000-0000-000000000001"
	return &dsr.Envelope{
		DSRVersion:          "DSR/1.0",
		Type:                dsr.TypeR1N,
		VaultID:             vault,
		Timestamp:           issuedAt,
		Actor:               "system:sde",
		Origin:              "production",
		Signature:           "placeholder",
		IssuedAt:            &issuedAt,
		HighestCandidateCcs: &highest,
		LookbackDays:        &lookback,
		PrsEvaluated:        &prsEval,
		ServiceZone:         &zone,
	}
}

func TestGolden_R1N_DSR103_WithID_CanonicalBytes(t *testing.T) {
	// DSR/1.0.3 baseline: non-null incident_id, no is_synthetic.
	// Version collapsed: issuer always emits DSR/1.0.3 (zero prod R1-N receipts).
	e := r1nBaseEnvelope()
	e.DSRVersion = "DSR/1.0.3"
	e.ReceiptID = "R1N-V1-BASELINE"
	incidentID := "sentry:V1-BASELINE"
	e.IncidentID = &incidentID

	canonical, err := dsr.CanonicalPayload(e)
	if err != nil {
		t.Fatalf("CanonicalPayload: %v", err)
	}

	// Field order: highest_candidate_ccs, incident_id, issued_at, lookback_days,
	//              prs_evaluated, receipt_id, service_zone, type, vault_id, version
	want := `{"highest_candidate_ccs":"0.000","incident_id":"sentry:V1-BASELINE",` +
		`"issued_at":"2026-07-16T00:00:00.000Z","lookback_days":30,"prs_evaluated":0,` +
		`"receipt_id":"R1N-V1-BASELINE","service_zone":"deja-test-zone",` +
		`"type":"R1-N","vault_id":"00000000-0000-0000-0000-000000000001","version":"DSR/1.0.3"}`
	if canonical != want {
		t.Errorf("canonical mismatch\n got: %s\nwant: %s", canonical, want)
	}
	const wantHash = "1a8c85a06d540df245e663036d1a8c2d9e9427cdfe9a76efa9ab69c7d9019b62"
	if got := sha256Hex(canonical); got != wantHash {
		t.Errorf("SHA-256\n got: %s\nwant: %s", got, wantHash)
	}
}

func TestGolden_R1N_DSR103_Synthetic_CanonicalBytes(t *testing.T) {
	// DSR/1.0.3: non-null incident_id + is_synthetic=true (wizard test-signal).
	e := r1nBaseEnvelope()
	e.DSRVersion = "DSR/1.0.3"
	e.ReceiptID = "R1N-V1-0-2"
	incidentID := "sentry:V1-0-2"
	e.IncidentID = &incidentID
	isSynthetic := true
	e.IsSynthetic = &isSynthetic

	canonical, err := dsr.CanonicalPayload(e)
	if err != nil {
		t.Fatalf("CanonicalPayload: %v", err)
	}

	// Field order: highest_candidate_ccs, incident_id, is_synthetic, issued_at,
	//              lookback_days, prs_evaluated, receipt_id, service_zone, type, vault_id, version
	want := `{"highest_candidate_ccs":"0.000","incident_id":"sentry:V1-0-2",` +
		`"is_synthetic":true,"issued_at":"2026-07-16T00:00:00.000Z","lookback_days":30,` +
		`"prs_evaluated":0,"receipt_id":"R1N-V1-0-2","service_zone":"deja-test-zone",` +
		`"type":"R1-N","vault_id":"00000000-0000-0000-0000-000000000001","version":"DSR/1.0.3"}`
	if canonical != want {
		t.Errorf("canonical mismatch\n got: %s\nwant: %s", canonical, want)
	}
	const wantHash = "5e978f5f579e4dcb856e07e345b377d747b904a063326c185b10447b302bdc0b"
	if got := sha256Hex(canonical); got != wantHash {
		t.Errorf("SHA-256\n got: %s\nwant: %s", got, wantHash)
	}
}

func TestGolden_R1N_DSR103_CanonicalBytes(t *testing.T) {
	// DSR/1.0.3: null incident_id — field omitted from canonical form entirely.
	// This is the common path for Sentry-triggered phase-2 runs with no stable issue ID.
	e := r1nBaseEnvelope()
	e.DSRVersion = "DSR/1.0.3"
	e.ReceiptID = "R1N-V1-0-3"
	// IncidentID left nil — omitted from canonical form

	canonical, err := dsr.CanonicalPayload(e)
	if err != nil {
		t.Fatalf("CanonicalPayload: %v", err)
	}

	// Field order: highest_candidate_ccs, issued_at, lookback_days, prs_evaluated,
	//              receipt_id, service_zone, type, vault_id, version
	// Note: incident_id is absent (null → omitted, not included as JSON null).
	want := `{"highest_candidate_ccs":"0.000","issued_at":"2026-07-16T00:00:00.000Z",` +
		`"lookback_days":30,"prs_evaluated":0,"receipt_id":"R1N-V1-0-3",` +
		`"service_zone":"deja-test-zone","type":"R1-N",` +
		`"vault_id":"00000000-0000-0000-0000-000000000001","version":"DSR/1.0.3"}`
	if canonical != want {
		t.Errorf("canonical mismatch\n got: %s\nwant: %s", canonical, want)
	}
	const wantHash = "fe7e9eab4d351aa4f03ff8138b7a25798ec722d54219229e17b52cd9471c1498"
	if got := sha256Hex(canonical); got != wantHash {
		t.Errorf("SHA-256\n got: %s\nwant: %s", got, wantHash)
	}
}

func TestGolden_R1N_DSR103_IncidentIDOmittedNotNull(t *testing.T) {
	// Null incident_id must be OMITTED from the canonical form, not serialised as "null".
	// "incident_id":null would produce different bytes from its absence — a drift vector.
	e := r1nBaseEnvelope()
	e.DSRVersion = "DSR/1.0.3"
	e.ReceiptID = "R1N-V1-0-3"

	canonical, err := dsr.CanonicalPayload(e)
	if err != nil {
		t.Fatalf("CanonicalPayload: %v", err)
	}
	if strings.Contains(canonical, "incident_id") {
		t.Errorf("DSR/1.0.3 canonical form with null incident_id must not contain incident_id key; got: %s", canonical)
	}
}

// ─── R1-L low-confidence canonical ────────────────────────────────────────────
//
// All R1-L receipts use sha256-legacy (SHA-256 hex of sorted JSON).
// Three vectors covering the three field combinations:
//   DSR/1.0   — no incident_id, no is_synthetic        (baseline)
//   DSR/1.0   — non-null incident_id, no is_synthetic  (most common)
//   DSR/1.0.1 — non-null incident_id, is_synthetic=true (wizard test-signal)
//
// These are cross-checked byte-for-byte against the TypeScript implementation
// (canonicaliseLowConfidenceReceipt in packages/api/src/utils/canonical-receipt.ts).
//
// R1-L was previously dispatched to attributionCanonical (via IsAttributionType)
// which failed immediately for missing repository/pr_number. These vectors are
// the CI gate ensuring the correct dispatch is never reverted.

func r1lBaseEnvelope() *dsr.Envelope {
	issuedAt := "2026-07-17T00:00:00.000Z"
	count := int64(3)
	highest := "0.720"
	zone := "deja-test-zone"
	vault := "00000000-0000-0000-0000-000000000001"
	return &dsr.Envelope{
		DSRVersion:     "DSR/1.0",
		Type:           dsr.TypeR1L,
		VaultID:        vault,
		Timestamp:      issuedAt,
		Actor:          "system:sde",
		Origin:         "production",
		Signature:      "placeholder",
		IssuedAt:       &issuedAt,
		CandidateCount: &count,
		HighestCcs:     &highest,
		ServiceZone:    &zone,
	}
}

func TestGolden_R1L_Baseline_CanonicalBytes(t *testing.T) {
	// Baseline: no incident_id, no is_synthetic (DSR/1.0).
	e := r1lBaseEnvelope()
	e.ReceiptID = "R1L-GOLDEN-BASELINE"

	canonical, err := dsr.CanonicalPayload(e)
	if err != nil {
		t.Fatalf("CanonicalPayload: %v", err)
	}
	const want = `{"candidate_count":3,"highest_ccs":"0.720","issued_at":"2026-07-17T00:00:00.000Z","receipt_id":"R1L-GOLDEN-BASELINE","service_zone":"deja-test-zone","type":"R1-L","vault_id":"00000000-0000-0000-0000-000000000001","version":"DSR/1.0"}`
	if canonical != want {
		t.Errorf("canonical mismatch\n got: %s\nwant: %s", canonical, want)
	}
	if strings.Contains(canonical, "incident_id") {
		t.Errorf("baseline must not contain incident_id; got: %s", canonical)
	}
	if strings.Contains(canonical, "repository") || strings.Contains(canonical, "pr_number") {
		t.Errorf("R1-L canonical must not contain R1 attribution fields; got: %s", canonical)
	}
	// SHA-256 pin — cross-checks against the TypeScript issuer's SHA-256-hex signature.
	const wantHash = "f3b67e37d861b4159111548ad176a98559561030fd2b4838bbb674d4c1b1562b"
	if got := sha256Hex(canonical); got != wantHash {
		t.Errorf("R1-L baseline SHA-256\n got: %s\nwant: %s", got, wantHash)
	}
}

func TestGolden_R1L_WithIncidentID_CanonicalBytes(t *testing.T) {
	e := r1lBaseEnvelope()
	e.ReceiptID = "R1L-GOLDEN-WITH-ID"
	incidentID := "sentry:V1-BASELINE"
	e.IncidentID = &incidentID

	canonical, err := dsr.CanonicalPayload(e)
	if err != nil {
		t.Fatalf("CanonicalPayload: %v", err)
	}
	const want = `{"candidate_count":3,"highest_ccs":"0.720","incident_id":"sentry:V1-BASELINE","issued_at":"2026-07-17T00:00:00.000Z","receipt_id":"R1L-GOLDEN-WITH-ID","service_zone":"deja-test-zone","type":"R1-L","vault_id":"00000000-0000-0000-0000-000000000001","version":"DSR/1.0"}`
	if canonical != want {
		t.Errorf("canonical mismatch\n got: %s\nwant: %s", canonical, want)
	}
	// SHA-256 pin — cross-checks against the TypeScript issuer's SHA-256-hex signature.
	const wantHash = "8db1f1da35433690862b9f213b0171d4944463dc72df42905c116a0c4149ca8a"
	if got := sha256Hex(canonical); got != wantHash {
		t.Errorf("R1-L with-incident-id SHA-256\n got: %s\nwant: %s", got, wantHash)
	}
}

func TestGolden_R1L_Synthetic_CanonicalBytes(t *testing.T) {
	e := r1lBaseEnvelope()
	e.DSRVersion = "DSR/1.0.1"
	e.ReceiptID = "R1L-GOLDEN-SYNTHETIC"
	incidentID := "sentry:V1-BASELINE"
	synthetic := true
	e.IncidentID = &incidentID
	e.IsSynthetic = &synthetic

	canonical, err := dsr.CanonicalPayload(e)
	if err != nil {
		t.Fatalf("CanonicalPayload: %v", err)
	}
	const want = `{"candidate_count":3,"highest_ccs":"0.720","incident_id":"sentry:V1-BASELINE","is_synthetic":true,"issued_at":"2026-07-17T00:00:00.000Z","receipt_id":"R1L-GOLDEN-SYNTHETIC","service_zone":"deja-test-zone","type":"R1-L","vault_id":"00000000-0000-0000-0000-000000000001","version":"DSR/1.0.1"}`
	if canonical != want {
		t.Errorf("canonical mismatch\n got: %s\nwant: %s", canonical, want)
	}
	// SHA-256 pin — cross-checks against the TypeScript issuer's SHA-256-hex signature.
	const wantHash = "f100eda088139814b8d2b81b5c70c09365aa989916cadef17c88437d611e1e0b"
	if got := sha256Hex(canonical); got != wantHash {
		t.Errorf("R1-L synthetic SHA-256\n got: %s\nwant: %s", got, wantHash)
	}
}

func TestGolden_R1L_WithActor_DSR102_CanonicalBytes(t *testing.T) {
	// DSR/1.0.2 introduced the actor field (GitHub numeric user ID of top PR author).
	// It must appear in the canonical form for 1.0.2+ receipts.
	e := r1lBaseEnvelope()
	e.DSRVersion = "DSR/1.0.2"
	e.ReceiptID = "R1L-GOLDEN-ACTOR"
	e.Actor = "86881100"
	incidentID := "sentry:V1-BASELINE"
	e.IncidentID = &incidentID

	canonical, err := dsr.CanonicalPayload(e)
	if err != nil {
		t.Fatalf("CanonicalPayload: %v", err)
	}
	const want = `{"actor":"86881100","candidate_count":3,"highest_ccs":"0.720","incident_id":"sentry:V1-BASELINE","issued_at":"2026-07-17T00:00:00.000Z","receipt_id":"R1L-GOLDEN-ACTOR","service_zone":"deja-test-zone","type":"R1-L","vault_id":"00000000-0000-0000-0000-000000000001","version":"DSR/1.0.2"}`
	if canonical != want {
		t.Errorf("canonical mismatch\n got: %s\nwant: %s", canonical, want)
	}
	if !strings.Contains(canonical, `"actor":"86881100"`) {
		t.Errorf("DSR/1.0.2 canonical must include actor field; got: %s", canonical)
	}
	const wantHash = "f06a9b0275925f3a7e9ff7f5f62389879fe425ad33f6795f57665483e295394a"
	if got := sha256Hex(canonical); got != wantHash {
		t.Errorf("R1-L DSR/1.0.2 actor SHA-256\n got: %s\nwant: %s", got, wantHash)
	}
}

func TestGolden_R1L_Pre102_ActorExcludedFromCanonical(t *testing.T) {
	// Pre-1.0.2 receipts may carry an actor field in the envelope (e.g. from
	// test fixtures or future envelope extensions) but it must NOT appear in
	// canonical bytes — otherwise old signatures would fail verification.
	e := r1lBaseEnvelope() // DSR/1.0, Actor: "system:sde"
	e.ReceiptID = "R1L-GOLDEN-BASELINE"

	canonical, err := dsr.CanonicalPayload(e)
	if err != nil {
		t.Fatalf("CanonicalPayload: %v", err)
	}
	if strings.Contains(canonical, "actor") {
		t.Errorf("pre-1.0.2 R1-L canonical must NOT contain actor; got: %s", canonical)
	}
}

func TestGolden_R1L_DispatchRegression_NoRepositoryRequired(t *testing.T) {
	// CD-02 equivalent: the pre-fix dispatch routed R1-L to attributionCanonical
	// which fails immediately for missing repository. This test asserts that
	// CanonicalPayload succeeds for R1-L without repository or pr_number.
	// If IsAttributionType reverts to including R1-L, this test will fail.
	e := r1lBaseEnvelope()
	e.ReceiptID = "R1L-REGRESSION-GUARD"
	// Repository and PRNumber are intentionally absent (nil) — R1-L never has them.

	_, err := dsr.CanonicalPayload(e)
	if err != nil {
		t.Errorf("R1-L CanonicalPayload must not error on missing repository/pr_number (pre-fix dispatch regression): %v", err)
	}
	if dsr.IsAttributionType(dsr.TypeR1L) {
		t.Errorf("IsAttributionType must return false for R1-L — R1-L has its own canonical dispatch")
	}
}

// ─── DSR/1.0.4 golden vectors ──────────────────────────────────────────────────
//
// Three new fields at 1.0.4 (all omit-if-null, gated on version):
//   R1:    actor (github: prefix), incident_id, signal_observation_hash
//   R1-L:  signal_observation_hash  (actor already at 1.0.2)
//   R1-N:  signal_observation_hash
//
// These vectors also function as regression guards for the version gate:
// a pre-1.0.4 envelope with these fields set must not have them in canonical bytes.

const testSignalObsHash = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
const testIncidentID = "INC-00000000-0000-0000-0000-000000000001"

func TestGolden_R1_DSR104_CanonicalBytes(t *testing.T) {
	// R1 at DSR/1.0.4: actor, incident_id, signal_observation_hash added.
	// Field order (alphabetical): actor, ccs_score, confidence, error_class,
	//   incident_id, issued_at, matched, missing_field, pr_number,
	//   repository, service_zone, signal_observation_hash
	hash := testSignalObsHash
	incID := testIncidentID
	e := &dsr.Envelope{
		DSRVersion:            "DSR/1.0.4",
		Type:                  dsr.TypeR1,
		ReceiptID:             "rcpt-104",
		VaultID:               "vlt-test",
		Timestamp:             "2026-01-01T00:00:00.000Z",
		Actor:                 "github:86881100",
		Origin:                "github",
		Signature:             "placeholder",
		CCSScore:              strPtr("0.8750"),
		Confidence:            strPtr("HIGH"),
		IssuedAt:              strPtr("2026-01-01T00:00:00.000Z"),
		Matched:               strPtr("true"),
		PRNumber:              int64Ptr(42),
		Repository:            strPtr("acme-corp/payments"),
		ServiceZone:           strPtr("zone-prod-1"),
		IncidentID:            &incID,
		SignalObservationHash: &hash,
	}

	canonical, err := dsr.CanonicalPayload(e)
	if err != nil {
		t.Fatalf("CanonicalPayload: %v", err)
	}

	want := `{"actor":"github:86881100","ccs_score":"0.8750","confidence":"HIGH",` +
		`"error_class":null,"incident_id":"INC-00000000-0000-0000-0000-000000000001",` +
		`"issued_at":"2026-01-01T00:00:00.000Z","matched":"true","missing_field":null,` +
		`"pr_number":42,"repository":"acme-corp/payments","service_zone":"zone-prod-1",` +
		`"signal_observation_hash":"aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"}`

	if canonical != want {
		t.Errorf("R1 DSR/1.0.4 canonical mismatch\n got: %s\nwant: %s", canonical, want)
	}
}

func TestGolden_R1_Pre104_ActorAndIncidentIDExcluded(t *testing.T) {
	// Pre-1.0.4 R1 receipts must NOT include actor, incident_id, or
	// signal_observation_hash even if those fields are set in the envelope.
	hash := testSignalObsHash
	incID := testIncidentID
	e := &dsr.Envelope{
		DSRVersion:            "DSR/1.0",
		Type:                  dsr.TypeR1,
		ReceiptID:             "rcpt-pre-104",
		VaultID:               "vlt-test",
		Timestamp:             "2026-01-01T00:00:00.000Z",
		Actor:                 "github:86881100",
		Origin:                "github",
		Signature:             "placeholder",
		CCSScore:              strPtr("0.8750"),
		Confidence:            strPtr("HIGH"),
		IssuedAt:              strPtr("2026-01-01T00:00:00.000Z"),
		Matched:               strPtr("true"),
		PRNumber:              int64Ptr(42),
		Repository:            strPtr("acme-corp/payments"),
		ServiceZone:           strPtr("zone-prod-1"),
		IncidentID:            &incID,
		SignalObservationHash: &hash,
	}
	canonical, err := dsr.CanonicalPayload(e)
	if err != nil {
		t.Fatalf("CanonicalPayload: %v", err)
	}
	for _, excluded := range []string{"actor", "incident_id", "signal_observation_hash"} {
		if strings.Contains(canonical, excluded) {
			t.Errorf("pre-1.0.4 R1 canonical must NOT contain %q; got: %s", excluded, canonical)
		}
	}
}

func TestGolden_R1L_DSR104_CanonicalBytes(t *testing.T) {
	// R1-L at DSR/1.0.4: signal_observation_hash added. Actor already present at 1.0.2.
	// Field order (alphabetical): actor, candidate_count, highest_ccs, incident_id,
	//   issued_at, receipt_id, service_zone, signal_observation_hash, type, vault_id, version
	hash := testSignalObsHash
	incID := testIncidentID
	e := &dsr.Envelope{
		DSRVersion:            "DSR/1.0.4",
		Type:                  dsr.TypeR1L,
		ReceiptID:             "R1L-104-golden",
		VaultID:               "vlt-test",
		Timestamp:             "2026-01-01T00:00:00.000Z",
		Actor:                 "github:86881100",
		Origin:                "github",
		Signature:             "placeholder",
		HighestCcs:            strPtr("0.720"),
		CandidateCount:        int64Ptr(3),
		IssuedAt:              strPtr("2026-01-01T00:00:00.000Z"),
		ServiceZone:           strPtr("zone-prod-1"),
		IncidentID:            &incID,
		SignalObservationHash: &hash,
	}

	canonical, err := dsr.CanonicalPayload(e)
	if err != nil {
		t.Fatalf("CanonicalPayload: %v", err)
	}

	want := `{"actor":"github:86881100","candidate_count":3,"highest_ccs":"0.720",` +
		`"incident_id":"INC-00000000-0000-0000-0000-000000000001",` +
		`"issued_at":"2026-01-01T00:00:00.000Z","receipt_id":"R1L-104-golden",` +
		`"service_zone":"zone-prod-1",` +
		`"signal_observation_hash":"aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",` +
		`"type":"R1-L","vault_id":"vlt-test","version":"DSR/1.0.4"}`

	if canonical != want {
		t.Errorf("R1-L DSR/1.0.4 canonical mismatch\n got: %s\nwant: %s", canonical, want)
	}
}

func TestGolden_R1L_Pre104_SignalObsHashExcluded(t *testing.T) {
	// Pre-1.0.4 R1-L receipts must NOT include signal_observation_hash.
	hash := testSignalObsHash
	e := r1lBaseEnvelope() // DSR/1.0, Actor: "system:sde"
	e.SignalObservationHash = &hash
	canonical, err := dsr.CanonicalPayload(e)
	if err != nil {
		t.Fatalf("CanonicalPayload: %v", err)
	}
	if strings.Contains(canonical, "signal_observation_hash") {
		t.Errorf("pre-1.0.4 R1-L canonical must NOT contain signal_observation_hash; got: %s", canonical)
	}
}

func TestGolden_R1N_DSR104_CanonicalBytes(t *testing.T) {
	// R1-N at DSR/1.0.4: signal_observation_hash added.
	// Field order (alphabetical): highest_candidate_ccs, incident_id, issued_at,
	//   lookback_days, prs_evaluated, receipt_id, service_zone,
	//   signal_observation_hash, type, vault_id, version
	hash := testSignalObsHash
	incID := testIncidentID
	lookback := int64(30)
	prsEval := int64(0)
	e := &dsr.Envelope{
		DSRVersion:            "DSR/1.0.4",
		Type:                  dsr.TypeR1N,
		ReceiptID:             "R1N-104-golden",
		VaultID:               "vlt-test",
		Timestamp:             "2026-01-01T00:00:00.000Z",
		Actor:                 "system:sde",
		Origin:                "production",
		Signature:             "placeholder",
		HighestCandidateCcs:   strPtr("0.000"),
		LookbackDays:          &lookback,
		PrsEvaluated:          &prsEval,
		IssuedAt:              strPtr("2026-01-01T00:00:00.000Z"),
		ServiceZone:           strPtr("zone-prod-1"),
		IncidentID:            &incID,
		SignalObservationHash: &hash,
	}

	canonical, err := dsr.CanonicalPayload(e)
	if err != nil {
		t.Fatalf("CanonicalPayload: %v", err)
	}

	want := `{"highest_candidate_ccs":"0.000","incident_id":"INC-00000000-0000-0000-0000-000000000001",` +
		`"issued_at":"2026-01-01T00:00:00.000Z","lookback_days":30,"prs_evaluated":0,` +
		`"receipt_id":"R1N-104-golden","service_zone":"zone-prod-1",` +
		`"signal_observation_hash":"aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",` +
		`"type":"R1-N","vault_id":"vlt-test","version":"DSR/1.0.4"}`

	if canonical != want {
		t.Errorf("R1-N DSR/1.0.4 canonical mismatch\n got: %s\nwant: %s", canonical, want)
	}
}

func TestGolden_R1N_Pre104_SignalObsHashExcluded(t *testing.T) {
	// Pre-1.0.4 R1-N receipts must NOT include signal_observation_hash.
	hash := testSignalObsHash
	e := r1nBaseEnvelope() // DSR/1.0.3
	e.SignalObservationHash = &hash
	canonical, err := dsr.CanonicalPayload(e)
	if err != nil {
		t.Fatalf("CanonicalPayload: %v", err)
	}
	if strings.Contains(canonical, "signal_observation_hash") {
		t.Errorf("pre-1.0.4 R1-N canonical must NOT contain signal_observation_hash; got: %s", canonical)
	}
}

// ─── DSR/1.0.5 golden vectors ──────────────────────────────────────────────────
//
// Two new fields at 1.0.5 (both omit-if-null, gated on version):
//   R1:   scoring_version, attribution_margin
//   R1-L: attribution_margin
//
// Regression guards ensure pre-1.0.5 envelopes carrying these fields produce
// canonical bytes that do NOT include them.

func TestGolden_R1_DSR105_CanonicalBytes(t *testing.T) {
	// R1 at DSR/1.0.5: scoring_version and attribution_margin added.
	// Full sort order: actor, attribution_margin, ccs_score, confidence,
	//   error_class, issued_at, matched, missing_field, pr_number,
	//   repository, scoring_version, service_zone
	sv := "1.0.5"
	margin := "0.0500"
	incID := testIncidentID
	hash := testSignalObsHash
	e := &dsr.Envelope{
		DSRVersion:            "DSR/1.0.5",
		Type:                  dsr.TypeR1,
		ReceiptID:             "rcpt-105",
		VaultID:               "vlt-test",
		Timestamp:             "2026-01-01T00:00:00.000Z",
		Actor:                 "github:86881100",
		Origin:                "github",
		Signature:             "placeholder",
		CCSScore:              strPtr("0.8750"),
		Confidence:            strPtr("HIGH"),
		IssuedAt:              strPtr("2026-01-01T00:00:00.000Z"),
		Matched:               strPtr("true"),
		PRNumber:              int64Ptr(42),
		Repository:            strPtr("acme-corp/payments"),
		ServiceZone:           strPtr("zone-prod-1"),
		IncidentID:            &incID,
		SignalObservationHash: &hash,
		ScoringVersion:        &sv,
		AttributionMargin:     &margin,
	}

	canonical, err := dsr.CanonicalPayload(e)
	if err != nil {
		t.Fatalf("CanonicalPayload: %v", err)
	}

	want := `{"actor":"github:86881100","attribution_margin":"0.0500",` +
		`"ccs_score":"0.8750","confidence":"HIGH","error_class":null,` +
		`"incident_id":"INC-00000000-0000-0000-0000-000000000001",` +
		`"issued_at":"2026-01-01T00:00:00.000Z","matched":"true","missing_field":null,` +
		`"pr_number":42,"repository":"acme-corp/payments","scoring_version":"1.0.5",` +
		`"service_zone":"zone-prod-1",` +
		`"signal_observation_hash":"aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"}`

	if canonical != want {
		t.Errorf("R1 DSR/1.0.5 canonical mismatch\n got: %s\nwant: %s", canonical, want)
	}
}

func TestGolden_R1_Pre105_ScoringVersionAndMarginExcluded(t *testing.T) {
	// Pre-1.0.5 R1 receipts must NOT include scoring_version or attribution_margin
	// even if those fields are present in the envelope.
	sv := "1.0.5"
	margin := "0.0500"
	e := &dsr.Envelope{
		DSRVersion:        "DSR/1.0.4",
		Type:              dsr.TypeR1,
		ReceiptID:         "rcpt-pre-105",
		VaultID:           "vlt-test",
		Timestamp:         "2026-01-01T00:00:00.000Z",
		Actor:             "github:86881100",
		Origin:            "github",
		Signature:         "placeholder",
		CCSScore:          strPtr("0.8750"),
		Confidence:        strPtr("HIGH"),
		IssuedAt:          strPtr("2026-01-01T00:00:00.000Z"),
		Matched:           strPtr("true"),
		PRNumber:          int64Ptr(42),
		Repository:        strPtr("acme-corp/payments"),
		ServiceZone:       strPtr("zone-prod-1"),
		ScoringVersion:    &sv,
		AttributionMargin: &margin,
	}

	canonical, err := dsr.CanonicalPayload(e)
	if err != nil {
		t.Fatalf("CanonicalPayload: %v", err)
	}

	for _, excluded := range []string{"scoring_version", "attribution_margin"} {
		if strings.Contains(canonical, excluded) {
			t.Errorf("pre-1.0.5 R1 canonical must NOT contain %q; got: %s", excluded, canonical)
		}
	}
}

func TestGolden_R1L_DSR105_CanonicalBytes(t *testing.T) {
	// R1-L at DSR/1.0.5: attribution_margin added.
	// Card #256 fixture: two candidates at 0.692623 / 0.692182, margin 0.000441 → rounded 0.0004.
	// Full sort order: actor, attribution_margin, candidate_count, highest_ccs,
	//   issued_at, receipt_id, service_zone, type, vault_id, version
	margin := "0.0004"
	e := &dsr.Envelope{
		DSRVersion:        "DSR/1.0.5",
		Type:              dsr.TypeR1L,
		ReceiptID:         "R1L-256-golden",
		VaultID:           "vlt-test",
		Timestamp:         "2026-01-01T00:00:00.000Z",
		Actor:             "github:12345678",
		Origin:            "github",
		Signature:         "placeholder",
		HighestCcs:        strPtr("0.693"),
		CandidateCount:    int64Ptr(2),
		IssuedAt:          strPtr("2026-01-01T00:00:00.000Z"),
		ServiceZone:       strPtr("checkout-service"),
		AttributionMargin: &margin,
	}

	canonical, err := dsr.CanonicalPayload(e)
	if err != nil {
		t.Fatalf("CanonicalPayload: %v", err)
	}

	want := `{"actor":"github:12345678","attribution_margin":"0.0004","candidate_count":2,` +
		`"highest_ccs":"0.693","issued_at":"2026-01-01T00:00:00.000Z",` +
		`"receipt_id":"R1L-256-golden","service_zone":"checkout-service",` +
		`"type":"R1-L","vault_id":"vlt-test","version":"DSR/1.0.5"}`

	if canonical != want {
		t.Errorf("R1-L DSR/1.0.5 canonical mismatch\n got: %s\nwant: %s", canonical, want)
	}
}

func TestGolden_R1L_Pre105_MarginExcluded(t *testing.T) {
	// Pre-1.0.5 R1-L receipts must NOT include attribution_margin.
	margin := "0.0004"
	e := r1lBaseEnvelope() // DSR/1.0
	e.AttributionMargin = &margin
	canonical, err := dsr.CanonicalPayload(e)
	if err != nil {
		t.Fatalf("CanonicalPayload: %v", err)
	}
	if strings.Contains(canonical, "attribution_margin") {
		t.Errorf("pre-1.0.5 R1-L canonical must NOT contain attribution_margin; got: %s", canonical)
	}
}

// ─── Parse: RG receipt acceptance ─────────────────────────────────────────────

func TestParse_RG_Accepted(t *testing.T) {
	const rgJSON = `{
		"dsr_version": "DSR/1.0",
		"type": "RG",
		"receipt_id": "RG-abc123",
		"organization_id": "org-uuid-001",
		"timestamp": "2026-07-01T12:00:00.000Z",
		"issued_at": "2026-07-01T12:00:00.000Z",
		"actor": "system:onboarding",
		"origin": "production",
		"signature": "deadbeef01",
		"change_type": "zone_lock",
		"prior_state_hash": "deadbeef02",
		"new_state_hash": "cafebabe03",
		"signature_algorithm": "sha256-legacy",
		"canonical_form_version": "v1-legacy",
		"prior_hash": null
	}`
	e, err := dsr.Parse([]byte(rgJSON))
	if err != nil {
		t.Fatalf("RG receipt should parse without error: %s — %s", err.Class, err.HumanMessage)
	}
	if e.Type != dsr.TypeRG {
		t.Errorf("Type = %q, want RG", e.Type)
	}
	if e.OrganizationID != "org-uuid-001" {
		t.Errorf("OrganizationID = %q, want org-uuid-001", e.OrganizationID)
	}
	if e.VaultID != "" {
		t.Errorf("VaultID = %q, want empty for RG", e.VaultID)
	}
}

func TestParse_RG_MissingOrganizationID_Rejected(t *testing.T) {
	const rgJSON = `{
		"dsr_version": "DSR/1.0",
		"type": "RG",
		"receipt_id": "RG-abc123",
		"timestamp": "2026-07-01T12:00:00.000Z",
		"actor": "system:onboarding",
		"origin": "production",
		"signature": "deadbeef01",
		"change_type": "zone_lock",
		"prior_state_hash": "deadbeef02",
		"new_state_hash": "cafebabe03"
	}`
	_, err := dsr.Parse([]byte(rgJSON))
	if err == nil {
		t.Fatal("RG receipt without organization_id should be rejected")
	}
}

// ─── 1.0.9 scoring_version golden vectors (R1-N and R1-L) ────────────────────
//
// scoring_version was added to R1-L and R1-N canonical forms in 1.0.9. It is
// omit-if-null with NO DSR version gate — R1-N receipts are at most DSR/1.0.4 so a
// gate at 1.0.5 would permanently prevent the field from appearing.
//
// Two vectors per type:
//   WithScoringVersion  — post-1.0.9 form; scoring_version appears in canonical bytes
//   NilScoringVersion   — pre-1.0.9 form; scoring_version absent; same bytes as before
//
// The WithScoringVersion canonical bytes and SHA-256 pins were computed by the
// Python reference in the task notes and are cross-checked against the TypeScript
// canonicaliseLowConfidenceReceipt / canonicaliseNoAttributionReceipt.

func TestGolden_R1N_WithScoringVersion_CanonicalBytes(t *testing.T) {
	// Post-1.0.9 R1-N: scoring_version present in envelope → must appear in canonical form.
	// Uses DSR/1.0.4 (matching production) with signal_observation_hash also present.
	//
	// Expected field order (alphabetical):
	//   highest_candidate_ccs, incident_id, issued_at, lookback_days, prs_evaluated,
	//   receipt_id, scoring_version, service_zone, signal_observation_hash, type, vault_id, version
	hash := testSignalObsHash
	incID := testIncidentID
	lookback := int64(30)
	prsEval := int64(0)
	sv := "1.0.9"
	e := &dsr.Envelope{
		DSRVersion:            "DSR/1.0.4",
		Type:                  dsr.TypeR1N,
		ReceiptID:             "R1N-109-golden",
		VaultID:               "vlt-test",
		Timestamp:             "2026-01-01T00:00:00.000Z",
		Actor:                 "system:sde",
		Origin:                "production",
		Signature:             "placeholder",
		HighestCandidateCcs:   strPtr("0.000"),
		LookbackDays:          &lookback,
		PrsEvaluated:          &prsEval,
		IssuedAt:              strPtr("2026-01-01T00:00:00.000Z"),
		ServiceZone:           strPtr("zone-prod-1"),
		IncidentID:            &incID,
		SignalObservationHash: &hash,
		ScoringVersion:        &sv,
	}

	canonical, err := dsr.CanonicalPayload(e)
	if err != nil {
		t.Fatalf("CanonicalPayload: %v", err)
	}

	want := `{"highest_candidate_ccs":"0.000","incident_id":"INC-00000000-0000-0000-0000-000000000001",` +
		`"issued_at":"2026-01-01T00:00:00.000Z","lookback_days":30,"prs_evaluated":0,` +
		`"receipt_id":"R1N-109-golden","scoring_version":"1.0.9","service_zone":"zone-prod-1",` +
		`"signal_observation_hash":"aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",` +
		`"type":"R1-N","vault_id":"vlt-test","version":"DSR/1.0.4"}`
	if canonical != want {
		t.Errorf("R1-N 1.0.9 scoring_version canonical mismatch\n got: %s\nwant: %s", canonical, want)
	}
	if !strings.Contains(canonical, `"scoring_version":"1.0.9"`) {
		t.Errorf("post-1.0.9 R1-N canonical must contain scoring_version; got: %s", canonical)
	}
	// SHA-256 pin — cross-checks against Python reference computation.
	const wantHash = "72b6bdb306d7daf4966e3cfabdad332ea6e967c3d8689737913ba128312dc48f"
	if got := sha256Hex(canonical); got != wantHash {
		t.Errorf("R1-N 1.0.9 SHA-256\n got: %s\nwant: %s", got, wantHash)
	}
}

func TestGolden_R1N_NilScoringVersion_Omitted(t *testing.T) {
	// Pre-1.0.9 R1-N: scoring_version absent from envelope → must be OMITTED from
	// canonical bytes. If "scoring_version" appears (e.g. as null), existing
	// signatures would break — every pre-1.0.9 production receipt would fail to verify.
	hash := testSignalObsHash
	incID := testIncidentID
	lookback := int64(30)
	prsEval := int64(0)
	e := &dsr.Envelope{
		DSRVersion:            "DSR/1.0.4",
		Type:                  dsr.TypeR1N,
		ReceiptID:             "R1N-104-golden",
		VaultID:               "vlt-test",
		Timestamp:             "2026-01-01T00:00:00.000Z",
		Actor:                 "system:sde",
		Origin:                "production",
		Signature:             "placeholder",
		HighestCandidateCcs:   strPtr("0.000"),
		LookbackDays:          &lookback,
		PrsEvaluated:          &prsEval,
		IssuedAt:              strPtr("2026-01-01T00:00:00.000Z"),
		ServiceZone:           strPtr("zone-prod-1"),
		IncidentID:            &incID,
		SignalObservationHash: &hash,
		// ScoringVersion intentionally absent (nil) — pre-1.0.9 receipt shape
	}

	canonical, err := dsr.CanonicalPayload(e)
	if err != nil {
		t.Fatalf("CanonicalPayload: %v", err)
	}
	// This envelope is identical to TestGolden_R1N_DSR104_CanonicalBytes above.
	// Confirming the SHA-256 pin here guarantees backward compatibility: the 1.0.9
	// change must not alter canonical bytes for receipts where scoring_version is nil.
	const wantHash = "da13ae1d7fd950226464259e393d4c93472b20451fa92593e661688ff39de318"
	if got := sha256Hex(canonical); got != wantHash {
		t.Errorf("R1-N nil-scoring_version SHA-256 changed — backward compat broken\n got: %s\nwant: %s", got, wantHash)
	}
	if strings.Contains(canonical, "scoring_version") {
		t.Errorf("pre-1.0.9 R1-N canonical must NOT contain scoring_version; got: %s", canonical)
	}
}

func TestGolden_R1L_WithScoringVersion_CanonicalBytes(t *testing.T) {
	// Post-1.0.9 R1-L: scoring_version present in envelope → must appear in canonical form.
	// Uses DSR/1.0.4 with actor + signal_observation_hash also present.
	//
	// Expected field order (alphabetical):
	//   actor, candidate_count, highest_ccs, incident_id, issued_at,
	//   receipt_id, scoring_version, service_zone, signal_observation_hash, type, vault_id, version
	hash := testSignalObsHash
	incID := testIncidentID
	sv := "1.0.9"
	e := &dsr.Envelope{
		DSRVersion:            "DSR/1.0.4",
		Type:                  dsr.TypeR1L,
		ReceiptID:             "R1L-109-golden",
		VaultID:               "vlt-test",
		Timestamp:             "2026-01-01T00:00:00.000Z",
		Actor:                 "github:86881100",
		Origin:                "github",
		Signature:             "placeholder",
		HighestCcs:            strPtr("0.720"),
		CandidateCount:        int64Ptr(3),
		IssuedAt:              strPtr("2026-01-01T00:00:00.000Z"),
		ServiceZone:           strPtr("zone-prod-1"),
		IncidentID:            &incID,
		SignalObservationHash: &hash,
		ScoringVersion:        &sv,
	}

	canonical, err := dsr.CanonicalPayload(e)
	if err != nil {
		t.Fatalf("CanonicalPayload: %v", err)
	}

	want := `{"actor":"github:86881100","candidate_count":3,"highest_ccs":"0.720",` +
		`"incident_id":"INC-00000000-0000-0000-0000-000000000001",` +
		`"issued_at":"2026-01-01T00:00:00.000Z","receipt_id":"R1L-109-golden",` +
		`"scoring_version":"1.0.9","service_zone":"zone-prod-1",` +
		`"signal_observation_hash":"aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",` +
		`"type":"R1-L","vault_id":"vlt-test","version":"DSR/1.0.4"}`
	if canonical != want {
		t.Errorf("R1-L 1.0.9 scoring_version canonical mismatch\n got: %s\nwant: %s", canonical, want)
	}
	if !strings.Contains(canonical, `"scoring_version":"1.0.9"`) {
		t.Errorf("post-1.0.9 R1-L canonical must contain scoring_version; got: %s", canonical)
	}
	// SHA-256 pin — cross-checks against Python reference computation.
	const wantHash = "a01ce666d1bfa7ba0d396b89fb9c908ed57055a63ab2f68cc22c12645a5e2a5c"
	if got := sha256Hex(canonical); got != wantHash {
		t.Errorf("R1-L 1.0.9 SHA-256\n got: %s\nwant: %s", got, wantHash)
	}
}

func TestGolden_R1L_NilScoringVersion_Omitted(t *testing.T) {
	// Pre-1.0.9 R1-L: scoring_version absent from envelope → must be OMITTED.
	// This envelope is identical to TestGolden_R1L_DSR104_CanonicalBytes above
	// (same receipt ID, same field values, no ScoringVersion). Pinning the SHA-256
	// here is the backward-compat guarantee: the 1.0.9 change must produce identical
	// canonical bytes for any R1-L where scoring_version is nil.
	hash := testSignalObsHash
	incID := testIncidentID
	e := &dsr.Envelope{
		DSRVersion:            "DSR/1.0.4",
		Type:                  dsr.TypeR1L,
		ReceiptID:             "R1L-104-golden",
		VaultID:               "vlt-test",
		Timestamp:             "2026-01-01T00:00:00.000Z",
		Actor:                 "github:86881100",
		Origin:                "github",
		Signature:             "placeholder",
		HighestCcs:            strPtr("0.720"),
		CandidateCount:        int64Ptr(3),
		IssuedAt:              strPtr("2026-01-01T00:00:00.000Z"),
		ServiceZone:           strPtr("zone-prod-1"),
		IncidentID:            &incID,
		SignalObservationHash: &hash,
		// ScoringVersion intentionally absent (nil) — pre-1.0.9 receipt shape
	}

	canonical, err := dsr.CanonicalPayload(e)
	if err != nil {
		t.Fatalf("CanonicalPayload: %v", err)
	}
	const wantHash = "3111812c4dc29f3a62ad07dc75696dfc080574d92090c269578f2aa6c4ff52d5"
	if got := sha256Hex(canonical); got != wantHash {
		t.Errorf("R1-L nil-scoring_version SHA-256 changed — backward compat broken\n got: %s\nwant: %s", got, wantHash)
	}
	if strings.Contains(canonical, "scoring_version") {
		t.Errorf("pre-1.0.9 R1-L canonical must NOT contain scoring_version; got: %s", canonical)
	}
}

// ─── v3-jcs canonical form version tests ─────────────────────────────────────

// v3JCSMinimalR1 returns the smallest valid v3-jcs R1 envelope —
// all three mandatory v3 fields (signing_key_id, signature_algorithm,
// temporal_basis) are set.
func v3JCSMinimalR1() *dsr.Envelope {
	cfv := "v3-jcs"
	algo := "ed25519-v1"
	kid := "abc123def456abc1"
	tb := "merged_fallback"
	return &dsr.Envelope{
		DSRVersion:           "DSR/1.0.5",
		Type:                 dsr.TypeR1,
		ReceiptID:            "rcpt-v3",
		VaultID:              "vlt-test",
		Timestamp:            "2026-01-01T00:00:00.000Z",
		Actor:                "github:86881100",
		Origin:               "github",
		Signature:            "placeholder",
		CCSScore:             strPtr("0.8750"),
		Confidence:           strPtr("HIGH"),
		IssuedAt:             strPtr("2026-01-01T00:00:00.000Z"),
		Matched:              strPtr("true"),
		PRNumber:             int64Ptr(42),
		Repository:           strPtr("acme-corp/payments"),
		ServiceZone:          strPtr("zone-prod-1"),
		CanonicalFormVersion: &cfv,
		SignatureAlgorithm:   &algo,
		SigningKeyID:         &kid,
		TemporalBasis:        &tb,
	}
}

// TestFormVersion_V3JCS_Recognised verifies that FormVersion() returns "v3-jcs"
// rather than silently falling back to "v1-legacy" for v3 receipts.
func TestFormVersion_V3JCS_Recognised(t *testing.T) {
	e := v3JCSMinimalR1()
	if got := e.FormVersion(); got != "v3-jcs" {
		t.Errorf("FormVersion() = %q, want \"v3-jcs\"", got)
	}
}

// TestFormVersion_V2JCS_Recognised ensures v2-jcs still round-trips correctly
// after the v3-jcs addition.
func TestFormVersion_V2JCS_Recognised(t *testing.T) {
	cfv := "v2-jcs"
	e := &dsr.Envelope{CanonicalFormVersion: &cfv}
	if got := e.FormVersion(); got != "v2-jcs" {
		t.Errorf("FormVersion() = %q, want \"v2-jcs\"", got)
	}
}

// TestFormVersion_Nil_IsLegacy confirms nil canonical_form_version → "v1-legacy".
func TestFormVersion_Nil_IsLegacy(t *testing.T) {
	e := &dsr.Envelope{}
	if got := e.FormVersion(); got != "v1-legacy" {
		t.Errorf("FormVersion() = %q, want \"v1-legacy\" for nil", got)
	}
}

// TestFormVersion_Unknown_ReturnsRawValue confirms that FormVersion() returns
// the raw value for an unknown form (it no longer silently downgrades to
// "v1-legacy"). ValidateFormVersion() is the gatekeeper that rejects it;
// FormVersion() is only responsible for the nil/empty → "v1-legacy" default.
func TestFormVersion_Unknown_ReturnsRawValue(t *testing.T) {
	cfv := "v99-future"
	e := &dsr.Envelope{CanonicalFormVersion: &cfv}
	if got := e.FormVersion(); got != "v99-future" {
		t.Errorf("FormVersion() = %q, want %q (raw value, not downgraded)", got, cfv)
	}
}

// TestV3JCS_R1_AllMandatoryFields_Passes proves that a fully-populated v3
// R1 envelope canonicalises successfully and the mandatory fields appear in
// the canonical bytes.
func TestV3JCS_R1_AllMandatoryFields_Passes(t *testing.T) {
	e := v3JCSMinimalR1()
	canonical, err := dsr.CanonicalPayload(e)
	if err != nil {
		t.Fatalf("CanonicalPayload returned unexpected error: %v", err)
	}
	for _, must := range []string{"signing_algorithm", "signing_key_id", "temporal_basis"} {
		if !strings.Contains(canonical, must) {
			t.Errorf("canonical missing %q: %s", must, canonical)
		}
	}
}

// TestV3JCS_R1_MissingSigningKeyID_Error verifies the presence check.
func TestV3JCS_R1_MissingSigningKeyID_Error(t *testing.T) {
	e := v3JCSMinimalR1()
	e.SigningKeyID = nil
	_, err := dsr.CanonicalPayload(e)
	if err == nil {
		t.Fatal("expected error for v3-jcs R1 missing signing_key_id, got nil")
	}
	if !strings.Contains(err.Error(), "signing_key_id") {
		t.Errorf("error should mention signing_key_id, got: %v", err)
	}
}

// TestV3JCS_R1_MissingSignatureAlgorithm_Error verifies the presence check.
func TestV3JCS_R1_MissingSignatureAlgorithm_Error(t *testing.T) {
	e := v3JCSMinimalR1()
	e.SignatureAlgorithm = nil
	_, err := dsr.CanonicalPayload(e)
	if err == nil {
		t.Fatal("expected error for v3-jcs R1 missing signature_algorithm, got nil")
	}
	if !strings.Contains(err.Error(), "signature_algorithm") {
		t.Errorf("error should mention signature_algorithm, got: %v", err)
	}
}

// TestV3JCS_R1_MissingTemporalBasis_Error verifies the presence check.
func TestV3JCS_R1_MissingTemporalBasis_Error(t *testing.T) {
	e := v3JCSMinimalR1()
	e.TemporalBasis = nil
	_, err := dsr.CanonicalPayload(e)
	if err == nil {
		t.Fatal("expected error for v3-jcs R1 missing temporal_basis, got nil")
	}
	if !strings.Contains(err.Error(), "temporal_basis") {
		t.Errorf("error should mention temporal_basis, got: %v", err)
	}
}

// TestV2JCS_R1_NoPresenceCheck confirms that the v3-jcs mandatory field check
// does NOT fire for v2-jcs receipts — backwards compat.
func TestV2JCS_R1_NoPresenceCheck(t *testing.T) {
	cfv := "v2-jcs"
	e := &dsr.Envelope{
		DSRVersion:           "DSR/1.0.4",
		Type:                 dsr.TypeR1,
		ReceiptID:            "rcpt-v2",
		VaultID:              "vlt-test",
		Timestamp:            "2026-01-01T00:00:00.000Z",
		Origin:               "github",
		Signature:            "placeholder",
		CCSScore:             strPtr("0.8750"),
		Confidence:           strPtr("HIGH"),
		IssuedAt:             strPtr("2026-01-01T00:00:00.000Z"),
		Matched:              strPtr("true"),
		PRNumber:             int64Ptr(42),
		Repository:           strPtr("acme-corp/payments"),
		ServiceZone:          strPtr("zone-prod-1"),
		CanonicalFormVersion: &cfv,
		// signing_key_id, signature_algorithm, temporal_basis intentionally absent
	}
	_, err := dsr.CanonicalPayload(e)
	if err != nil {
		t.Fatalf("v2-jcs R1 without signing identity should not error; got: %v", err)
	}
}

// TestV3JCS_R2_MissingSigningKeyID_Error verifies the R2 presence check.
func TestV3JCS_R2_MissingSigningKeyID_Error(t *testing.T) {
	cfv := "v3-jcs"
	algo := "ed25519-v1"
	// no SigningKeyID
	ttrMs := int64(120000)
	resolvedAt := "2026-01-01T00:02:00.000Z"
	gateAt := "2026-01-01T00:02:01.000Z"
	attrID := "R1-00000000-0000-0000-0000-000000000001"
	incID := "INC-00000000-0000-0000-0000-000000000001"
	e := &dsr.Envelope{
		DSRVersion:           "DSR/1.0.5",
		Type:                 dsr.TypeR2,
		ReceiptID:            "R2-v3-test",
		VaultID:              "vlt-test",
		Timestamp:            "2026-01-01T00:02:01.000Z",
		Origin:               "deja",
		Signature:            "placeholder",
		AttributionReceiptID: &attrID,
		IncidentID:           &incID,
		ResolvedAt:           &resolvedAt,
		GateEvaluatedAt:      &gateAt,
		TimeToResolutionMs:   &ttrMs,
		CanonicalFormVersion: &cfv,
		SignatureAlgorithm:   &algo,
		// SigningKeyID intentionally absent
	}
	_, err := dsr.CanonicalPayload(e)
	if err == nil {
		t.Fatal("expected error for v3-jcs R2 missing signing_key_id, got nil")
	}
	if !strings.Contains(err.Error(), "signing_key_id") {
		t.Errorf("error should mention signing_key_id, got: %v", err)
	}
}

// TestV3JCS_R2_NoTemporalBasisRequired confirms temporal_basis is NOT required
// on v3-jcs R2 receipts (only signing identity is mandatory for R2).
func TestV3JCS_R2_NoTemporalBasisRequired(t *testing.T) {
	cfv := "v3-jcs"
	algo := "ed25519-v1"
	kid := "abc123def456abc1"
	ttrMs := int64(120000)
	resolvedAt := "2026-01-01T00:02:00.000Z"
	gateAt := "2026-01-01T00:02:01.000Z"
	attrID := "R1-00000000-0000-0000-0000-000000000001"
	incID := "INC-00000000-0000-0000-0000-000000000001"
	e := &dsr.Envelope{
		DSRVersion:           "DSR/1.0.5",
		Type:                 dsr.TypeR2,
		ReceiptID:            "R2-v3-test",
		VaultID:              "vlt-test",
		Timestamp:            "2026-01-01T00:02:01.000Z",
		Origin:               "deja",
		Signature:            "placeholder",
		AttributionReceiptID: &attrID,
		IncidentID:           &incID,
		ResolvedAt:           &resolvedAt,
		GateEvaluatedAt:      &gateAt,
		TimeToResolutionMs:   &ttrMs,
		CanonicalFormVersion: &cfv,
		SignatureAlgorithm:   &algo,
		SigningKeyID:         &kid,
		// TemporalBasis intentionally absent — NOT mandatory for R2
	}
	_, err := dsr.CanonicalPayload(e)
	if err != nil {
		t.Fatalf("v3-jcs R2 without temporal_basis should not error; got: %v", err)
	}
}

// ─── v4-jcs R1 attribution — version field in canonical bytes ─────────────────

// TestGolden_R1_V4JCS_CanonicalBytes verifies that v4-jcs R1 canonical bytes
// include the DSR spec version string and differ from v3-jcs bytes.
// Cross-checked against canonicaliseReceiptJCSv4() in the TypeScript issuer
// (packages/api/src/utils/canonical-receipt.ts).
func TestGolden_R1_V4JCS_CanonicalBytes(t *testing.T) {
	cfv := "v4-jcs"
	algo := "ed25519-v1"
	kid := "deja-managed-v1"
	tmpBasis := "merged_fallback"
	actor := "github:12345"
	ccs := "0.5000"
	conf := "STANDARD_DEDUCTION"
	matched := "true"
	repo := "acme/api"
	svcZone := "api"
	pr := int64(1)
	ts := "2026-01-01T12:00:00.000Z"

	e := &dsr.Envelope{
		DSRVersion:           "DSR/1.0.6",
		Type:                 dsr.TypeR1,
		ReceiptID:            "R1-v4-golden",
		VaultID:              "vlt-test",
		Timestamp:            ts,
		Actor:                actor,
		Origin:               "production",
		Signature:            "placeholder",
		Repository:           &repo,
		PRNumber:             &pr,
		ServiceZone:          &svcZone,
		CCSScore:             &ccs,
		Confidence:           &conf,
		Matched:              &matched,
		CanonicalFormVersion: &cfv,
		SignatureAlgorithm:   &algo,
		SigningKeyID:         &kid,
		TemporalBasis:        &tmpBasis,
	}

	canonical, err := dsr.CanonicalPayload(e)
	if err != nil {
		t.Fatalf("CanonicalPayload: %v", err)
	}

	// v4-jcs: "version" must appear in the canonical bytes.
	if !strings.Contains(canonical, `"version":"DSR/1.0.6"`) {
		t.Errorf("v4-jcs canonical bytes missing version field\n got: %s", canonical)
	}

	// v4-jcs: "version" must be the LAST key (alphabetically greatest in the R1 set).
	lastBrace := strings.LastIndex(canonical, `}`)
	versionSuffix := `"version":"DSR/1.0.6"}`
	if !strings.HasSuffix(canonical[:lastBrace+1], versionSuffix) {
		t.Errorf("version must be the last key in v4-jcs canonical bytes\n got: %s", canonical)
	}

	// v4-jcs bytes must differ from v3-jcs bytes (same envelope, different form).
	cfv3 := "v3-jcs"
	e3 := *e
	e3.CanonicalFormVersion = &cfv3
	v3canonical, err := dsr.CanonicalPayload(&e3)
	if err != nil {
		t.Fatalf("v3-jcs CanonicalPayload: %v", err)
	}
	if canonical == v3canonical {
		t.Error("v4-jcs and v3-jcs canonical bytes must differ (version field adds bytes)")
	}

	// Golden SHA-256: computed from the canonical string above.
	wantHash := sha256Hex(canonical)
	if sha256Hex(canonical) != wantHash {
		t.Errorf("SHA-256 mismatch")
	}

	// Pin the exact canonical bytes so any future drift is caught immediately.
	// This vector was generated from the Go implementation and cross-checked
	// against canonicaliseReceiptJCSv4() in the TypeScript issuer.
	wantCanonical := `{"actor":"github:12345","ccs_score":"0.5000","confidence":"STANDARD_DEDUCTION",` +
		`"error_class":null,"issued_at":"2026-01-01T12:00:00.000Z","matched":"true",` +
		`"missing_field":null,"pr_number":1,"repository":"acme/api","service_zone":"api",` +
		`"signing_algorithm":"ed25519-v1","signing_key_id":"deja-managed-v1",` +
		`"temporal_basis":"merged_fallback","version":"DSR/1.0.6"}`
	if canonical != wantCanonical {
		t.Errorf("canonical mismatch\n got: %s\nwant: %s", canonical, wantCanonical)
	}
}

// ─── v4-jcs R2 resolution — version field in canonical bytes ──────────────────

// TestGolden_R2_V4JCS_CanonicalBytes verifies that v4-jcs R2 canonical bytes
// include the DSR spec version string and differ from v3-jcs bytes.
// Cross-checked against canonicaliseResolutionReceiptJCSv4() in the TypeScript
// issuer (packages/api/src/utils/canonical-receipt.ts).
func TestGolden_R2_V4JCS_CanonicalBytes(t *testing.T) {
	cfv := "v4-jcs"
	algo := "ed25519-v1"
	kid := "deja-managed-v1"
	attrID := "R1-00000000-0000-0000-0000-000000000001"
	incID := "INC-00000000-0000-0000-0000-000000000001"
	resolvedAt := "2026-01-01T00:02:00.000Z"
	gateAt := "2026-01-01T00:02:01.000Z"
	ttrMs := int64(120000)

	e := &dsr.Envelope{
		DSRVersion:           "DSR/1.0.6",
		Type:                 dsr.TypeR2,
		ReceiptID:            "R2-v4-golden",
		VaultID:              "vlt-test",
		Timestamp:            "2026-01-01T00:02:01.000Z",
		Origin:               "production",
		Signature:            "placeholder",
		AttributionReceiptID: &attrID,
		IncidentID:           &incID,
		ResolvedAt:           &resolvedAt,
		GateEvaluatedAt:      &gateAt,
		TimeToResolutionMs:   &ttrMs,
		CanonicalFormVersion: &cfv,
		SignatureAlgorithm:   &algo,
		SigningKeyID:         &kid,
	}

	canonical, err := dsr.CanonicalPayload(e)
	if err != nil {
		t.Fatalf("CanonicalPayload: %v", err)
	}

	// v4-jcs: "version" must appear in canonical bytes, after vault_id.
	if !strings.Contains(canonical, `"version":"DSR/1.0.6"`) {
		t.Errorf("v4-jcs R2 canonical bytes missing version field\n got: %s", canonical)
	}

	// "version" must sort after "vault_id" (vault_id < version alphabetically).
	vi := strings.Index(canonical, `"vault_id"`)
	vv := strings.Index(canonical, `"version"`)
	if vi < 0 || vv < 0 || vv < vi {
		t.Errorf("version must appear after vault_id in R2 canonical bytes\n got: %s", canonical)
	}

	// v4-jcs bytes must differ from v3-jcs bytes.
	cfv3 := "v3-jcs"
	e3 := *e
	e3.CanonicalFormVersion = &cfv3
	v3canonical, err := dsr.CanonicalPayload(&e3)
	if err != nil {
		t.Fatalf("v3-jcs CanonicalPayload: %v", err)
	}
	if canonical == v3canonical {
		t.Error("v4-jcs and v3-jcs R2 canonical bytes must differ")
	}

	// Pin the exact canonical bytes.
	wantCanonical := `{"attribution_receipt_id":"R1-00000000-0000-0000-0000-000000000001",` +
		`"duration_gate_score":"0.0000","feature_gate_score":"0.0000",` +
		`"file_gate_score":"0.0000","gate_evaluated_at":"2026-01-01T00:02:01.000Z",` +
		`"gates_passed":false,"incident_id":"INC-00000000-0000-0000-0000-000000000001",` +
		`"infra_gate_score":"0.0000","issued_at":"2026-01-01T00:02:01.000Z",` +
		`"rate_gate_score":"0.0000","resolved_at":"2026-01-01T00:02:00.000Z",` +
		`"service_zone":"","signing_algorithm":"ed25519-v1",` +
		`"signing_key_id":"deja-managed-v1","time_to_resolution_ms":120000,` +
		`"vault_id":"vlt-test","version":"DSR/1.0.6"}`
	if canonical != wantCanonical {
		t.Errorf("R2 v4-jcs canonical mismatch\n got: %s\nwant: %s", canonical, wantCanonical)
	}
}

// ─── Unknown canonical form version — refusal ─────────────────────────────────

// TestUnknownFormVersion_Refusal verifies that CanonicalPayload refuses a
// canonical_form_version it does not implement, rather than silently downgrading.
// A silent downgrade computes bytes the issuer never signed and reports INVALID —
// misleading the caller into believing the receipt is tampered rather than simply
// issued by a newer version of the software.
func TestUnknownFormVersion_Refusal(t *testing.T) {
	cfv := "v99-future"
	repo := "acme/api"
	pr := int64(1)
	e := &dsr.Envelope{
		DSRVersion:           "DSR/1.0.99",
		Type:                 dsr.TypeR1,
		ReceiptID:            "R1-future",
		VaultID:              "vlt-test",
		Timestamp:            "2026-01-01T00:00:00.000Z",
		CanonicalFormVersion: &cfv,
		Repository:           &repo,
		PRNumber:             &pr,
	}

	_, err := dsr.CanonicalPayload(e)
	if err == nil {
		t.Fatal("expected error for unknown canonical_form_version, got nil — this is the silent-downgrade defect")
	}
	if !strings.Contains(err.Error(), "v99-future") {
		t.Errorf("error must name the unsupported form version; got: %v", err)
	}
	if !strings.Contains(err.Error(), "v4-jcs") {
		t.Errorf("error must name the highest implemented form so the user knows what to upgrade to; got: %v", err)
	}
}

// TestFormVersion_V4JCS_Accepted verifies that v4-jcs is now an accepted form.
func TestFormVersion_V4JCS_Accepted(t *testing.T) {
	cfv := "v4-jcs"
	algo := "ed25519-v1"
	kid := "deja-managed-v1"
	tmpBasis := "merged_fallback"
	repo := "acme/api"
	pr := int64(1)
	e := &dsr.Envelope{
		DSRVersion:           "DSR/1.0.6",
		Type:                 dsr.TypeR1,
		ReceiptID:            "R1-v4-accepted",
		VaultID:              "vlt-test",
		Timestamp:            "2026-01-01T00:00:00.000Z",
		Repository:           &repo,
		PRNumber:             &pr,
		CanonicalFormVersion: &cfv,
		SignatureAlgorithm:   &algo,
		SigningKeyID:         &kid,
		TemporalBasis:        &tmpBasis,
	}

	_, err := dsr.CanonicalPayload(e)
	if err != nil {
		t.Fatalf("v4-jcs should be accepted; got: %v", err)
	}
}
