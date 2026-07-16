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
// Three vectors, one per DSR version:
//   DSR/1.0   — non-null incident_id, no is_synthetic
//   DSR/1.0.2 — non-null incident_id, is_synthetic=true
//   DSR/1.0.3 — null incident_id (field omitted from canonical form)
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

func TestGolden_R1N_DSR10_CanonicalBytes(t *testing.T) {
	// DSR/1.0 baseline: non-null incident_id, no is_synthetic.
	// Proves pre-1.0.3 receipts (always non-null incident_id) are byte-compatible.
	e := r1nBaseEnvelope()
	e.DSRVersion = "DSR/1.0"
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
		`"type":"R1-N","vault_id":"00000000-0000-0000-0000-000000000001","version":"DSR/1.0"}`
	if canonical != want {
		t.Errorf("canonical mismatch\n got: %s\nwant: %s", canonical, want)
	}
	const wantHash = "b0a0bbe96916acfce29dfe476623f6bb02c5d27f9e73b8bff7d6762417425e7b"
	if got := sha256Hex(canonical); got != wantHash {
		t.Errorf("SHA-256\n got: %s\nwant: %s", got, wantHash)
	}
}

func TestGolden_R1N_DSR102_CanonicalBytes(t *testing.T) {
	// DSR/1.0.2: non-null incident_id + is_synthetic=true.
	e := r1nBaseEnvelope()
	e.DSRVersion = "DSR/1.0.2"
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
		`"type":"R1-N","vault_id":"00000000-0000-0000-0000-000000000001","version":"DSR/1.0.2"}`
	if canonical != want {
		t.Errorf("canonical mismatch\n got: %s\nwant: %s", canonical, want)
	}
	const wantHash = "21d7b5c3f6a2c09f6591d29bee729149ce1e86789bee7b392db44706c1d354a5"
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
