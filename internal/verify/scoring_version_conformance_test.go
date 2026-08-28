package verify_test

// scoring_version_conformance_test.go — DSR/1.0.5 conformance gate for
// scoring_version on R1-L and R1-N receipt types.
//
// "one-directional testing is exactly how the field went missing for a week"
//
// Two directions are tested for each type:
//
//  Pre-1.0.9 (scoring_version nil): sign → verify → PASS, and "scoring_version"
//  must be absent from canonical bytes. Proves backward compat — no existing
//  signature breaks when the CLI is updated.
//
//  Post-1.0.9 (scoring_version "1.0.9"): sign → verify → PASS, and
//  "scoring_version" must be present in canonical bytes. Proves forward compat —
//  receipts issued after the 1.0.9 bump can be verified by this binary.
//
// Algorithm:
//   R1-N — Ed25519 (ed25519-v1). DSR/1.0.4 matching production.
//   R1-L — SHA-256 legacy (sha256-legacy). DSR/1.0.4 matching production.
//
// Note on R1N-0e51a9ca: Charles referenced this receipt ID as "the
// independently-verified production receipt". It does not exist in any
// connected database or fixture file (only R1N-c7ab941f-4bd3-4182-8b3d-
// b5dbf3342d46 exists in prod, issued 2026-08-03, scoring_version=null).
// These conformance tests are therefore built on synthetic envelopes that
// match the production receipt shape (DSR/1.0.4, scoring_version null for
// pre-1.0.9). The actual production receipt is a pre-1.0.9 receipt, so the
// backward-compat direction directly covers the real-world case.

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/deja-app/dsr-verifier-cli/internal/dsr"
	"github.com/deja-app/dsr-verifier-cli/internal/verify"
)

// ─────────────────────────────────────────────────────────────────────────────
// helpers local to this file
// ─────────────────────────────────────────────────────────────────────────────

// baseR1N returns a minimal R1-N envelope at DSR/1.0.4 (production shape).
// ScoringVersion is left nil by the caller.
func baseR1N() *dsr.Envelope {
	incID := "sentry:conformance-001"
	zone := "zone-prod-conformance"
	highest := "0.000"
	lookback := int64(30)
	prsEval := int64(5)
	issuedAt := "2026-08-05T12:00:00.000Z"
	algo := dsr.AlgoED25519V1
	return &dsr.Envelope{
		DSRVersion:          "DSR/1.0.4",
		Type:                dsr.TypeR1N,
		ReceiptID:           "R1N-conform-001",
		VaultID:             "vlt-conform",
		Timestamp:           issuedAt,
		Actor:               "system:sde",
		Origin:              "production",
		Signature:           "",
		IssuedAt:            &issuedAt,
		HighestCandidateCcs: &highest,
		LookbackDays:        &lookback,
		PrsEvaluated:        &prsEval,
		ServiceZone:         &zone,
		IncidentID:          &incID,
		SignatureAlgorithm:  &algo,
	}
}

// baseR1L returns a minimal R1-L envelope at DSR/1.0.4 (production shape).
// ScoringVersion is left nil by the caller.
func baseR1L() *dsr.Envelope {
	incID := "sentry:conformance-r1l-001"
	zone := "zone-prod-conformance"
	highest := "0.720"
	count := int64(3)
	issuedAt := "2026-08-05T12:00:00.000Z"
	// R1-L uses sha256-legacy — SignatureAlgorithm intentionally left nil.
	return &dsr.Envelope{
		DSRVersion:     "DSR/1.0.4",
		Type:           dsr.TypeR1L,
		ReceiptID:      "R1L-conform-001",
		VaultID:        "vlt-conform",
		Timestamp:      issuedAt,
		Actor:          "github:86881100",
		Origin:         "github",
		Signature:      "",
		IssuedAt:       &issuedAt,
		HighestCcs:     &highest,
		CandidateCount: &count,
		ServiceZone:    &zone,
		IncidentID:     &incID,
	}
}

// signR1NEd25519 signs e with the given Ed25519 private key, updating e.Signature.
func signR1NEd25519(t *testing.T, e *dsr.Envelope, priv ed25519.PrivateKey) {
	t.Helper()
	canonical, err := dsr.CanonicalPayload(e)
	if err != nil {
		t.Fatalf("CanonicalPayload: %v", err)
	}
	sig := ed25519.Sign(priv, []byte(canonical))
	e.Signature = base64.StdEncoding.EncodeToString(sig)
}

// signR1LSHA256 signs e with SHA-256 (sha256-legacy), updating e.Signature.
func signR1LSHA256(t *testing.T, e *dsr.Envelope) {
	t.Helper()
	canonical, err := dsr.CanonicalPayload(e)
	if err != nil {
		t.Fatalf("CanonicalPayload: %v", err)
	}
	sum := sha256.Sum256([]byte(canonical))
	e.Signature = hex.EncodeToString(sum[:])
}

// ─────────────────────────────────────────────────────────────────────────────
// R1-N conformance — Ed25519
// ─────────────────────────────────────────────────────────────────────────────

func TestConformance_ScoringVersion_R1N_NilScoringVersion_NullInBytes(t *testing.T) {
	// 2026-08-23 (migration 0265): scoring_version is now ALWAYS present in canonical
	// bytes as null when ScoringVersion is nil. Sign and verify both call the same
	// CanonicalPayload → the signature round-trips correctly even with nil.
	// Pre-0265 production receipts signed without scoring_version are grandfathered
	// as unverifiable under the new form; that is the accepted outcome.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}

	e := baseR1N()
	// ScoringVersion nil — produces scoring_version:null in canonical bytes
	signR1NEd25519(t, e, priv)

	// Verify canonical bytes DO contain scoring_version:null
	canonical, cerr := dsr.CanonicalPayload(e)
	if cerr != nil {
		t.Fatalf("CanonicalPayload: %v", cerr)
	}
	if !strings.Contains(canonical, `"scoring_version":null`) {
		t.Errorf("R1-N canonical must contain scoring_version:null when ScoringVersion is nil; got: %s", canonical)
	}

	// Verify signature round-trips correctly (sign + verify use same canonical form)
	provided := &verify.PublicKeyWithID{Key: pub, KeyID: "test-key-nil-sv-r1n"}
	res := verify.Signature(e, provided)
	if !res.Valid {
		t.Errorf("R1-N (nil scoring_version → scoring_version:null) must verify: %v", res.Err)
	}
}

func TestConformance_ScoringVersion_R1N_Post109_VerifiesWith(t *testing.T) {
	// Post-1.0.9 direction: scoring_version="1.0.9" → canonical bytes include the
	// field → Ed25519 signature verifies. If scoring_version is missing from the
	// canonical form after this CLI change, the signature computed at sign time will
	// differ from the canonical bytes at verify time → verification fails.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}

	sv := "1.0.9"
	e := baseR1N()
	e.ScoringVersion = &sv
	signR1NEd25519(t, e, priv)

	// Verify canonical bytes DO contain scoring_version
	canonical, cerr := dsr.CanonicalPayload(e)
	if cerr != nil {
		t.Fatalf("CanonicalPayload: %v", cerr)
	}
	if !strings.Contains(canonical, `"scoring_version":"1.0.9"`) {
		t.Errorf("post-1.0.9 R1-N canonical must contain scoring_version; got: %s", canonical)
	}

	// Verify signature round-trips correctly
	provided := &verify.PublicKeyWithID{Key: pub, KeyID: "test-key-post109-r1n"}
	res := verify.Signature(e, provided)
	if !res.Valid {
		t.Errorf("post-1.0.9 R1-N (scoring_version='1.0.9') must verify: %v", res.Err)
	}
}

func TestConformance_ScoringVersion_R1N_Tamper_FieldAddedAfterSigning(t *testing.T) {
	// Tamper guard for R1-N: sign WITHOUT scoring_version, then add it post-hoc.
	// The Ed25519 signature (over canonical bytes without the field) should no
	// longer verify once scoring_version is present in canonical bytes.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}

	e := baseR1N()
	// Sign without scoring_version
	signR1NEd25519(t, e, priv)
	savedSig := e.Signature

	// Add scoring_version after signing — canonical bytes now differ → must fail
	sv := "1.0.9"
	e.ScoringVersion = &sv
	e.Signature = savedSig

	provided := &verify.PublicKeyWithID{Key: pub, KeyID: "test-key-tamper-r1n"}
	res := verify.Signature(e, provided)
	if res.Valid {
		t.Error("R1-N: adding scoring_version after signing must invalidate the signature — field is in signed bytes")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// R1-L conformance — SHA-256 legacy
// ─────────────────────────────────────────────────────────────────────────────

func TestConformance_ScoringVersion_R1L_NilScoringVersion_NullInBytes(t *testing.T) {
	// 2026-08-23 (migration 0270): scoring_version is now ALWAYS present in canonical
	// bytes as null when ScoringVersion is nil. SHA-256 sign and verify both call the
	// same CanonicalPayload → the signature round-trips correctly even with nil.
	// Pre-0270 production receipts signed without scoring_version are grandfathered
	// as unverifiable under the new form; that is the accepted outcome.
	e := baseR1L()
	// ScoringVersion nil — produces scoring_version:null in canonical bytes
	signR1LSHA256(t, e)

	// Verify canonical bytes DO contain scoring_version:null
	canonical, cerr := dsr.CanonicalPayload(e)
	if cerr != nil {
		t.Fatalf("CanonicalPayload: %v", cerr)
	}
	if !strings.Contains(canonical, `"scoring_version":null`) {
		t.Errorf("R1-L canonical must contain scoring_version:null when ScoringVersion is nil; got: %s", canonical)
	}

	// Verify SHA-256 round-trips correctly (sign + verify use same canonical form)
	res := verify.Signature(e, nil)
	if !res.Valid {
		t.Errorf("R1-L (nil scoring_version → scoring_version:null) must verify: %v", res.Err)
	}
	if res.Algorithm != dsr.AlgoSHA256Legacy {
		t.Errorf("R1-L must use sha256-legacy; got: %s", res.Algorithm)
	}
}

func TestConformance_ScoringVersion_R1L_Post109_VerifiesWith(t *testing.T) {
	// Post-1.0.9 direction: scoring_version="1.0.9" → SHA-256 includes the field →
	// verifier reconstructs same bytes → signature matches. If scoring_version is
	// missing from the canonical form, the SHA-256 will differ → verification fails.
	sv := "1.0.9"
	e := baseR1L()
	e.ScoringVersion = &sv
	signR1LSHA256(t, e)

	// Verify canonical bytes DO contain scoring_version
	canonical, cerr := dsr.CanonicalPayload(e)
	if cerr != nil {
		t.Fatalf("CanonicalPayload: %v", cerr)
	}
	if !strings.Contains(canonical, `"scoring_version":"1.0.9"`) {
		t.Errorf("post-1.0.9 R1-L canonical must contain scoring_version; got: %s", canonical)
	}

	// Verify SHA-256 round-trips correctly
	res := verify.Signature(e, nil)
	if !res.Valid {
		t.Errorf("post-1.0.9 R1-L (scoring_version='1.0.9') must verify: %v", res.Err)
	}
}

func TestConformance_ScoringVersion_R1L_Tamper_FieldAddedAfterSigning(t *testing.T) {
	// Tamper guard: sign WITHOUT scoring_version, then add it post-hoc.
	// The SHA-256 should no longer match, proving the field is in the signed payload.
	e := baseR1L()
	signR1LSHA256(t, e)
	savedSig := e.Signature

	sv := "1.0.9"
	e.ScoringVersion = &sv
	// Re-verify with old signature — canonical bytes now differ → must fail
	e.Signature = savedSig
	res := verify.Signature(e, nil)
	if res.Valid {
		t.Error("R1-L: adding scoring_version after signing must invalidate the signature — field is not in signed bytes")
	}
}
