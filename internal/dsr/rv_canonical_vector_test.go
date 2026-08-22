package dsr_test

// rv_canonical_vector_test.go — implementation-assert vector tests for all RV
// and RE canonical forms.
//
// Each test reads a protocol vector file, builds a DSR Envelope from its "input"
// fields, calls CanonicalPayload(), and asserts the output matches the pinned
// canonical_json bytes and canonical_sha256.
//
// Vector files are the authoritative source; the Go implementation generates the
// actual value independently. Any drift in the canonical functions fails the test.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/deja-app/dsr-verifier-cli/internal/dsr"
)

// ─── RV-Run (integrity-monitor) vector ────────────────────────────────────

// rvRunVectorInput mirrors the camelCase "input" object in rv-canonical-vector.json.
type rvRunVectorInput struct {
	ReceiptID               string   `json:"receiptId"`
	RVType                  string   `json:"rvType"`
	VaultID                 string   `json:"vaultId"`
	VerificationRunID       string   `json:"verificationRunId"`
	VerificationMode        string   `json:"verificationMode"`
	ReceiptsAttestedCount   int64    `json:"receiptsAttestedCount"`
	ChecksPassed            []string `json:"checksPassed"`
	VerificationStartedAt   string   `json:"verificationStartedAt"`
	VerificationCompletedAt string   `json:"verificationCompletedAt"`
	IssuedAt                string   `json:"issuedAt"`
	VerificationResult      string   `json:"verificationResult"`
	FailedCheckType         *string  `json:"failedCheckType"`
	FailureReason           *string  `json:"failureReason"`
}

type rvRunVectorFile struct {
	Input           rvRunVectorInput `json:"input"`
	CanonicalJSON   string           `json:"canonical_json"`
	CanonicalSHA256 string           `json:"canonical_sha256"`
}

func TestGolden_RV_CanonicalVector(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/protocol/rv-canonical-vector.json")
	if err != nil {
		t.Fatalf("read vector file: %v", err)
	}
	var vec rvRunVectorFile
	if err := json.Unmarshal(raw, &vec); err != nil {
		t.Fatalf("parse vector file: %v", err)
	}

	inp := vec.Input
	attested := inp.ReceiptsAttestedCount
	e := &dsr.Envelope{
		Type:                    dsr.TypeRV,
		ReceiptID:               inp.ReceiptID,
		VaultID:                 inp.VaultID,
		Timestamp:               inp.IssuedAt,
		Actor:                   "system:verifier",
		Origin:                  "production",
		Signature:               "placeholder",
		IssuedAt:                &inp.IssuedAt,
		RVType:                  &inp.RVType,
		VerificationRunID:       &inp.VerificationRunID,
		VerificationMode:        &inp.VerificationMode,
		ReceiptsAttestedCount:   &attested,
		ChecksPassed:            inp.ChecksPassed,
		VerificationStartedAt:   &inp.VerificationStartedAt,
		VerificationCompletedAt: &inp.VerificationCompletedAt,
		VerificationResult:      &inp.VerificationResult,
		FailedCheckType:         inp.FailedCheckType,
		FailureReason:           inp.FailureReason,
	}

	assertCanonical(t, e, vec.CanonicalJSON, vec.CanonicalSHA256)
}

// ─── RV-Manual (sde_verification_receipts) vector ─────────────────────────

type rvManualVectorInput struct {
	Actor                string  `json:"actor"`
	EngagementID         string  `json:"engagementId"`
	InvalidCount         int64   `json:"invalidCount"`
	IssuedAt             string  `json:"issuedAt"`
	PreviousHash         *string `json:"previousHash"`
	ReceiptID            string  `json:"receiptId"`
	Type                 string  `json:"type"`
	ValidCount           int64   `json:"validCount"`
	VaultID              string  `json:"vaultId"`
	VerificationResult   string  `json:"verificationResult"`
	VerifiedReceiptCount int64   `json:"verifiedReceiptCount"`
	VerifierClient       string  `json:"verifierClient"`
	VerifierIdentityHash string  `json:"verifierIdentityHash"`
	Version              string  `json:"version"`
}

type rvManualVectorFile struct {
	Input           rvManualVectorInput `json:"input"`
	CanonicalJSON   string              `json:"canonical_json"`
	CanonicalSHA256 string              `json:"canonical_sha256"`
}

func TestGolden_RVManual_CanonicalVector(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/protocol/rv-manual-canonical-vector.json")
	if err != nil {
		t.Fatalf("read vector file: %v", err)
	}
	var vec rvManualVectorFile
	if err := json.Unmarshal(raw, &vec); err != nil {
		t.Fatalf("parse vector file: %v", err)
	}

	inp := vec.Input
	valid := inp.ValidCount
	invalid := inp.InvalidCount
	verified := inp.VerifiedReceiptCount
	e := &dsr.Envelope{
		Type:                 dsr.TypeRV,
		ReceiptID:            inp.ReceiptID,
		VaultID:              inp.VaultID,
		DSRVersion:           inp.Version,
		Timestamp:            inp.IssuedAt,
		Actor:                inp.Actor,
		Signature:            "placeholder",
		IssuedAt:             &inp.IssuedAt,
		EngagementID:         &inp.EngagementID,
		ValidCount:           &valid,
		InvalidCount:         &invalid,
		VerifiedReceiptCount: &verified,
		VerificationResult:   &inp.VerificationResult,
		VerifierClient:       &inp.VerifierClient,
		VerifierIdentityHash: &inp.VerifierIdentityHash,
		PreviousHash:         inp.PreviousHash,
		// RVType intentionally nil — selects rvManualCanonical path
	}

	assertCanonical(t, e, vec.CanonicalJSON, vec.CanonicalSHA256)
}

// ─── RE (sde_engagement_receipts) vector ──────────────────────────────────

type reVectorInput struct {
	Actor          string   `json:"actor"`
	EngagementID   string   `json:"engagementId"`
	ExpiresAt      string   `json:"expiresAt"`
	IssuedAt       string   `json:"issuedAt"`
	Permissions    []string `json:"permissions"`
	PriorHash      *string  `json:"priorHash"`
	ReceiptID      string   `json:"receiptId"`
	ReceiptsInScope int64   `json:"receiptsInScope"`
	RecipientHash  string   `json:"recipientHash"`
	RevokedAt      *string  `json:"revokedAt"`
	ScopeHash      string   `json:"scopeHash"`
	Type           string   `json:"type"`
	VaultID        string   `json:"vaultId"`
	Version        string   `json:"version"`
}

type reVectorFile struct {
	Input           reVectorInput `json:"input"`
	CanonicalJSON   string        `json:"canonical_json"`
	CanonicalSHA256 string        `json:"canonical_sha256"`
}

func TestGolden_RE_CanonicalVector(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/protocol/re-canonical-vector.json")
	if err != nil {
		t.Fatalf("read vector file: %v", err)
	}
	var vec reVectorFile
	if err := json.Unmarshal(raw, &vec); err != nil {
		t.Fatalf("parse vector file: %v", err)
	}

	inp := vec.Input
	scope := inp.ReceiptsInScope
	e := &dsr.Envelope{
		Type:           dsr.TypeRE,
		ReceiptID:      inp.ReceiptID,
		VaultID:        inp.VaultID,
		DSRVersion:     inp.Version,
		Timestamp:      inp.IssuedAt,
		Actor:          inp.Actor,
		Signature:      "placeholder",
		IssuedAt:       &inp.IssuedAt,
		EngagementID:   &inp.EngagementID,
		ExpiresAt:      &inp.ExpiresAt,
		RecipientHash:  &inp.RecipientHash,
		ReceiptsInScope: &scope,
		ScopeHash:      &inp.ScopeHash,
		Permissions:    inp.Permissions,
		PriorHash:      inp.PriorHash,
		RevokedAt:      inp.RevokedAt,
	}

	assertCanonical(t, e, vec.CanonicalJSON, vec.CanonicalSHA256)
}

// ─── helpers ──────────────────────────────────────────────────────────────

func assertCanonical(t *testing.T, e *dsr.Envelope, wantJSON, wantSHA256 string) {
	t.Helper()
	canonical, err := dsr.CanonicalPayload(e)
	if err != nil {
		t.Fatalf("CanonicalPayload: %v", err)
	}
	if canonical != wantJSON {
		t.Errorf("canonical bytes mismatch\n got: %s\nwant: %s", canonical, wantJSON)
	}
	sum := sha256.Sum256([]byte(canonical))
	got := hex.EncodeToString(sum[:])
	if got != wantSHA256 {
		t.Errorf("canonical SHA-256\n got: %s\nwant: %s", got, wantSHA256)
	}
}
