package dsr_test

// rv_canonical_vector_test.go — implementation-assert vector test for the RV canonical form.
//
// This test reads testdata/protocol/rv-canonical-vector.json, builds a DSR Envelope
// from the "input" fields, calls CanonicalPayload(), and asserts the output matches
// the pinned "canonical_json" bytes and "canonical_sha256" in the vector file.
//
// This is what makes it an implementation-assert test rather than a file-match check:
// the expected value (canonical_json) lives in the vector file, which is maintained by
// the wallow monorepo. The Go implementation generates the actual value independently.
// Any drift in rvCanonical() will fail this test even if the vector file is intact.
//
// Contrast with the CI "Vector parity" step (ci.yml), which only confirms the vendored
// JSON file has not drifted from the wallow authoritative copy. Both checks are needed:
//   - File-match: vendor drift (JSON edited without updating the Go implementation)
//   - This test: implementation drift (Go implementation produces wrong bytes)

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/deja-app/dsr-verifier-cli/internal/dsr"
)

// rvVectorInput mirrors the camelCase "input" object in rv-canonical-vector.json.
type rvVectorInput struct {
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

type rvVectorFile struct {
	Input           rvVectorInput `json:"input"`
	CanonicalJSON   string        `json:"canonical_json"`
	CanonicalSHA256 string        `json:"canonical_sha256"`
}

func TestGolden_RV_CanonicalVector(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/protocol/rv-canonical-vector.json")
	if err != nil {
		t.Fatalf("read vector file: %v", err)
	}
	var vec rvVectorFile
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

	canonical, err := dsr.CanonicalPayload(e)
	if err != nil {
		t.Fatalf("CanonicalPayload: %v", err)
	}

	if canonical != vec.CanonicalJSON {
		t.Errorf("canonical bytes mismatch\n got: %s\nwant: %s", canonical, vec.CanonicalJSON)
	}

	sum := sha256.Sum256([]byte(canonical))
	got := hex.EncodeToString(sum[:])
	if got != vec.CanonicalSHA256 {
		t.Errorf("canonical SHA-256\n got: %s\nwant: %s", got, vec.CanonicalSHA256)
	}
}
