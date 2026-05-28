// gen.go — fixture generator for internal/verify/testdata
//
// Run with:
//
//	go run ./internal/verify/testdata/gen
//
// from the repository root. This produces:
//
//	internal/verify/testdata/rsa_pss_receipt.dsr
//	internal/verify/testdata/rsa_pss_key.pub
//	internal/verify/testdata/ecdsa_receipt.dsr
//	internal/verify/testdata/ecdsa_key.pub
//
// How each was generated:
//   - RSA key: rsa.GenerateKey(rand.Reader, 2048)  →  PKIX PEM
//   - RSA-PSS sig: rsa.SignPSS(rand.Reader, priv, crypto.SHA256, sha256(payload), PSSSaltLengthAuto)
//   - ECDSA key: ecdsa.GenerateKey(elliptic.P256(), rand.Reader)  →  PKIX PEM
//   - ECDSA sig: ecdsa.SignASN1(rand.Reader, priv, sha256(payload))  →  DER-encoded
//
// The receipt payload is the canonical signed payload (sorted-key JSON) over a
// representative R1 receipt. The content_hash covers the canonical JSON content.
//
//go:generate go run .
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

func main() {
	// Locate the testdata directory relative to this file.
	_, filename, _, _ := runtime.Caller(0)
	outDir := filepath.Dir(filepath.Dir(filename)) // parent of gen/

	if err := genRSAPSS(outDir); err != nil {
		fmt.Fprintf(os.Stderr, "rsa-pss: %v\n", err)
		os.Exit(1)
	}
	if err := genECDSA(outDir); err != nil {
		fmt.Fprintf(os.Stderr, "ecdsa: %v\n", err)
		os.Exit(1)
	}
	if err := genRVi(outDir); err != nil {
		fmt.Fprintf(os.Stderr, "rv-i: %v\n", err)
		os.Exit(1)
	}
	if err := genRVf(outDir); err != nil {
		fmt.Fprintf(os.Stderr, "rv-f: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("fixtures written to", outDir)
}

// sharedReceiptFields returns the fields common to both fixture receipts.
func sharedReceiptFields(algo, keyID string) (content json.RawMessage, contentHash string, issuedAt time.Time) {
	content = json.RawMessage(`{"commit_sha":"fixture000000000000000000000000000000000000","merged_at":"2026-05-01T00:00:00Z","pr_url":"github.com/deja-dev/example#1"}`)
	sum := sha256.Sum256(content)
	contentHash = hex.EncodeToString(sum[:])
	issuedAt = time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	return
}

// canonicalPayload constructs the canonical signed payload JSON.
func canonicalPayload(id, algo, keyID, contentHash string, issuedAt time.Time) ([]byte, error) {
	payload := struct {
		ContentHash      string `json:"content_hash"`
		ID               string `json:"id"`
		IssuedAt         string `json:"issued_at"`
		SigningAlgorithm string `json:"signing_algorithm"`
		SigningKeyID     string `json:"signing_key_id"`
		Type             string `json:"type"`
		VaultID          string `json:"vault_id"`
		Version          string `json:"version"`
	}{
		ContentHash:      contentHash,
		ID:               id,
		IssuedAt:         issuedAt.UTC().Format("2006-01-02T15:04:05Z"),
		SigningAlgorithm: algo,
		SigningKeyID:     keyID,
		Type:             "R1",
		VaultID:          "vlt_fixture_byok",
		Version:          "DSR/1.0.1",
	}
	return json.Marshal(payload)
}

func writePEMKey(path string, pub interface{}, keyID string) error {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return err
	}
	block := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	data := fmt.Sprintf("# key_id: %s\n%s", keyID, string(block))
	return os.WriteFile(path, []byte(data), 0644)
}

func writeReceiptJSON(path string, id, algo, keyID, contentHash string, content json.RawMessage, issuedAt time.Time, sig []byte) error {
	receipt := map[string]interface{}{
		"id":                id,
		"version":           "DSR/1.0.1",
		"type":              "R1",
		"vault_id":          "vlt_fixture_byok",
		"issued_at":         issuedAt.UTC().Format(time.RFC3339),
		"content":           content,
		"content_hash":      contentHash,
		"signing_key_id":    keyID,
		"signing_algorithm": algo,
		"signature":         hex.EncodeToString(sig),
	}
	b, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0644)
}

func genRSAPSS(outDir string) error {
	const algo = "rsa-pss-sha256"
	const keyID = "key_fixture_rsa_pss_2026"
	const receiptID = "r_fixture_rsa_pss_001"

	// Generate RSA-2048 key pair.
	// Method: rsa.GenerateKey(rand.Reader, 2048)
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("rsa.GenerateKey: %w", err)
	}

	content, contentHash, issuedAt := sharedReceiptFields(algo, keyID)

	payload, err := canonicalPayload(receiptID, algo, keyID, contentHash, issuedAt)
	if err != nil {
		return err
	}

	// Sign: rsa.SignPSS with SHA-256 digest and PSSSaltLengthAuto.
	hashed := sha256.Sum256(payload)
	opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: crypto.SHA256}
	sig, err := rsa.SignPSS(rand.Reader, priv, crypto.SHA256, hashed[:], opts)
	if err != nil {
		return fmt.Errorf("rsa.SignPSS: %w", err)
	}

	if err := writePEMKey(filepath.Join(outDir, "rsa_pss_key.pub"), &priv.PublicKey, keyID); err != nil {
		return err
	}
	return writeReceiptJSON(filepath.Join(outDir, "rsa_pss_receipt.dsr"),
		receiptID, algo, keyID, contentHash, content, issuedAt, sig)
}

func genECDSA(outDir string) error {
	const algo = "ecdsa-sha256"
	const keyID = "key_fixture_ecdsa_2026"
	const receiptID = "r_fixture_ecdsa_001"

	// Generate P-256 ECDSA key pair.
	// Method: ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("ecdsa.GenerateKey: %w", err)
	}

	content, contentHash, issuedAt := sharedReceiptFields(algo, keyID)

	payload, err := canonicalPayload(receiptID, algo, keyID, contentHash, issuedAt)
	if err != nil {
		return err
	}

	// Sign: ecdsa.SignASN1 produces DER-encoded signature (same as AWS KMS output).
	hashed := sha256.Sum256(payload)
	sig, err := ecdsa.SignASN1(rand.Reader, priv, hashed[:])
	if err != nil {
		return fmt.Errorf("ecdsa.SignASN1: %w", err)
	}

	if err := writePEMKey(filepath.Join(outDir, "ecdsa_key.pub"), &priv.PublicKey, keyID); err != nil {
		return err
	}
	return writeReceiptJSON(filepath.Join(outDir, "ecdsa_receipt.dsr"),
		receiptID, algo, keyID, contentHash, content, issuedAt, sig)
}

// ─────────────────────────────────────────────────────────────────────────────
// RV-i / RV-f fixture generation
// ─────────────────────────────────────────────────────────────────────────────

// rvFields holds the RV-specific signing fields that go into the RV canonical payload.
type rvFields struct {
	checksPassed            []string
	issuedAt                string // ISO 8601 string — preserved verbatim in canonical form
	receiptID               string
	receiptsAttestedCount   int
	rvType                  string
	vaultID                 string
	verificationCompletedAt string
	verificationMode        string
	verificationRunID       string
	verificationStartedAt   string
}

// canonicalRvPayload produces the 10-field sorted-key JSON payload matching
// canonicaliseRvReceipt() in rv-receipt-canonical.ts.
//
// Field order must be Unicode code-point alphabetical:
//   checks_passed, issued_at, receipt_id, receipts_attested_count, rv_type,
//   vault_id, verification_completed_at, verification_mode,
//   verification_run_id, verification_started_at
func canonicalRvPayload(f rvFields) ([]byte, error) {
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
		ChecksPassed:            f.checksPassed,
		IssuedAt:                f.issuedAt,
		ReceiptID:               f.receiptID,
		ReceiptsAttestedCount:   f.receiptsAttestedCount,
		RvType:                  f.rvType,
		VaultID:                 f.vaultID,
		VerificationCompletedAt: f.verificationCompletedAt,
		VerificationMode:        f.verificationMode,
		VerificationRunID:       f.verificationRunID,
		VerificationStartedAt:   f.verificationStartedAt,
	}
	return json.Marshal(payload)
}

// writeRVReceiptJSON writes an RV receipt to path.
func writeRVReceiptJSON(path string, receiptType string, f rvFields, contentHash string, content json.RawMessage, sig []byte) error {
	receipt := map[string]interface{}{
		"id":                       f.receiptID,
		"version":                  "DSR/1.0",
		"type":                     receiptType,
		"vault_id":                 f.vaultID,
		"issued_at":                f.issuedAt,
		"content":                  content,
		"content_hash":             contentHash,
		"signing_key_id":           "key_fixture_rv_2026",
		"signing_algorithm":        "ed25519",
		"signature":                hex.EncodeToString(sig),
		"checks_passed":            f.checksPassed,
		"receipts_attested_count":  f.receiptsAttestedCount,
		"rv_type":                  f.rvType,
		"verification_run_id":      f.verificationRunID,
		"verification_mode":        f.verificationMode,
		"verification_started_at":  f.verificationStartedAt,
		"verification_completed_at": f.verificationCompletedAt,
	}
	b, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0644)
}

// genRVi generates an RV-i (incremental run) fixture receipt + key pair.
// Method: ed25519.GenerateKey, sign RV canonical payload.
func genRVi(outDir string) error {
	const receiptType = "RV-i"

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("ed25519.GenerateKey: %w", err)
	}

	content := json.RawMessage(`{"anomalies":0,"scan_at":"2026-05-01T00:00:00.000Z"}`)
	sum := sha256.Sum256(content)
	contentHash := hex.EncodeToString(sum[:])

	f := rvFields{
		checksPassed:            []string{"chain_integrity", "signature_validity", "content_hash", "key_authority", "cross_vault_isolation"},
		issuedAt:                "2026-05-01T00:00:30.000Z",
		receiptID:               "rv_fixture_rvi_001",
		receiptsAttestedCount:   42,
		rvType:                  "rv-i",
		vaultID:                 "vlt_fixture_rv",
		verificationCompletedAt: "2026-05-01T00:00:28.000Z",
		verificationMode:        "incremental",
		verificationRunID:       "run_fixture_rvi_001",
		verificationStartedAt:   "2026-05-01T00:00:00.000Z",
	}

	payload, err := canonicalRvPayload(f)
	if err != nil {
		return fmt.Errorf("canonicalRvPayload: %w", err)
	}

	sig := ed25519.Sign(priv, payload)

	if err := writePEMKey(filepath.Join(outDir, "rv_i_key.pub"), pub, "key_fixture_rv_2026"); err != nil {
		return err
	}
	return writeRVReceiptJSON(filepath.Join(outDir, "rv_i_receipt.dsr"), receiptType, f, contentHash, content, sig)
}

// genRVf generates an RV-f (full run) fixture receipt + key pair.
// Method: ed25519.GenerateKey, sign RV canonical payload.
func genRVf(outDir string) error {
	const receiptType = "RV-f"

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("ed25519.GenerateKey: %w", err)
	}

	content := json.RawMessage(`{"anomalies":0,"scan_at":"2026-05-01T01:00:00.000Z"}`)
	sum := sha256.Sum256(content)
	contentHash := hex.EncodeToString(sum[:])

	f := rvFields{
		checksPassed:            []string{"chain_integrity", "signature_validity", "content_hash", "key_authority", "cross_vault_isolation", "rv_freshness"},
		issuedAt:                "2026-05-01T01:05:00.000Z",
		receiptID:               "rv_fixture_rvf_001",
		receiptsAttestedCount:   1250,
		rvType:                  "rv-f",
		vaultID:                 "vlt_fixture_rv",
		verificationCompletedAt: "2026-05-01T01:04:55.000Z",
		verificationMode:        "full",
		verificationRunID:       "run_fixture_rvf_001",
		verificationStartedAt:   "2026-05-01T01:00:00.000Z",
	}

	payload, err := canonicalRvPayload(f)
	if err != nil {
		return fmt.Errorf("canonicalRvPayload: %w", err)
	}

	sig := ed25519.Sign(priv, payload)

	if err := writePEMKey(filepath.Join(outDir, "rv_f_key.pub"), pub, "key_fixture_rv_2026"); err != nil {
		return err
	}
	return writeRVReceiptJSON(filepath.Join(outDir, "rv_f_receipt.dsr"), receiptType, f, contentHash, content, sig)
}
