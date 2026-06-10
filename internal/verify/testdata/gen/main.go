//go:build ignore

// gen/main.go generates parity test fixtures for internal/verify/testdata/.
//
// Usage:
//
//	DEJA_SIGNING_PRIVATE_KEY=<base64-raw-32-bytes> go run ./internal/verify/testdata/gen/main.go
//
// The private key is the same key used by the wallow issuer (DEJA_SIGNING_PRIVATE_KEY).
// The public key (DEJA_SIGNING_PUBLIC_KEY) is read from the keys/ directory.
//
// Fixtures written:
//
//	testdata/managed-r1.dsr            R1 receipt signed by ed25519-v1
//	testdata/managed-pubkey.b64        Base64 raw Ed25519 public key
//	testdata/managed-r1-tampered.dsr   Same R1 with ccs_score mutated (must FAIL)
//	testdata/managed-r2.dsr            R2 receipt signed by ed25519-v1
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/deja-dev/dsr-verifier-cli/internal/dsr"
)

const keyID = "deja-managed-v1"
const outDir = "internal/verify/testdata"

func main() {
	privKeyB64 := os.Getenv("DEJA_SIGNING_PRIVATE_KEY")
	if privKeyB64 == "" {
		fmt.Fprintln(os.Stderr, "DEJA_SIGNING_PRIVATE_KEY is not set")
		os.Exit(1)
	}
	privRaw, err := base64.StdEncoding.DecodeString(privKeyB64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "decode private key: %v\n", err)
		os.Exit(1)
	}
	if len(privRaw) != 32 {
		fmt.Fprintf(os.Stderr, "private key must be 32 bytes, got %d\n", len(privRaw))
		os.Exit(1)
	}
	privKey := ed25519.NewKeyFromSeed(privRaw)
	pubKey := privKey.Public().(ed25519.PublicKey)
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKey)

	// Write public key file.
	must(writeFile(filepath.Join(outDir, "managed-pubkey.b64"), []byte(pubKeyB64)))
	fmt.Println("wrote managed-pubkey.b64")

	// R1 receipt.
	prNum := int64(4287)
	algo := dsr.AlgoED25519V1
	keyIDStr := keyID
	r1 := &dsr.Envelope{
		DSRVersion:          "DSR/1.0.2",
		Type:                dsr.TypeR1,
		ReceiptID:           "rcpt_parity_r1_001",
		VaultID:             "vlt_parity_test",
		Timestamp:           "2026-06-10T09:00:00Z",
		Actor:               "scott@deja.dev",
		Origin:              "github",
		Signature:           "",
		SignatureAlgorithm:  &algo,
		SigningKeyID:        &keyIDStr,
		Repository:          strPtr("github.com/parity-test-org/payments-api"),
		PRNumber:            &prNum,
		ServiceZone:         strPtr("us-east-1"),
		CCSScore:            strPtr("0.8750"),
		Confidence:          strPtr("high"),
		Matched:             strPtr("true"),
	}
	r1JSON := signAndSerialise(t(r1), privKey)
	must(writeFile(filepath.Join(outDir, "managed-r1.dsr"), r1JSON))
	fmt.Println("wrote managed-r1.dsr")

	// Tampered R1: mutate ccs_score after signing → signature mismatch.
	var tampered map[string]interface{}
	if err := json.Unmarshal(r1JSON, &tampered); err != nil {
		fatal("unmarshal r1 for tampering: %v", err)
	}
	tampered["ccs_score"] = "0.9999"
	tamperedJSON, _ := json.Marshal(tampered)
	must(writeFile(filepath.Join(outDir, "managed-r1-tampered.dsr"), tamperedJSON))
	fmt.Println("wrote managed-r1-tampered.dsr")

	// R2 receipt (references the R1).
	r1ID := "rcpt_parity_r1_001"
	ttr := int64(3600000)
	gateEval := "2026-06-10T10:00:00Z"
	resolvedAt := "2026-06-10T10:00:00Z"
	r2 := &dsr.Envelope{
		DSRVersion:           "DSR/1.0.2",
		Type:                 dsr.TypeR2,
		ReceiptID:            "rcpt_parity_r2_001",
		VaultID:              "vlt_parity_test",
		Timestamp:            "2026-06-10T10:00:00Z",
		Actor:                "scott@deja.dev",
		Origin:               "github",
		Signature:            "",
		SignatureAlgorithm:   &algo,
		SigningKeyID:         &keyIDStr,
		AttributionReceiptID: &r1ID,
		IncidentID:           strPtr("inc_parity_001"),
		ResolvedAt:           &resolvedAt,
		TimeToResolutionMs:   &ttr,
		GateEvaluatedAt:      &gateEval,
		GatesPassed:          boolPtr(true),
		ServiceZone:          strPtr("us-east-1"),
		FileGateScore:        strPtr("0.9000"),
		RateGateScore:        strPtr("0.9000"),
		InfraGateScore:       strPtr("0.9000"),
		FeatureGateScore:     strPtr("0.9000"),
		DurationGateScore:    strPtr("0.9000"),
	}
	r2JSON := signAndSerialise(t(r2), privKey)
	must(writeFile(filepath.Join(outDir, "managed-r2.dsr"), r2JSON))
	fmt.Println("wrote managed-r2.dsr")

	fmt.Printf("\nAll fixtures written to %s/\n", outDir)
	fmt.Printf("Public key: %s\n", pubKeyB64)
}

// signAndSerialise computes the canonical payload, signs it, then marshals
// the complete Envelope with the base64 signature set.
func signAndSerialise(e *dsr.Envelope, privKey ed25519.PrivateKey) []byte {
	payload, err := dsr.CanonicalPayload(e)
	if err != nil {
		fatal("CanonicalPayload: %v", err)
	}
	sig := ed25519.Sign(privKey, []byte(payload))
	e.Signature = base64.StdEncoding.EncodeToString(sig)

	b, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		fatal("marshal envelope: %v", err)
	}
	return b
}

func t(e *dsr.Envelope) *dsr.Envelope { return e }

func strPtr(s string) *string { return &s }
func boolPtr(b bool) *bool    { return &b }

func writeFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func must(err error) {
	if err != nil {
		fatal("%v", err)
	}
}

func fatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}
