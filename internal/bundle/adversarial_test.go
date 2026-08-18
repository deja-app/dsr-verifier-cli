package bundle_test

// adversarial_test.go — bundle-level attack scenarios.
//
// Every test here attempts an attack. Each must be caught by the verifier.
// Pass criterion (card "Why does the verifier have no adversarial tests?"):
//
//   A0. Baseline          — clean bundle passes (guard: helpers are correct)
//   A1. Tampered payload  — flip a byte in receipt JSON after signing
//   A2. Forged signature  — random/zero bytes instead of a real signature
//   A3. Relabeled version — change dsr_version without re-signing
//   A4. Truncated bundle  — manifest references a receipt absent from ZIP
//   A5. Manifest tampered — change bundle_id after manifest is signed

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/deja-app/dsr-verifier-cli/internal/bundle"
	"github.com/deja-app/dsr-verifier-cli/internal/verify"
)

// ─────────────────────────────────────────────────────────────────────────────
// A0. Baseline — clean bundle passes (guard)
// ─────────────────────────────────────────────────────────────────────────────

func TestAdversarial_CleanBundle_Passes(t *testing.T) {
	pub, priv := makeEd25519Pair(t)
	zipBytes, _, _ := singleReceiptBundle(t, pub, priv)

	b, err := bundle.ParseBundleFromBytes(zipBytes)
	if err != nil {
		t.Fatalf("ParseBundleFromBytes (clean): %v", err)
	}
	provided, keyErr := verify.ParsePublicKeyFile(ed25519B64Key(pub, "key_bundle_test"))
	if keyErr != nil {
		t.Fatalf("ParsePublicKeyFile: %v", keyErr)
	}
	res := bundle.VerifyBundle(b, provided)
	if !res.AllPassed() {
		t.Fatalf("clean bundle should pass all checks: manifest_sig=%v seq=%v per_receipt_failed=%d",
			res.ManifestSig.Valid, res.SequenceInteg.Valid, res.PerReceipt.Failed)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// A1. Tampered payload — flip one byte in receipt JSON after signing
// ─────────────────────────────────────────────────────────────────────────────

func TestAdversarial_TamperedPayload_SignatureRejected(t *testing.T) {
	pub, priv := makeEd25519Pair(t)
	_, entry, rJSON := singleReceiptBundle(t, pub, priv)

	if len(rJSON) < 60 {
		t.Fatalf("receipt JSON unexpectedly short: %d bytes", len(rJSON))
	}
	tampered := bytes.Clone(rJSON)
	tampered[50] ^= 0x01 // flip one bit mid-body

	// Re-sign the manifest (with original entry hash, pointing to the tampered file).
	m := minimalManifest(t, pub, priv, []bundle.ManifestEntry{entry})
	zipBytes := buildZIP(t, m, map[string][]byte{entry.Filename: tampered})

	b, parseErr := bundle.ParseBundleFromBytes(zipBytes)
	if parseErr != nil {
		// Flipped byte may break JSON parse — that is also a valid rejection.
		t.Logf("parse rejected tampered JSON: %v", parseErr)
		return
	}
	provided, keyErr := verify.ParsePublicKeyFile(ed25519B64Key(pub, "key_bundle_test"))
	if keyErr != nil {
		t.Fatalf("ParsePublicKeyFile: %v", keyErr)
	}
	res := bundle.VerifyBundle(b, provided)
	if res.PerReceipt.Failed == 0 {
		t.Errorf("tampered payload should be detected: per_receipt_failed=%d", res.PerReceipt.Failed)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// A2. Forged signature — zero bytes replace the receipt's signature field
// ─────────────────────────────────────────────────────────────────────────────

func TestAdversarial_ForgedSignature_Rejected(t *testing.T) {
	pub, priv := makeEd25519Pair(t)

	receipt := minimalR1(t, "rcpt_forged", priv)
	// Replace valid signature with 64 zero bytes (structurally valid base64,
	// not a valid Ed25519 signature over the canonical payload).
	receipt.Signature = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

	rJSON := envelopeJSON(t, receipt)
	filename := "receipts/00001_rcpt_forged.dsr"
	entry := bundle.ManifestEntry{
		Seq: 1, ReceiptID: receipt.ReceiptID, Type: receipt.Type,
		Filename: filename, ContentHash: contentHash(rJSON),
	}
	m := minimalManifest(t, pub, priv, []bundle.ManifestEntry{entry})
	zipBytes := buildZIP(t, m, map[string][]byte{filename: rJSON})

	b, parseErr := bundle.ParseBundleFromBytes(zipBytes)
	if parseErr != nil {
		t.Fatalf("ParseBundleFromBytes: %v", parseErr)
	}
	provided, keyErr := verify.ParsePublicKeyFile(ed25519B64Key(pub, "key_bundle_test"))
	if keyErr != nil {
		t.Fatalf("ParsePublicKeyFile: %v", keyErr)
	}
	res := bundle.VerifyBundle(b, provided)
	if res.PerReceipt.Failed == 0 {
		t.Errorf("forged signature should be rejected: per_receipt_failed=%d", res.PerReceipt.Failed)
	}
	if res.Tampered() != 1 {
		t.Errorf("expected Tampered()=1, got %d", res.Tampered())
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// A3. Relabeled dsr_version — change version string without re-signing
// ─────────────────────────────────────────────────────────────────────────────

// This is the relabeling attack discovered by reading code this week:
// an attacker changes dsr_version to claim a newer spec without possessing
// the private key. The canonical form includes dsr_version, so the
// existing signature does not cover the new value.
func TestAdversarial_RelabeledDSRVersion_SignatureRejected(t *testing.T) {
	pub, priv := makeEd25519Pair(t)

	receipt := minimalR1(t, "rcpt_relabeled", priv) // signed as "DSR/1.0.2"

	// Patch dsr_version without re-signing.
	var raw map[string]interface{}
	if err := json.Unmarshal(envelopeJSON(t, receipt), &raw); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	raw["dsr_version"] = "DSR/1.0.6"
	tamperedJSON, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("json.Marshal relabeled: %v", err)
	}

	filename := "receipts/00001_rcpt_relabeled.dsr"
	entry := bundle.ManifestEntry{
		Seq: 1, ReceiptID: receipt.ReceiptID, Type: receipt.Type,
		Filename: filename, ContentHash: contentHash(tamperedJSON),
	}
	m := minimalManifest(t, pub, priv, []bundle.ManifestEntry{entry})
	zipBytes := buildZIP(t, m, map[string][]byte{filename: tamperedJSON})

	b, parseErr := bundle.ParseBundleFromBytes(zipBytes)
	if parseErr != nil {
		t.Fatalf("ParseBundleFromBytes: %v", parseErr)
	}
	provided, keyErr := verify.ParsePublicKeyFile(ed25519B64Key(pub, "key_bundle_test"))
	if keyErr != nil {
		t.Fatalf("ParsePublicKeyFile: %v", keyErr)
	}
	res := bundle.VerifyBundle(b, provided)
	if res.PerReceipt.Failed == 0 {
		t.Errorf("relabeled dsr_version must be caught by signature check: per_receipt_failed=%d",
			res.PerReceipt.Failed)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// A4. Truncated bundle — manifest references a receipt absent from ZIP
// ─────────────────────────────────────────────────────────────────────────────

func TestAdversarial_TruncatedBundle_MissingReceiptRejected(t *testing.T) {
	pub, priv := makeEd25519Pair(t)

	r1 := minimalR1(t, "rcpt_001", priv)
	r2 := minimalR1(t, "rcpt_002", priv)
	rJSON1 := envelopeJSON(t, r1)
	rJSON2 := envelopeJSON(t, r2)
	fname1 := "receipts/00001_rcpt_001.dsr"
	fname2 := "receipts/00002_rcpt_002.dsr"

	entries := []bundle.ManifestEntry{
		{Seq: 1, ReceiptID: r1.ReceiptID, Type: "R1", Filename: fname1, ContentHash: contentHash(rJSON1)},
		{Seq: 2, ReceiptID: r2.ReceiptID, Type: "R1", Filename: fname2, ContentHash: contentHash(rJSON2)},
	}
	m := minimalManifest(t, pub, priv, entries)
	// Only pack r1 — r2 is missing from the ZIP.
	zipBytes := buildZIP(t, m, map[string][]byte{fname1: rJSON1})

	b, parseErr := bundle.ParseBundleFromBytes(zipBytes)
	if parseErr != nil {
		t.Fatalf("ParseBundleFromBytes: %v", parseErr)
	}
	provided, keyErr := verify.ParsePublicKeyFile(ed25519B64Key(pub, "key_bundle_test"))
	if keyErr != nil {
		t.Fatalf("ParsePublicKeyFile: %v", keyErr)
	}
	res := bundle.VerifyBundle(b, provided)
	if res.PerReceipt.Failed == 0 {
		t.Errorf("truncated bundle should count missing file as failure: per_receipt_failed=%d missing=%d",
			res.PerReceipt.Failed, res.Missing())
	}
	if res.Missing() == 0 {
		t.Errorf("Missing() should be non-zero for a truncated bundle")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// A5. Manifest tampered — change bundle_id after manifest is signed
// ─────────────────────────────────────────────────────────────────────────────

func TestAdversarial_ManifestTampered_SignatureRejected(t *testing.T) {
	pub, priv := makeEd25519Pair(t)
	_, entry, rJSON := singleReceiptBundle(t, pub, priv)

	// Build a valid signed manifest, then mutate bundle_id before packing.
	m := minimalManifest(t, pub, priv, []bundle.ManifestEntry{entry})
	m.BundleID = "bndl_ATTACKER_INJECTED" // mutation after signing

	zipBytes := buildZIP(t, m, map[string][]byte{entry.Filename: rJSON})

	b, parseErr := bundle.ParseBundleFromBytes(zipBytes)
	if parseErr != nil {
		t.Fatalf("ParseBundleFromBytes (tampered manifest): %v", parseErr)
	}
	provided, keyErr := verify.ParsePublicKeyFile(ed25519B64Key(pub, "key_bundle_test"))
	if keyErr != nil {
		t.Fatalf("ParsePublicKeyFile: %v", keyErr)
	}
	res := bundle.VerifyBundle(b, provided)
	if res.ManifestSig.Valid {
		t.Errorf("manifest with mutated bundle_id should fail signature check")
	}
}
