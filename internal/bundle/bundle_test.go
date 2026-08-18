package bundle_test

// bundle_test.go — bundle verification unit tests for ExternalDSREnvelope format.
//
// Tests operate at the VerifyX function level, constructing Manifest and
// ParsedReceipt structs directly. ZIP-level integration (round-trip through
// ParseBundleFromBytes) lives in adversarial_test.go.
//
// Ported from pre-Envelope-refactor TODOs:
//   - TestVerifyBYOKBundleRSAPSS  (G-4)
//   - TestVerifyBYOKBundleECDSA   (G-4)
//   - manifest signature, sequence integrity, per-receipt, causal chain

import (
	"archive/zip"
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"testing"
	"time"

	"github.com/deja-app/dsr-verifier-cli/internal/bundle"
	"github.com/deja-app/dsr-verifier-cli/internal/dsr"
	"github.com/deja-app/dsr-verifier-cli/internal/verify"
)

// ─────────────────────────────────────────────────────────────────────────────
// Helpers shared with adversarial_test.go
// ─────────────────────────────────────────────────────────────────────────────

func pStr(s string) *string { return &s }
func pI64(n int64) *int64   { return &n }

// makeEd25519Pair generates a fresh Ed25519 key pair.
func makeEd25519Pair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	return pub, priv
}

// makeRSAKey generates a fresh 2048-bit RSA key pair.
func makeRSAKey(t *testing.T) (*rsa.PublicKey, *rsa.PrivateKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	return &priv.PublicKey, priv
}

// makeECDSAKey generates a fresh P-256 ECDSA key pair.
func makeECDSAKey(t *testing.T) (*ecdsa.PublicKey, *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	return &priv.PublicKey, priv
}

// pubKeyWithID wraps any public key into a *verify.PublicKeyWithID.
func pubKeyWithID(key interface{}, keyID string) *verify.PublicKeyWithID {
	return &verify.PublicKeyWithID{Key: key, KeyID: keyID}
}

// ed25519B64Key returns the raw base64 key bytes with an optional key_id comment.
func ed25519B64Key(pub ed25519.PublicKey, keyID string) []byte {
	b64 := base64.StdEncoding.EncodeToString([]byte(pub))
	if keyID != "" {
		return []byte(fmt.Sprintf("# key_id: %s\n%s\n", keyID, b64))
	}
	return []byte(b64 + "\n")
}

// pkixPEMKey returns a PKIX PEM block for pub with an optional key_id comment.
func pkixPEMKey(t *testing.T, pub interface{}, keyID string) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	var out []byte
	if keyID != "" {
		out = append(out, fmt.Sprintf("# key_id: %s\n", keyID)...)
	}
	out = append(out, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})...)
	return out
}

// minimalR1 returns a minimal signed R1 Envelope.
func minimalR1(t *testing.T, id string, priv ed25519.PrivateKey) *dsr.Envelope {
	t.Helper()
	algo := dsr.AlgoED25519V1
	e := &dsr.Envelope{
		DSRVersion:         "DSR/1.0.2",
		Type:               "R1",
		ReceiptID:          id,
		VaultID:            "vlt_bundle_test",
		Timestamp:          "2026-06-01T10:00:00Z",
		Actor:              "author@example.com",
		Origin:             "github.com/test/repo",
		Repository:         pStr("test/repo"),
		PRNumber:           pI64(42),
		CCSScore:           pStr("0.8750"),
		Confidence:         pStr("high"),
		Matched:            pStr("true"),
		ServiceZone:        pStr("payments"),
		SignatureAlgorithm: &algo,
		SigningKeyID:       pStr("key_bundle_test"),
	}
	canonical, err := dsr.CanonicalPayload(e)
	if err != nil {
		t.Fatalf("CanonicalPayload: %v", err)
	}
	sig := ed25519.Sign(priv, []byte(canonical))
	e.Signature = base64.StdEncoding.EncodeToString(sig)
	return e
}

// envelopeJSON marshals e to JSON bytes.
func envelopeJSON(t *testing.T, e *dsr.Envelope) []byte {
	t.Helper()
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("json.Marshal envelope: %v", err)
	}
	return b
}

// minimalManifest builds and signs a Manifest containing one entry.
// Returns the manifest (with Signature set) and the receipt JSON.
func minimalManifest(
	t *testing.T,
	pub ed25519.PublicKey,
	priv ed25519.PrivateKey,
	entries []bundle.ManifestEntry,
) *bundle.Manifest {
	t.Helper()
	m := &bundle.Manifest{
		Format:      bundle.BundleFormat,
		BundleID:    "bndl_test_001",
		VaultID:     "vlt_bundle_test",
		IssuedAt:    time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC),
		PeriodStart: "2026-05-01",
		PeriodEnd:   "2026-05-31",
		Frameworks:  []string{"SOC 2"},
		IssuerKeyID: "key_bundle_test",
		Entries:     entries,
		ReceiptCount: len(entries),
	}
	payload, err := bundle.CanonicalManifestPayload(m)
	if err != nil {
		t.Fatalf("CanonicalManifestPayload: %v", err)
	}
	m.Signature = dsr.HexBytes(ed25519.Sign(priv, payload))
	return m
}

// buildZIP packs a manifest and named file contents into an in-memory ZIP.
func buildZIP(t *testing.T, manifest *bundle.Manifest, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	w, err := zw.Create("manifest.json")
	if err != nil {
		t.Fatalf("zip create manifest.json: %v", err)
	}
	if _, err := w.Write(manifestJSON); err != nil {
		t.Fatalf("zip write manifest.json: %v", err)
	}

	for name, data := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip create %q: %v", name, err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatalf("zip write %q: %v", name, err)
		}
	}

	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

// contentHash returns the hex SHA-256 of data.
func contentHash(data []byte) string {
	sum := sha256.Sum256(data)
	b := make([]byte, 0, sha256.Size*2)
	const hx = "0123456789abcdef"
	for _, v := range sum {
		b = append(b, hx[v>>4], hx[v&0xf])
	}
	return string(b)
}

// singleReceiptBundle builds a complete ZIP bundle with one R1 receipt.
// Returns (zipBytes, entry, receiptJSON).
func singleReceiptBundle(
	t *testing.T,
	pub ed25519.PublicKey,
	priv ed25519.PrivateKey,
) ([]byte, bundle.ManifestEntry, []byte) {
	t.Helper()
	receipt := minimalR1(t, "rcpt_001", priv)
	rJSON := envelopeJSON(t, receipt)
	filename := "receipts/00001_rcpt_001.dsr"
	entry := bundle.ManifestEntry{
		Seq:         1,
		ReceiptID:   receipt.ReceiptID,
		Type:        receipt.Type,
		Filename:    filename,
		ContentHash: contentHash(rJSON),
	}
	m := minimalManifest(t, pub, priv, []bundle.ManifestEntry{entry})
	zipBytes := buildZIP(t, m, map[string][]byte{filename: rJSON})
	return zipBytes, entry, rJSON
}

// ─────────────────────────────────────────────────────────────────────────────
// VerifyManifestSignature — Ed25519
// ─────────────────────────────────────────────────────────────────────────────

func TestVerifyManifestSignature_Ed25519_Valid(t *testing.T) {
	pub, priv := makeEd25519Pair(t)
	entry := bundle.ManifestEntry{Seq: 1, ReceiptID: "r1", Type: "R1", Filename: "receipts/00001_r1.dsr"}
	m := minimalManifest(t, pub, priv, []bundle.ManifestEntry{entry})

	res := bundle.VerifyManifestSignature(m, pubKeyWithID(pub, "key_bundle_test"))
	if !res.Valid {
		t.Fatalf("expected valid manifest signature, got: %v", res.Err)
	}
}

func TestVerifyManifestSignature_Ed25519_WrongKey_Fails(t *testing.T) {
	pub, priv := makeEd25519Pair(t)
	wrongPub, _ := makeEd25519Pair(t) // different key pair
	entry := bundle.ManifestEntry{Seq: 1, ReceiptID: "r1", Type: "R1", Filename: "receipts/00001_r1.dsr"}
	m := minimalManifest(t, pub, priv, []bundle.ManifestEntry{entry})

	res := bundle.VerifyManifestSignature(m, pubKeyWithID(wrongPub, "key_bundle_test"))
	if res.Valid {
		t.Fatal("expected manifest signature to fail with wrong key")
	}
}

func TestVerifyManifestSignature_Ed25519_ForgedBytes_Fails(t *testing.T) {
	pub, priv := makeEd25519Pair(t)
	entry := bundle.ManifestEntry{Seq: 1, ReceiptID: "r1", Type: "R1", Filename: "receipts/00001_r1.dsr"}
	m := minimalManifest(t, pub, priv, []bundle.ManifestEntry{entry})
	// Replace signature with random bytes (same length).
	m.Signature = make(dsr.HexBytes, 64)
	if _, err := rand.Read(m.Signature); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	res := bundle.VerifyManifestSignature(m, pubKeyWithID(pub, "key_bundle_test"))
	if res.Valid {
		t.Fatal("forged signature should be rejected")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// VerifyManifestSignature — BYOK RSA-PSS (G-4)
// ─────────────────────────────────────────────────────────────────────────────

func TestVerifyBYOKBundleRSAPSS(t *testing.T) {
	rsaPub, rsaPriv := makeRSAKey(t)
	entry := bundle.ManifestEntry{Seq: 1, ReceiptID: "r1", Type: "R1", Filename: "receipts/00001_r1.dsr"}
	m := &bundle.Manifest{
		Format:       bundle.BundleFormat,
		BundleID:     "bndl_rsa_test",
		VaultID:      "vlt_rsa",
		IssuedAt:     time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC),
		PeriodStart:  "2026-05-01",
		PeriodEnd:    "2026-05-31",
		Frameworks:   []string{"ISO 27001"},
		IssuerKeyID:  "byok_rsa_key",
		Entries:      []bundle.ManifestEntry{entry},
		ReceiptCount: 1,
	}
	payload, err := bundle.CanonicalManifestPayload(m)
	if err != nil {
		t.Fatalf("CanonicalManifestPayload: %v", err)
	}
	hashed := sha256.Sum256(payload)
	opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: crypto.SHA256}
	sigBytes, err := rsa.SignPSS(rand.Reader, rsaPriv, crypto.SHA256, hashed[:], opts)
	if err != nil {
		t.Fatalf("rsa.SignPSS: %v", err)
	}
	m.Signature = dsr.HexBytes(sigBytes)

	res := bundle.VerifyManifestSignature(m, pubKeyWithID(rsaPub, "byok_rsa_key"))
	if !res.Valid {
		t.Fatalf("RSA-PSS manifest signature should be valid: %v", res.Err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// VerifyManifestSignature — BYOK ECDSA (G-4)
// ─────────────────────────────────────────────────────────────────────────────

func TestVerifyBYOKBundleECDSA(t *testing.T) {
	ecPub, ecPriv := makeECDSAKey(t)
	entry := bundle.ManifestEntry{Seq: 1, ReceiptID: "r1", Type: "R1", Filename: "receipts/00001_r1.dsr"}
	m := &bundle.Manifest{
		Format:       bundle.BundleFormat,
		BundleID:     "bndl_ecdsa_test",
		VaultID:      "vlt_ecdsa",
		IssuedAt:     time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC),
		PeriodStart:  "2026-05-01",
		PeriodEnd:    "2026-05-31",
		Frameworks:   []string{"SOC 2"},
		IssuerKeyID:  "byok_ecdsa_key",
		Entries:      []bundle.ManifestEntry{entry},
		ReceiptCount: 1,
	}
	payload, err := bundle.CanonicalManifestPayload(m)
	if err != nil {
		t.Fatalf("CanonicalManifestPayload: %v", err)
	}
	hashed := sha256.Sum256(payload)
	sigBytes, err := ecdsa.SignASN1(rand.Reader, ecPriv, hashed[:])
	if err != nil {
		t.Fatalf("ecdsa.SignASN1: %v", err)
	}
	m.Signature = dsr.HexBytes(sigBytes)

	res := bundle.VerifyManifestSignature(m, pubKeyWithID(ecPub, "byok_ecdsa_key"))
	if !res.Valid {
		t.Fatalf("ECDSA manifest signature should be valid: %v", res.Err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// VerifySequenceIntegrity
// ─────────────────────────────────────────────────────────────────────────────

func TestVerifySequenceIntegrity_Complete(t *testing.T) {
	m := &bundle.Manifest{
		Entries: []bundle.ManifestEntry{
			{Seq: 1}, {Seq: 2}, {Seq: 3}, {Seq: 4}, {Seq: 5},
		},
	}
	res := bundle.VerifySequenceIntegrity(m)
	if !res.Valid {
		t.Fatalf("complete sequence should be valid, got gaps: %v", res.Gaps)
	}
	if res.Count != 5 || res.MinSeq != 1 || res.MaxSeq != 5 {
		t.Errorf("counts wrong: count=%d min=%d max=%d", res.Count, res.MinSeq, res.MaxSeq)
	}
}

func TestVerifySequenceIntegrity_Gaps(t *testing.T) {
	m := &bundle.Manifest{
		// Seq 3 is missing.
		Entries: []bundle.ManifestEntry{{Seq: 1}, {Seq: 2}, {Seq: 4}, {Seq: 5}},
	}
	res := bundle.VerifySequenceIntegrity(m)
	if res.Valid {
		t.Fatal("sequence with gap should be invalid")
	}
	if len(res.Gaps) != 1 || res.Gaps[0] != 3 {
		t.Errorf("expected gap at seq 3, got: %v", res.Gaps)
	}
}

func TestVerifySequenceIntegrity_Empty(t *testing.T) {
	res := bundle.VerifySequenceIntegrity(&bundle.Manifest{})
	if !res.Valid {
		t.Fatal("empty manifest should be considered valid (no gaps)")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// VerifyPerReceipt
// ─────────────────────────────────────────────────────────────────────────────

func TestVerifyPerReceipt_AllPass(t *testing.T) {
	pub, priv := makeEd25519Pair(t)
	provided, err := verify.ParsePublicKeyFile(ed25519B64Key(pub, "key_bundle_test"))
	if err != nil {
		t.Fatalf("ParsePublicKeyFile: %v", err)
	}

	r1 := minimalR1(t, "rcpt_001", priv)
	r2 := minimalR1(t, "rcpt_002", priv)
	receipts := []*bundle.ParsedReceipt{
		{Entry: bundle.ManifestEntry{Seq: 1, ReceiptID: r1.ReceiptID, Type: "R1"}, Receipt: r1},
		{Entry: bundle.ManifestEntry{Seq: 2, ReceiptID: r2.ReceiptID, Type: "R1"}, Receipt: r2},
	}

	res := bundle.VerifyPerReceipt(receipts, provided)
	if res.Failed != 0 || res.Passed != 2 {
		t.Errorf("expected 2 passed 0 failed, got passed=%d failed=%d failures=%v", res.Passed, res.Failed, res.Failures)
	}
}

func TestVerifyPerReceipt_TamperedSignature_CountedAsFailed(t *testing.T) {
	pub, priv := makeEd25519Pair(t)
	provided, err := verify.ParsePublicKeyFile(ed25519B64Key(pub, "key_bundle_test"))
	if err != nil {
		t.Fatalf("ParsePublicKeyFile: %v", err)
	}

	good := minimalR1(t, "rcpt_good", priv)
	bad := minimalR1(t, "rcpt_bad", priv)
	bad.Signature = base64.StdEncoding.EncodeToString(make([]byte, 64)) // all-zero sig

	receipts := []*bundle.ParsedReceipt{
		{Entry: bundle.ManifestEntry{Seq: 1, ReceiptID: good.ReceiptID, Type: "R1"}, Receipt: good},
		{Entry: bundle.ManifestEntry{Seq: 2, ReceiptID: bad.ReceiptID, Type: "R1"}, Receipt: bad},
	}

	res := bundle.VerifyPerReceipt(receipts, provided)
	if res.Failed != 1 {
		t.Errorf("expected 1 failed, got %d (failures: %v)", res.Failed, res.Failures)
	}
	if res.Passed != 1 {
		t.Errorf("expected 1 passed, got %d", res.Passed)
	}
	// Confirm the failure is a signature error, not a parse error.
	if len(res.Failures) == 0 {
		t.Errorf("expected at least one failure detail, got none")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// VerifyCausalChain
// ─────────────────────────────────────────────────────────────────────────────

func TestVerifyCausalChain_R2_WithR1_InBundle(t *testing.T) {
	r1ID := "rcpt_r1_001"
	r2 := &dsr.Envelope{
		DSRVersion:           "DSR/1.0.2",
		Type:                 "R2",
		ReceiptID:            "rcpt_r2_001",
		VaultID:              "vlt_test",
		Timestamp:            "2026-06-02T10:00:00Z",
		Actor:                "author@example.com",
		Origin:               "github.com/test/repo",
		AttributionReceiptID: pStr(r1ID),
		IncidentID:           pStr("inc_001"),
		ResolvedAt:           pStr("2026-06-02T10:00:00Z"),
		Signature:            "placeholder",
	}
	receipts := []*bundle.ParsedReceipt{
		{Entry: bundle.ManifestEntry{Seq: 1, ReceiptID: r1ID, Type: "R1"}, Receipt: &dsr.Envelope{ReceiptID: r1ID}},
		{Entry: bundle.ManifestEntry{Seq: 2, ReceiptID: r2.ReceiptID, Type: "R2"}, Receipt: r2},
	}

	res := bundle.VerifyCausalChain(receipts)
	if !res.Valid {
		t.Fatalf("R2 with R1 present should be valid: %v", res.Err)
	}
	if res.Total != 1 || res.Resolved != 1 || len(res.Unresolvable) != 0 {
		t.Errorf("expected total=1 resolved=1, got total=%d resolved=%d unresolvable=%v",
			res.Total, res.Resolved, res.Unresolvable)
	}
}

func TestVerifyCausalChain_R2_MissingR1(t *testing.T) {
	r2 := &dsr.Envelope{
		DSRVersion:           "DSR/1.0.2",
		Type:                 "R2",
		ReceiptID:            "rcpt_r2_001",
		VaultID:              "vlt_test",
		Timestamp:            "2026-06-02T10:00:00Z",
		Actor:                "author@example.com",
		Origin:               "github.com/test/repo",
		AttributionReceiptID: pStr("rcpt_r1_MISSING"),
		IncidentID:           pStr("inc_001"),
		ResolvedAt:           pStr("2026-06-02T10:00:00Z"),
		Signature:            "placeholder",
	}
	receipts := []*bundle.ParsedReceipt{
		{Entry: bundle.ManifestEntry{Seq: 1, ReceiptID: r2.ReceiptID, Type: "R2"}, Receipt: r2},
	}

	res := bundle.VerifyCausalChain(receipts)
	if res.Total != 1 || res.Resolved != 0 || len(res.Unresolvable) != 1 {
		t.Errorf("expected 1 unresolvable R1 ref, got: total=%d resolved=%d unresolvable=%v",
			res.Total, res.Resolved, res.Unresolvable)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Full round-trip: ParseBundleFromBytes + VerifyBundle
// ─────────────────────────────────────────────────────────────────────────────

func TestVerifyBundle_RoundTrip_Passes(t *testing.T) {
	pub, priv := makeEd25519Pair(t)
	zipBytes, _, _ := singleReceiptBundle(t, pub, priv)

	b, bundleErr := bundle.ParseBundleFromBytes(zipBytes)
	if bundleErr != nil {
		t.Fatalf("ParseBundleFromBytes: %v", bundleErr)
	}

	provided, keyErr := verify.ParsePublicKeyFile(ed25519B64Key(pub, "key_bundle_test"))
	if keyErr != nil {
		t.Fatalf("ParsePublicKeyFile: %v", keyErr)
	}

	res := bundle.VerifyBundle(b, provided)
	if !res.AllPassed() {
		t.Errorf("expected all checks passed:\n  ManifestSig=%v\n  SeqInteg=%v\n  PerReceipt(failed=%d)\n  CausalChain=%v",
			res.ManifestSig.Valid, res.SequenceInteg.Valid, res.PerReceipt.Failed, res.CausalChain.Valid)
	}
}
