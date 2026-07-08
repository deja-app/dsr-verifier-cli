package verify_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"testing"

	"github.com/deja-app/dsr-verifier-cli/internal/dsr"
	dsrerrors "github.com/deja-app/dsr-verifier-cli/internal/errors"
	"github.com/deja-app/dsr-verifier-cli/internal/verify"
)

const testVaultID = "vault_testorg"
const testKeyID = "key_test_2026q2"

// ─────────────────────────────────────────────────────────────────────────────
// Helper builders
// ─────────────────────────────────────────────────────────────────────────────

func ptrStr(s string) *string { return &s }
func ptrBool(b bool) *bool    { return &b }
func ptrInt64(n int64) *int64 { return &n }

// baseR1 returns a minimal valid R1 attribution Envelope with no signature set.
func baseR1() *dsr.Envelope {
	return &dsr.Envelope{
		DSRVersion:  "DSR/1.0.2",
		Type:        "R1",
		ReceiptID:   "rcpt_test_r1_001",
		VaultID:     testVaultID,
		Timestamp:   "2026-05-12T12:00:00Z",
		Actor:       "actor@example.com",
		Origin:      "github.com/example/repo",
		Repository:  ptrStr("example/repo"),
		PRNumber:    ptrInt64(4287),
		CCSScore:    ptrStr("0.8750"),
		Confidence:  ptrStr("high"),
		Matched:     ptrStr("true"),
		ServiceZone: ptrStr("us-east-1"),
	}
}

// baseR2 returns a minimal valid R2 resolution Envelope with no signature set.
func baseR2() *dsr.Envelope {
	return &dsr.Envelope{
		DSRVersion:           "DSR/1.0.2",
		Type:                 "R2",
		ReceiptID:            "rcpt_test_r2_001",
		VaultID:              testVaultID,
		Timestamp:            "2026-05-13T10:00:00Z",
		Actor:                "actor@example.com",
		Origin:               "github.com/example/repo",
		AttributionReceiptID: ptrStr("rcpt_test_r1_001"),
		IncidentID:           ptrStr("inc_001"),
		ResolvedAt:           ptrStr("2026-05-13T10:00:00Z"),
		GateEvaluatedAt:      ptrStr("2026-05-13T09:58:00Z"),
		TimeToResolutionMs:   ptrInt64(3600000),
		GatesPassed:          ptrBool(true),
		FileGateScore:        ptrStr("0.9000"),
		RateGateScore:        ptrStr("0.8500"),
		InfraGateScore:       ptrStr("0.9500"),
		FeatureGateScore:     ptrStr("0.8000"),
		DurationGateScore:    ptrStr("0.7500"),
	}
}

// signEd25519 sets e.Signature to the base64 ed25519 signature over the canonical payload.
func signEd25519(t *testing.T, e *dsr.Envelope, priv ed25519.PrivateKey) {
	t.Helper()
	algo := dsr.AlgoED25519V1
	e.SignatureAlgorithm = &algo
	canonical, err := dsr.CanonicalPayload(e)
	if err != nil {
		t.Fatalf("CanonicalPayload: %v", err)
	}
	sig := ed25519.Sign(priv, []byte(canonical))
	e.Signature = base64.StdEncoding.EncodeToString(sig)
}

// signSHA256Legacy sets e.Signature to the SHA-256 hex of the canonical payload.
func signSHA256Legacy(t *testing.T, e *dsr.Envelope) {
	t.Helper()
	e.SignatureAlgorithm = nil // absent = sha256-legacy
	canonical, err := dsr.CanonicalPayload(e)
	if err != nil {
		t.Fatalf("CanonicalPayload: %v", err)
	}
	sum := sha256.Sum256([]byte(canonical))
	e.Signature = hex.EncodeToString(sum[:])
}

// makeEd25519Key wraps ed25519.GenerateKey for tests.
func makeEd25519Key(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	return pub, priv
}

// ed25519PEMKey returns a PKIX PEM block for the public key with an optional key_id comment.
func ed25519PEMKey(t *testing.T, pub ed25519.PublicKey, keyID string) []byte {
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

// ed25519Base64Key returns the base64 raw key with an optional key_id comment.
func ed25519Base64Key(pub ed25519.PublicKey, keyID string) []byte {
	b64 := base64.StdEncoding.EncodeToString([]byte(pub))
	if keyID != "" {
		return []byte(fmt.Sprintf("# key_id: %s\n%s\n", keyID, b64))
	}
	return []byte(b64 + "\n")
}

// ─────────────────────────────────────────────────────────────────────────────
// Ed25519-v1
// ─────────────────────────────────────────────────────────────────────────────

func TestSignature_Ed25519_PEMKey_Passes(t *testing.T) {
	pub, priv := makeEd25519Key(t)
	e := baseR1()
	e.SigningKeyID = ptrStr(testKeyID)
	signEd25519(t, e, priv)

	provided, keyErr := verify.ParsePublicKeyFile(ed25519PEMKey(t, pub, testKeyID))
	if keyErr != nil {
		t.Fatalf("ParsePublicKeyFile: %v", keyErr)
	}

	if res := verify.KeyAuthority(e, provided); !res.Valid {
		t.Errorf("KeyAuthority: %v", res.Err)
	}
	if res := verify.Signature(e, provided); !res.Valid {
		t.Errorf("Signature: %v", res.Err)
	}
}

func TestSignature_Ed25519_Base64Key_Passes(t *testing.T) {
	pub, priv := makeEd25519Key(t)
	e := baseR1()
	e.SigningKeyID = ptrStr(testKeyID)
	signEd25519(t, e, priv)

	provided, keyErr := verify.ParsePublicKeyFile(ed25519Base64Key(pub, testKeyID))
	if keyErr != nil {
		t.Fatalf("ParsePublicKeyFile (base64): %v", keyErr)
	}

	if res := verify.Signature(e, provided); !res.Valid {
		t.Errorf("Signature (base64 key): %v", res.Err)
	}
}

func TestSignature_Ed25519_Tampered_Fails(t *testing.T) {
	pub, priv := makeEd25519Key(t)
	e := baseR1()
	e.SigningKeyID = ptrStr(testKeyID)
	signEd25519(t, e, priv)

	// Flip one bit in the signature.
	sigBytes, _ := base64.StdEncoding.DecodeString(e.Signature)
	sigBytes[0] ^= 0x01
	e.Signature = base64.StdEncoding.EncodeToString(sigBytes)

	provided, _ := verify.ParsePublicKeyFile(ed25519PEMKey(t, pub, testKeyID))
	res := verify.Signature(e, provided)
	assertInvalid(t, "Signature tampered", res.Valid, res.Err, dsrerrors.SignatureInvalid)
}

func TestSignature_Ed25519_FieldMutation_Fails(t *testing.T) {
	pub, priv := makeEd25519Key(t)
	e := baseR1()
	e.SigningKeyID = ptrStr(testKeyID)
	signEd25519(t, e, priv)

	// Mutate a signed field after signing.
	e.PRNumber = ptrInt64(9999)

	provided, _ := verify.ParsePublicKeyFile(ed25519PEMKey(t, pub, testKeyID))
	res := verify.Signature(e, provided)
	assertInvalid(t, "Signature (field mutated post-sign)", res.Valid, res.Err, dsrerrors.SignatureInvalid)
}

// ─────────────────────────────────────────────────────────────────────────────
// SHA256-legacy
// ─────────────────────────────────────────────────────────────────────────────

func TestSignature_SHA256Legacy_Passes(t *testing.T) {
	e := baseR1()
	signSHA256Legacy(t, e)

	res := verify.Signature(e, nil)
	if !res.Valid {
		t.Errorf("SHA256-legacy Signature: %v", res.Err)
	}
}

func TestSignature_SHA256Legacy_Tampered_Fails(t *testing.T) {
	e := baseR1()
	signSHA256Legacy(t, e)
	e.CCSScore = ptrStr("0.0001") // mutate post-sign

	res := verify.Signature(e, nil)
	assertInvalid(t, "SHA256-legacy tampered", res.Valid, res.Err, dsrerrors.SignatureInvalid)
}

func TestKeyAuthority_SHA256Legacy_IsSkipped(t *testing.T) {
	e := baseR1()
	signSHA256Legacy(t, e)
	res := verify.KeyAuthority(e, nil)
	if !res.Valid || !res.Skipped {
		t.Errorf("SHA256-legacy KeyAuthority must be skipped; got Valid=%v Skipped=%v", res.Valid, res.Skipped)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// RSA-PSS-SHA256
// ─────────────────────────────────────────────────────────────────────────────

func TestSignature_RSAPSS_Passes(t *testing.T) {
	rsaPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	e := baseR1()
	e.SigningKeyID = ptrStr(testKeyID)
	algo := dsr.AlgoRSAPSSSHA256
	e.SignatureAlgorithm = &algo
	canonical, _ := dsr.CanonicalPayload(e)
	hashed := sha256.Sum256([]byte(canonical))
	opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: crypto.SHA256}
	sig, err := rsa.SignPSS(rand.Reader, rsaPriv, crypto.SHA256, hashed[:], opts)
	if err != nil {
		t.Fatalf("rsa.SignPSS: %v", err)
	}
	e.Signature = base64.StdEncoding.EncodeToString(sig)

	der, _ := x509.MarshalPKIXPublicKey(&rsaPriv.PublicKey)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	provided, _ := verify.ParsePublicKeyFile(keyPEM)

	if res := verify.Signature(e, provided); !res.Valid {
		t.Errorf("RSA-PSS Signature: %v", res.Err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// ECDSA-SHA256
// ─────────────────────────────────────────────────────────────────────────────

func TestSignature_ECDSA_Passes(t *testing.T) {
	ecPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	e := baseR1()
	e.SigningKeyID = ptrStr(testKeyID)
	algo := dsr.AlgoECDSASHA256
	e.SignatureAlgorithm = &algo
	canonical, _ := dsr.CanonicalPayload(e)
	hashed := sha256.Sum256([]byte(canonical))
	sig, err := ecdsa.SignASN1(rand.Reader, ecPriv, hashed[:])
	if err != nil {
		t.Fatalf("ecdsa.SignASN1: %v", err)
	}
	e.Signature = base64.StdEncoding.EncodeToString(sig)

	der, _ := x509.MarshalPKIXPublicKey(&ecPriv.PublicKey)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	provided, _ := verify.ParsePublicKeyFile(keyPEM)

	if res := verify.Signature(e, provided); !res.Valid {
		t.Errorf("ECDSA Signature: %v", res.Err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Key authority
// ─────────────────────────────────────────────────────────────────────────────

func TestKeyAuthority_IDMismatch_Fails(t *testing.T) {
	pub, priv := makeEd25519Key(t)
	e := baseR1()
	e.SigningKeyID = ptrStr("key_actual")
	signEd25519(t, e, priv)

	// Key file identifies as a different key_id.
	provided, _ := verify.ParsePublicKeyFile(ed25519PEMKey(t, pub, "key_wrong"))
	res := verify.KeyAuthority(e, provided)
	assertInvalid(t, "KeyAuthority mismatch", res.Valid, res.Err, dsrerrors.KeyAuthorityMismatch)
}

func TestKeyAuthority_EmptyProvidedID_Passes(t *testing.T) {
	pub, priv := makeEd25519Key(t)
	e := baseR1()
	e.SigningKeyID = ptrStr("key_actual")
	signEd25519(t, e, priv)

	// No # key_id comment in key file → empty ProvidedKeyID → skip mismatch check.
	provided, _ := verify.ParsePublicKeyFile(ed25519PEMKey(t, pub, ""))
	res := verify.KeyAuthority(e, provided)
	if !res.Valid {
		t.Errorf("KeyAuthority with empty provided key ID must pass: %v", res.Err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Canonical form correctness — R1, R2, other
// ─────────────────────────────────────────────────────────────────────────────

func TestCanonical_R1_KeySortOrder(t *testing.T) {
	e := baseR1()
	// Add conditional fields.
	e.IsSynthetic = ptrBool(false)
	e.IsInternalValidation = ptrBool(true)
	e.SigningKeyID = ptrStr(testKeyID)
	e.SignatureAlgorithm = ptrStr(dsr.AlgoED25519V1)

	canonical, err := dsr.CanonicalPayload(e)
	if err != nil {
		t.Fatalf("CanonicalPayload: %v", err)
	}

	// All keys must appear in Unicode code-point (lexicographic) order.
	prev := ""
	inKey, key := false, ""
	for _, ch := range canonical {
		if ch == '{' || ch == ',' {
			inKey = true
			key = ""
			continue
		}
		if inKey {
			if ch == '"' && key == "" {
				continue
			}
			if ch == '"' {
				if prev != "" && key < prev {
					t.Errorf("keys out of order: %q came after %q in canonical payload", key, prev)
				}
				prev = key
				inKey = false
				key = ""
			} else {
				key += string(ch)
			}
		}
	}
}

func TestCanonical_R2_IssuedAtIsTimestamp(t *testing.T) {
	e := baseR2()
	canonical, err := dsr.CanonicalPayload(e)
	if err != nil {
		t.Fatalf("CanonicalPayload R2: %v", err)
	}
	// The canonical form for R2 uses timestamp as issued_at.
	if !containsStr(canonical, `"issued_at":"2026-05-13T10:00:00Z"`) {
		t.Errorf("R2 canonical payload must use timestamp for issued_at; got:\n%s", canonical)
	}
}

func TestCanonical_Int64NeverFloat(t *testing.T) {
	e := baseR1()
	e.PRNumber = ptrInt64(9007199254740993) // 2^53+1: unsafe as float64
	canonical, err := dsr.CanonicalPayload(e)
	if err != nil {
		t.Fatalf("CanonicalPayload: %v", err)
	}
	if !containsStr(canonical, `"pr_number":9007199254740993`) {
		t.Errorf("pr_number must be encoded as integer, got: %s", canonical)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Chain hash
// ─────────────────────────────────────────────────────────────────────────────

func TestChainHash_GenesisAndSuccessor(t *testing.T) {
	pub, priv := makeEd25519Key(t)
	_ = pub

	e1 := baseR1()
	signEd25519(t, e1, priv)
	// PriorHash of genesis is nil.

	canonical1, _ := dsr.CanonicalPayload(e1)
	expected := dsr.ChainHash(nil, canonical1)

	e2 := baseR2()
	e2.PriorHash = &expected
	signEd25519(t, e2, priv)

	result := verify.VerifyChainHash([]*dsr.Envelope{e1, e2})
	if !result.Valid {
		t.Errorf("VerifyChainHash: %v", result.Err)
	}
	if result.Checked != 1 {
		t.Errorf("Checked = %d, want 1", result.Checked)
	}
}

func TestChainHash_BrokenChain_Fails(t *testing.T) {
	pub, priv := makeEd25519Key(t)
	_ = pub

	e1 := baseR1()
	signEd25519(t, e1, priv)

	e2 := baseR2()
	wrongHash := "0000000000000000000000000000000000000000000000000000000000000000"
	e2.PriorHash = &wrongHash
	signEd25519(t, e2, priv)

	result := verify.VerifyChainHash([]*dsr.Envelope{e1, e2})
	assertInvalid(t, "VerifyChainHash broken", result.Valid, result.Err, dsrerrors.HashChainBroken)
}

// ─────────────────────────────────────────────────────────────────────────────
// helpers
// ─────────────────────────────────────────────────────────────────────────────

func assertValid(t *testing.T, label string, valid bool, verr *dsrerrors.VerificationError) {
	t.Helper()
	if !valid {
		t.Errorf("%s: expected Valid=true but got failure: class=%s, message=%s",
			label, verr.Class, verr.HumanMessage)
	}
}

func assertInvalid(t *testing.T, label string, valid bool, verr *dsrerrors.VerificationError, wantClass dsrerrors.ErrorClass) {
	t.Helper()
	if valid {
		t.Errorf("%s: expected Valid=false but got Valid=true", label)
		return
	}
	if verr == nil {
		t.Errorf("%s: expected non-nil VerificationError but got nil", label)
		return
	}
	if verr.Class != wantClass {
		t.Errorf("%s: error class = %q, want %q", label, verr.Class, wantClass)
	}
}

func containsStr(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && func() bool {
		for i := 0; i <= len(s)-len(substr); i++ {
			if s[i:i+len(substr)] == substr {
				return true
			}
		}
		return false
	}())
}
