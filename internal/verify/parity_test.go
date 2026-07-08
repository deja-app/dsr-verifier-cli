// parity_test.go — issuer↔verifier parity gate.
//
// This test proves that receipts produced by the live Déjà issuer (TypeScript)
// verify correctly in this Go binary. Any canonical-form drift — a changed key-sort
// order, a float64 vs int64 serialization difference, a missing conditional field —
// will make a real issuer-signed receipt fail to verify here, failing this gate.
//
// Zero-network guarantee: the test is intentionally run with a sandboxed network
// on Linux via `unshare -n` (see Makefile target `test-offline`). Any net call
// inserted into the verifier makes that job fail.
//
// Fixtures:
//
//	testdata/managed-r1.dsr           Real R1 receipt signed by ed25519-v1 (staging)
//	testdata/managed-pubkey.b64       Base64 raw Ed25519 public key for the above
//	testdata/managed-r1-tampered.dsr  Same receipt with ccs_score mutated (must FAIL)
//	testdata/managed-r2.dsr           Real R2 receipt (ed25519-v1)
//	testdata/byok-r1.dsr              Real R1 receipt signed by rsa-pss-sha256 (staging)
//	testdata/byok-pubkey.pem          RSA-2048 public key PEM for the BYOK receipt
//	testdata/byok-r1-tampered.dsr     Same BYOK receipt with pr_number mutated (must FAIL)
//
// Generate fixtures by running from the wallow monorepo:
//
//	WALLOW_REPO=../wallow make generate-parity-fixtures
//
// Canonical form versions covered:
//
//   - v1-legacy (absent canonical_form_version): tested via managed-r1 if the
//     staging fixture carries no canonical_form_version field
//   - v2-jcs (canonical_form_version="v2-jcs"): tested when the staging fixture
//     includes this field
//
// Until fixtures exist, all tests in this file are skipped with:
//
//	SKIP: parity fixtures not found — run: make generate-parity-fixtures
package verify_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/deja-app/dsr-verifier-cli/internal/dsr"
	dsrerrors "github.com/deja-app/dsr-verifier-cli/internal/errors"
	"github.com/deja-app/dsr-verifier-cli/internal/verify"
)

const testdataDir = "testdata"

func TestParity_ManagedR1_Passes(t *testing.T) {
	env, key := loadParityFixture(t, "managed-r1.dsr", "managed-pubkey.b64")

	authRes := verify.KeyAuthority(env, key)
	if !authRes.Valid && !authRes.Skipped {
		t.Errorf("KeyAuthority FAIL: %s — %s", authRes.Err.Class, authRes.Err.HumanMessage)
	}
	sigRes := verify.Signature(env, key)
	if !sigRes.Valid {
		t.Errorf("Signature FAIL: %s — %s", sigRes.Err.Class, sigRes.Err.HumanMessage)
		t.Logf("algorithm=%s canonical_len=%d", sigRes.Algorithm, sigRes.CanonicalLen)
	}
}

func TestParity_ManagedR1_Tampered_Fails(t *testing.T) {
	env, key := loadParityFixture(t, "managed-r1-tampered.dsr", "managed-pubkey.b64")

	sigRes := verify.Signature(env, key)
	if sigRes.Valid {
		t.Fatal("tampered managed-r1 must NOT verify — the parity gate is broken")
	}
	if sigRes.Err == nil || sigRes.Err.Class != dsrerrors.SignatureInvalid {
		t.Errorf("expected SignatureInvalid, got %v", sigRes.Err)
	}
}

func TestParity_ManagedR2_Passes(t *testing.T) {
	env, key := loadParityFixture(t, "managed-r2.dsr", "managed-pubkey.b64")

	sigRes := verify.Signature(env, key)
	if !sigRes.Valid {
		t.Errorf("R2 Signature FAIL: %s — %s", sigRes.Err.Class, sigRes.Err.HumanMessage)
		t.Logf("algorithm=%s canonical_len=%d", sigRes.Algorithm, sigRes.CanonicalLen)
	}
}

func TestParity_BYOKr1_Passes(t *testing.T) {
	env, key := loadParityFixture(t, "byok-r1.dsr", "byok-pubkey.pem")

	sigRes := verify.Signature(env, key)
	if !sigRes.Valid {
		t.Errorf("BYOK R1 Signature FAIL: %s — %s", sigRes.Err.Class, sigRes.Err.HumanMessage)
		t.Logf("algorithm=%s canonical_len=%d", sigRes.Algorithm, sigRes.CanonicalLen)
	}
}

func TestParity_BYOKr1_Tampered_Fails(t *testing.T) {
	env, key := loadParityFixture(t, "byok-r1-tampered.dsr", "byok-pubkey.pem")

	sigRes := verify.Signature(env, key)
	if sigRes.Valid {
		t.Fatal("tampered BYOK r1 must NOT verify — the parity gate is broken")
	}
	if sigRes.Err == nil || sigRes.Err.Class != dsrerrors.SignatureInvalid {
		t.Errorf("expected SignatureInvalid, got %v", sigRes.Err)
	}
}

// TestParity_CanonicalFormVersionCoverage reports which canonical_form_version
// values are present in the current fixture set. This documents coverage rather
// than asserting it — the test always passes, but the log output pinpoints which
// version is exercised by each fixture.
func TestParity_CanonicalFormVersionCoverage(t *testing.T) {
	fixtures := []string{"managed-r1.dsr", "managed-r2.dsr", "byok-r1.dsr"}
	for _, name := range fixtures {
		path := filepath.Join(testdataDir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Logf("SKIP %s: %v", name, err)
			continue
		}
		env, parseErr := dsr.Parse(data)
		if parseErr != nil {
			t.Logf("SKIP %s (parse error): %s", name, parseErr.HumanMessage)
			continue
		}
		t.Logf("%s: type=%s algo=%s form=%s",
			name, env.Type, env.SigAlgo(), env.FormVersion())
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// helpers
// ─────────────────────────────────────────────────────────────────────────────

// loadParityFixture reads the receipt and key files; skips the test if either
// is missing. This makes the parity gate a no-op in clean checkouts and active
// only after `make generate-parity-fixtures` has been run.
func loadParityFixture(t *testing.T, receiptFile, keyFile string) (*dsr.Envelope, *verify.PublicKeyWithID) {
	t.Helper()

	receiptPath := filepath.Join(testdataDir, receiptFile)
	keyPath := filepath.Join(testdataDir, keyFile)

	receiptData, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Skipf("parity fixture not found (%s) — run: make generate-parity-fixtures", receiptFile)
	}
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		t.Skipf("parity key fixture not found (%s) — run: make generate-parity-fixtures", keyFile)
	}

	env, parseErr := dsr.Parse(receiptData)
	if parseErr != nil {
		t.Fatalf("Parse(%s): %s — %s", receiptFile, parseErr.Class, parseErr.HumanMessage)
	}

	key, keyErr := verify.ParsePublicKeyFile(keyData)
	if keyErr != nil {
		t.Fatalf("ParsePublicKeyFile(%s): %s — %s", keyFile, keyErr.Class, keyErr.HumanMessage)
	}

	return env, key
}
