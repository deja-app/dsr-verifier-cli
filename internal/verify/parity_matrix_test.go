package verify_test

// parity_matrix_test.go — cross-implementation parity gate.
//
// Runs every pre-committed DSR vector from testdata/parity/ through the Go
// verifier and asserts that the signature is VALID.  Because each fixture was
// produced by the TypeScript canonicaliser and signed by a deterministic
// Ed25519 keypair, a failure here means the Go CanonicalPayload() function
// produces different bytes from the TypeScript issuer for that receipt type +
// canonical-form-version combination.
//
// Matrix covered (11 vectors):
//
//   R1  × {v1-legacy, v2-jcs, v3-jcs, v4-jcs}
//   R2  × {v1-legacy, v2-jcs, v3-jcs, v4-jcs}
//   R1-L × (single canonical form)
//   R1-N × (single canonical form)
//   RG   × (single canonical form)
//
// Public key: testdata/parity/parity-pubkey.b64
// Key ID    : parity-test-key-v1
//
// Regenerate vectors whenever the TypeScript canonical form changes:
//
//   # from the dsr-verifier-cli root:
//   make generate-parity-vectors WALLOW_REPO=../wallow
//
// Then re-run this test; if it passes, both implementations are consistent and
// the new vectors can be committed.  If it fails, the Go CanonicalPayload()
// function needs a matching update.
//
// The test is deliberately NOT skipped when vectors are absent — an absent
// directory means the Makefile target has never been run, which is itself a
// failure of the parity gate.  Committing the vectors is part of the gate.

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/deja-app/dsr-verifier-cli/internal/dsr"
	"github.com/deja-app/dsr-verifier-cli/internal/verify"
)

const parityDir = "testdata/parity"

// TestParityMatrix runs every fixture in the parity directory through both
// verify.KeyAuthority() and verify.Signature(), failing on any error.
func TestParityMatrix(t *testing.T) {
	t.Parallel()

	keyData, err := os.ReadFile(filepath.Join(parityDir, "parity-pubkey.b64"))
	if err != nil {
		t.Fatalf("parity public key not found — run: make generate-parity-vectors WALLOW_REPO=../wallow\nerror: %v", err)
	}

	provided, keyErr := verify.ParsePublicKeyFile(keyData)
	if keyErr != nil {
		t.Fatalf("ParsePublicKeyFile: %v", keyErr)
	}

	cases := []struct {
		name    string
		file    string
		wantCFV string // expected canonical_form_version ("" = v1-legacy)
	}{
		// R1 attribution receipts — one per canonical form version.
		// v1-legacy: canonical_form_version is null in the envelope; FormVersion() normalises to "v1-legacy".
		{name: "R1/v1-legacy", file: "parity-r1-v1-legacy.dsr", wantCFV: "v1-legacy"},
		{name: "R1/v2-jcs", file: "parity-r1-v2-jcs.dsr", wantCFV: "v2-jcs"},
		{name: "R1/v3-jcs", file: "parity-r1-v3-jcs.dsr", wantCFV: "v3-jcs"},
		{name: "R1/v4-jcs", file: "parity-r1-v4-jcs.dsr", wantCFV: "v4-jcs"},

		// R2 resolution receipts — one per canonical form version.
		{name: "R2/v1-legacy", file: "parity-r2-v1-legacy.dsr", wantCFV: "v1-legacy"},
		{name: "R2/v2-jcs", file: "parity-r2-v2-jcs.dsr", wantCFV: "v2-jcs"},
		{name: "R2/v3-jcs", file: "parity-r2-v3-jcs.dsr", wantCFV: "v3-jcs"},
		{name: "R2/v4-jcs", file: "parity-r2-v4-jcs.dsr", wantCFV: "v4-jcs"},

		// Single-canonical-form types (FormVersion() returns "v1-legacy" for null canonical_form_version).
		{name: "R1-L", file: "parity-r1l.dsr", wantCFV: "v1-legacy"},
		{name: "R1-N", file: "parity-r1n.dsr", wantCFV: "v1-legacy"},
		{name: "RG", file: "parity-rg.dsr", wantCFV: "v1-legacy"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			fullPath := filepath.Join(parityDir, tc.file)
			data, err := os.ReadFile(fullPath)
			if err != nil {
				t.Fatalf("fixture %q not found — run: make generate-parity-vectors WALLOW_REPO=../wallow\nerror: %v",
					tc.file, err)
			}

			env, parseErr := dsr.Parse(data)
			if parseErr != nil {
				t.Fatalf("dsr.Parse(%s): %v", tc.file, parseErr)
			}

			// Sanity: canonical_form_version matches what the generator wrote.
			if env.FormVersion() != tc.wantCFV {
				t.Errorf("FormVersion mismatch: got %q, want %q", env.FormVersion(), tc.wantCFV)
			}

			// Key authority check (signing_key_id must match the provided key ID).
			authRes := verify.KeyAuthority(env, provided)
			if !authRes.Valid && !authRes.Skipped {
				t.Errorf("KeyAuthority FAIL: %s — %s", authRes.Err.Class, authRes.Err.HumanMessage)
			}

			// Signature check: Go canonical bytes must match TypeScript canonical bytes.
			sigRes := verify.Signature(env, provided)
			if !sigRes.Valid {
				t.Errorf("Signature FAIL: %s — %s\n  algorithm=%s canonical_len=%d\n"+
					"  This means CanonicalPayload() in Go diverges from the TypeScript issuer.\n"+
					"  Check canonical.go and canonical-receipt.ts for field-set differences.",
					sigRes.Err.Class, sigRes.Err.HumanMessage, sigRes.Algorithm, sigRes.CanonicalLen)
			}

			// Log the canonical length for debugging without failing.
			t.Logf("%s: canonical_len=%d algorithm=%s", tc.name, sigRes.CanonicalLen, sigRes.Algorithm)
		})
	}
}

// TestParityMatrix_TamperedR1_Fails guards the test helpers: if we flip a byte
// in the r1-v3-jcs fixture and verify it, the signature must fail.  This
// catches any regression where the Go verifier would naively accept all input.
func TestParityMatrix_TamperedR1_Fails(t *testing.T) {
	t.Parallel()

	keyData, err := os.ReadFile(filepath.Join(parityDir, "parity-pubkey.b64"))
	if err != nil {
		t.Skip("parity fixtures not present — skip tamper guard")
	}
	provided, _ := verify.ParsePublicKeyFile(keyData)

	data, err := os.ReadFile(filepath.Join(parityDir, "parity-r1-v3-jcs.dsr"))
	if err != nil {
		t.Skip("parity-r1-v3-jcs.dsr not present — skip tamper guard")
	}

	// Flip a byte in the middle of the JSON payload.
	if len(data) < 80 {
		t.Fatal("fixture unexpectedly short")
	}
	tampered := make([]byte, len(data))
	copy(tampered, data)
	tampered[60] ^= 0x01

	env, parseErr := dsr.Parse(tampered)
	if parseErr != nil {
		// JSON parse failure is also a valid rejection.
		t.Logf("tampered fixture rejected at parse: %v", parseErr)
		return
	}

	sigRes := verify.Signature(env, provided)
	if sigRes.Valid {
		t.Error("tampered parity fixture must NOT verify — the parity gate is broken")
	}
}
