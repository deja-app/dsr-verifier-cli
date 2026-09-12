package verify_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/deja-app/dsr-verifier-cli/internal/dsr"
	"github.com/deja-app/dsr-verifier-cli/internal/verdict"
	"github.com/deja-app/dsr-verifier-cli/internal/verify"
)

// These tests pin the three-state mapping in Signature() and, more importantly,
// pin the rule that produced it:
//
//	the check RAN and disagreed        → Failed
//	the check never ran to a conclusion → CannotVerify
//
// Only a cryptographic comparison that was actually performed and came back
// negative is an assertion about the receipt. Everything else — an
// unimplemented canonical form, an incomplete envelope, an absent key, a
// wrong-type key, undecodable signature bytes, an unimplemented algorithm — is
// a statement about what this verifier could not do.

func stateProbeR1(fv string) *dsr.Envelope {
	repo := "deja-app/x"
	var pr int64 = 1
	e := &dsr.Envelope{
		DSRVersion: "DSR/1.0.9",
		Type:       dsr.TypeR1,
		ReceiptID:  "rcpt_state_probe",
		VaultID:    "vault_state_probe",
		Timestamp:  "2026-09-12T00:00:00.000Z",
		Actor:      "svc:probe",
		Origin:     "github",
		Repository: &repo,
		PRNumber:   &pr,
	}
	if fv != "" {
		e.CanonicalFormVersion = &fv
	}
	return e
}

func strPtr(s string) *string { return &s }

// TestSignatureState_NoPathLeavesStateUnset is the fail-closed guard.
//
// verdict.Unset is the zero value and counts as not-verified, so a forgotten
// assignment cannot pass a gate — but it also cannot be DISPLAYED honestly, and
// it means a branch was missed. Every reachable branch of Signature() must set a
// real verdict.
//
// PLANT TO PROVE IT FIRES: delete any one `res.State = ...` line in verify.go.
// The subtest driving that branch must fail on IsVerdict(). Restore afterwards.
func TestSignatureState_NoPathLeavesStateUnset(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	edKey := &verify.PublicKeyWithID{Key: pub}

	// A sha256-legacy receipt whose signature is correct.
	good := stateProbeR1("")
	good.Signature = "placeholder"
	canonical, cerr := dsr.CanonicalPayload(good)
	if cerr != nil {
		t.Fatalf("canonical: %v", cerr)
	}
	sum := sha256.Sum256([]byte(canonical))
	good.Signature = hex.EncodeToString(sum[:])

	// A valid ed25519-v1 receipt over the same canonical bytes.
	edGood := stateProbeR1("")
	edGood.SignatureAlgorithm = strPtr(dsr.AlgoED25519V1)
	edGood.SigningKeyID = strPtr("k1")
	edCanonical, _ := dsr.CanonicalPayload(edGood)
	edGood.Signature = b64(ed25519.Sign(priv, []byte(edCanonical)))

	cases := []struct {
		name  string
		build func() *dsr.Envelope
		key   *verify.PublicKeyWithID
		want  verdict.State
		why   string
	}{
		{
			name:  "unimplemented canonical form",
			build: func() *dsr.Envelope { e := stateProbeR1("v5-jcs"); e.Signature = "00"; return e },
			want:  verdict.CannotVerify,
			why:   "bytes were never constructed",
		},
		{
			name: "incomplete envelope for the declared form",
			build: func() *dsr.Envelope {
				e := stateProbeR1("v4-jcs")
				e.Signature = "00"
				return e
			},
			want: verdict.CannotVerify,
			why:  "mandatory fields absent, bytes were never constructed",
		},
		{
			name:  "ed25519 receipt, no key supplied",
			build: func() *dsr.Envelope { return edGood },
			key:   nil,
			want:  verdict.CannotVerify,
			why:   "no key, nothing was compared",
		},
		{
			name: "ed25519 receipt, signature not base64",
			build: func() *dsr.Envelope {
				e := stateProbeR1("")
				e.SignatureAlgorithm = strPtr(dsr.AlgoED25519V1)
				e.Signature = "!!!not base64!!!"
				return e
			},
			key:  edKey,
			want: verdict.CannotVerify,
			why:  "signature bytes undecodable, nothing was compared",
		},
		{
			name: "ed25519 receipt, signature does not verify",
			build: func() *dsr.Envelope {
				e := stateProbeR1("")
				e.SignatureAlgorithm = strPtr(dsr.AlgoED25519V1)
				e.Signature = b64(make([]byte, ed25519.SignatureSize))
				return e
			},
			key:  edKey,
			want: verdict.Failed,
			why:  "the check ran and disagreed",
		},
		{
			name:  "ed25519 receipt, signature verifies",
			build: func() *dsr.Envelope { return edGood },
			key:   edKey,
			want:  verdict.Verified,
			why:   "the check ran and agreed",
		},
		{
			name: "unimplemented signature algorithm",
			build: func() *dsr.Envelope {
				e := stateProbeR1("")
				e.SignatureAlgorithm = strPtr("dilithium-v9")
				e.Signature = "00"
				return e
			},
			want: verdict.CannotVerify,
			why:  "algorithm not implemented, nothing was compared",
		},
		{
			name: "sha256-legacy, signature not hex",
			build: func() *dsr.Envelope {
				e := stateProbeR1("")
				e.Signature = "zzzz"
				return e
			},
			want: verdict.CannotVerify,
			why:  "signature bytes undecodable, nothing was compared",
		},
		{
			name: "sha256-legacy, hash mismatch",
			build: func() *dsr.Envelope {
				e := stateProbeR1("")
				e.Signature = hex.EncodeToString(make([]byte, 32))
				return e
			},
			want: verdict.Failed,
			why:  "the hash was computed and compared, and disagreed",
		},
		{
			name:  "sha256-legacy, hash matches",
			build: func() *dsr.Envelope { return good },
			want:  verdict.Verified,
			why:   "the hash was computed and compared, and agreed",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := verify.Signature(c.build(), c.key)
			if !res.State.IsVerdict() {
				t.Fatalf("State = Unset: this branch of Signature() never assigns a "+
					"verdict, so the receipt would aggregate as nothing (%s)", c.why)
			}
			if res.State != c.want {
				t.Errorf("State = %d, want %d — %s", res.State, c.want, c.why)
			}
			// The aggregation invariant: only Verified may count as a pass.
			if got := res.State.CountsAsVerified(); got != (c.want == verdict.Verified) {
				t.Errorf("CountsAsVerified() = %v for State %d", got, res.State)
			}
		})
	}
}

// TestSignatureState_CannotVerifyNeverCountsAsVerified is the rule that makes
// the third state safe: it groups with NOT VERIFIED in every aggregate, so it
// cannot weaken the gate for a pre-v5 receipt whose canonical_form_version is
// unsigned and therefore attacker-controllable.
//
// PLANT TO PROVE IT FIRES: set res.State = verdict.Verified on the
// CanonicalPayload error path in verify.go. This test must fail.
func TestSignatureState_CannotVerifyNeverCountsAsVerified(t *testing.T) {
	e := stateProbeR1("v5-jcs")
	e.Signature = "00"
	res := verify.Signature(e, nil)

	if res.State != verdict.CannotVerify {
		t.Fatalf("State = %d, want CannotVerify", res.State)
	}
	if res.State.CountsAsVerified() {
		t.Error("an unimplemented canonical form counted as verified: an " +
			"attacker-controllable version field would bypass the gate")
	}
	if res.Valid {
		t.Error("res.Valid = true for a receipt whose canonical bytes were never built")
	}
}

// TestSignatureState_ErrClassUnchangedFor17 pins the deliberate staleness.
//
// error_class stays "signature_invalid" on the --json wire and in the audit log
// for 1.7 (VERSIONING.md lists both as breaking surfaces). State carries the
// truth instead. If a future change "fixes" the class here, it breaks the
// release plan — so the freeze is asserted, not assumed.
func TestSignatureState_ErrClassUnchangedFor17(t *testing.T) {
	e := stateProbeR1("v5-jcs")
	e.Signature = "00"
	res := verify.Signature(e, nil)

	if res.Err == nil {
		t.Fatal("expected an error for an unimplemented canonical form")
	}
	if got := string(res.Err.Class); got != "signature_invalid" {
		t.Errorf("error_class = %q, want %q for the 1.7 release: the wire value is "+
			"deliberately frozen and State carries the real verdict", got, "signature_invalid")
	}
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
