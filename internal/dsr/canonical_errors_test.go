package dsr

import (
	"errors"
	"testing"
)

// The exact strings CanonicalPayload produced before the errors were typed.
//
// Typing the errors must not change any output: internal/verify still wraps
// them into error_class "signature_invalid" for the 1.7 release, and both the
// human and --json surfaces render the text verbatim. These constants are the
// byte-identity guard on that promise.
//
// They are NOT the §9-conformant copy. "unsupported canonical_form_version"
// asserts the version is not real; it is real and this verifier does not
// implement it. Rewriting these needs §9.6. When that lands, update these
// constants deliberately — do not let them drift.
const (
	wantUnknownFormMsg = `unsupported canonical_form_version "v5-jcs": this verifier implements ` +
		`v1-legacy, v2-jcs, v3-jcs, v4-jcs, confirmation-rg-v1 — upgrade the verifier to ` +
		`check receipts issued under "v5-jcs"`
	wantMissingRepoMsg    = `attribution receipt missing repository`
	wantMissingIncidentID = `resolution receipt missing incident_id`
	wantV3MissingKeyIDMsg = `v3-jcs attribution receipt missing required field: signing_key_id`
)

func probeR1(fv string) *Envelope {
	e := &Envelope{
		DSRVersion: "DSR/1.0.9",
		Type:       TypeR1,
		ReceiptID:  "rcpt_probe",
		VaultID:    "vault_probe",
		Timestamp:  "2026-09-12T00:00:00.000Z",
		Actor:      "svc:probe",
		Origin:     "github",
		Signature:  "00",
	}
	if fv != "" {
		e.CanonicalFormVersion = &fv
	}
	repo := "deja-app/x"
	var pr int64 = 1
	e.Repository = &repo
	e.PRNumber = &pr
	return e
}

// TestUnknownFormVersion_IsTypedAndMessageUnchanged is the guard that an
// unimplemented canonical form is distinguishable from a signature mismatch.
//
// PLANT TO PROVE IT FIRES: in receipt.go ValidateFormVersion, return
// fmt.Errorf(...) instead of &FormNotImplementedError{...}. The errors.As
// assertion must fail. Restore afterwards.
func TestUnknownFormVersion_IsTypedAndMessageUnchanged(t *testing.T) {
	e := probeR1("v5-jcs")
	_, err := CanonicalPayload(e)
	if err == nil {
		t.Fatal("CanonicalPayload accepted an unimplemented canonical_form_version")
	}

	var fnie *FormNotImplementedError
	if !errors.As(err, &fnie) {
		t.Fatalf("error is not a *FormNotImplementedError (%T): internal/verify "+
			"cannot distinguish an unimplemented form from a signature mismatch", err)
	}
	if fnie.FormVersion != "v5-jcs" {
		t.Errorf("FormVersion = %q, want %q", fnie.FormVersion, "v5-jcs")
	}
	if got := err.Error(); got != wantUnknownFormMsg {
		t.Errorf("message changed:\n got: %s\nwant: %s", got, wantUnknownFormMsg)
	}
}

// TestEnvelopeIncomplete_IsTypedAndMessagesUnchanged covers both message
// shapes: a field required by every form, and a field required only by v3/v4.
//
// PLANT TO PROVE IT FIRES: revert any one of the EnvelopeIncompleteError
// returns in canonical.go to its fmt.Errorf form. The matching errors.As
// assertion must fail. Restore afterwards.
func TestEnvelopeIncomplete_IsTypedAndMessagesUnchanged(t *testing.T) {
	cases := []struct {
		name      string
		mutate    func(*Envelope)
		wantMsg   string
		wantKind  string
		wantForm  string
		wantField string
	}{
		{
			name:      "R1 missing repository (all forms)",
			mutate:    func(e *Envelope) { e.Repository = nil },
			wantMsg:   wantMissingRepoMsg,
			wantKind:  "attribution",
			wantForm:  "",
			wantField: "repository",
		},
		{
			name: "v3-jcs R1 missing signing_key_id only",
			mutate: func(e *Envelope) {
				fv := "v3-jcs"
				e.CanonicalFormVersion = &fv
				algo, tb := "ed25519-v1", "deployed"
				e.SignatureAlgorithm = &algo
				e.TemporalBasis = &tb
				e.SigningKeyID = nil
			},
			wantMsg:   wantV3MissingKeyIDMsg,
			wantKind:  "attribution",
			wantForm:  "v3-jcs",
			wantField: "signing_key_id",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := probeR1("")
			c.mutate(e)
			_, err := CanonicalPayload(e)
			if err == nil {
				t.Fatal("CanonicalPayload built bytes from an incomplete envelope")
			}
			var eie *EnvelopeIncompleteError
			if !errors.As(err, &eie) {
				t.Fatalf("error is not a *EnvelopeIncompleteError (%T)", err)
			}
			if eie.Kind != c.wantKind || eie.FormVersion != c.wantForm {
				t.Errorf("Kind/FormVersion = %q/%q, want %q/%q",
					eie.Kind, eie.FormVersion, c.wantKind, c.wantForm)
			}
			if len(eie.MissingFields) != 1 || eie.MissingFields[0] != c.wantField {
				t.Errorf("MissingFields = %v, want [%s]", eie.MissingFields, c.wantField)
			}
			if got := err.Error(); got != c.wantMsg {
				t.Errorf("message changed:\n got: %s\nwant: %s", got, c.wantMsg)
			}
		})
	}
}

// TestEnvelopeIncomplete_CarriesEveryMissingField is the field-list guard.
//
// One reason code carrying a field list, not a code per field. The old code
// returned on the first absence, so a receipt missing all three v3 mandatory
// fields reported only one — under-reporting exactly the information that
// makes the condition actionable.
//
// PLANT TO PROVE IT FIRES: change the collector in attributionCanonical back to
// returning on the first missing field. This test must fail on the length.
func TestEnvelopeIncomplete_CarriesEveryMissingField(t *testing.T) {
	e := probeR1("v4-jcs")
	e.SigningKeyID = nil
	e.SignatureAlgorithm = nil
	e.TemporalBasis = nil

	_, err := CanonicalPayload(e)
	var eie *EnvelopeIncompleteError
	if !errors.As(err, &eie) {
		t.Fatalf("error is not a *EnvelopeIncompleteError (%T)", err)
	}

	want := []string{"signing_key_id", "signature_algorithm", "temporal_basis"}
	if len(eie.MissingFields) != len(want) {
		t.Fatalf("MissingFields = %v (%d fields), want all %d: %v",
			eie.MissingFields, len(eie.MissingFields), len(want), want)
	}
	for i, f := range want {
		if eie.MissingFields[i] != f {
			t.Errorf("MissingFields[%d] = %q, want %q (original check order)",
				i, eie.MissingFields[i], f)
		}
	}

	// The PAYLOAD is complete; the MESSAGE stays frozen. technical_detail is part
	// of the --json surface, which is breaking-listed, so naming every absent
	// field there waits for §9.6. Conflating these two is how a plumbing commit
	// silently changes a versioned surface.
	//
	// PLANT TO PROVE THIS FIRES: make Error() join every MissingFields entry.
	// This assertion must fail.
	const wantFrozen = `v4-jcs attribution receipt missing required field: signing_key_id`
	if got := err.Error(); got != wantFrozen {
		t.Errorf("message is no longer byte-identical to the 1.6.x message:\n got: %s\nwant: %s",
			got, wantFrozen)
	}
}

// TestImplementedFormVersions_IsTheOnlyAllowlist guards the single source of
// truth, and records why it is not sufficient on its own.
func TestImplementedFormVersions_IsTheOnlyAllowlist(t *testing.T) {
	for _, fv := range ImplementedFormVersions {
		e := probeR1(fv)
		if err := e.ValidateFormVersion(); err != nil {
			t.Errorf("ValidateFormVersion(%q) = %v, want nil: the allowlist and the "+
				"validator disagree", fv, err)
		}
	}
	e := probeR1("v5-jcs")
	if err := e.ValidateFormVersion(); err == nil {
		t.Error("ValidateFormVersion(\"v5-jcs\") = nil: an unimplemented form was accepted")
	}
}
