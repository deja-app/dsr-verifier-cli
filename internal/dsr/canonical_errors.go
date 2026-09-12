package dsr

import (
	"fmt"
	"strings"
)

// Typed canonical-construction errors.
//
// CanonicalPayload previously returned bare fmt.Errorf values, so every caller
// saw one undifferentiated error and internal/verify collapsed all of them into
// error_class "signature_invalid". An auditor therefore read "the signature on
// this receipt does not verify" for a receipt whose canonical bytes were never
// constructed at all.
//
// These types carry what the caller needs to distinguish the cases. They do NOT
// carry a reason code: the reason-code namespace is §9.2 of
// DSR-V5-CANONICAL-FIELD-SET.md and is not invented here.
//
// COPY SLOT: the Error() strings below are preserved BYTE-IDENTICAL to the
// fmt.Errorf strings they replace, so this change alters no output. They do not
// yet satisfy the §9 copy rule — "unsupported canonical_form_version" asserts
// the version is not real, when it is real and this verifier does not implement
// it. Rewriting them needs §9.6, which is not in hand. Do not reword them here.

// FormNotImplementedError means the envelope declares a canonical_form_version
// this verifier does not implement, so the canonical bytes were never built.
//
// This is not a statement about the receipt. A receipt issued under a newer
// canonical form is a valid receipt that this binary is too old to check.
type FormNotImplementedError struct {
	// FormVersion is the declared form, as it appeared in the envelope.
	FormVersion string
	// Implemented lists the forms this build does implement, in spec order.
	Implemented []string
}

func (e *FormNotImplementedError) Error() string {
	return fmt.Sprintf(
		"unsupported canonical_form_version %q: this verifier implements "+
			"%s — upgrade the verifier to check receipts issued under %q",
		e.FormVersion, strings.Join(e.Implemented, ", "), e.FormVersion,
	)
}

// EnvelopeIncompleteError means the envelope lacks one or more fields the
// declared canonical form requires, so the canonical bytes were never built.
//
// One error type carrying a field list, not one type per field: "which fields"
// is what makes the message actionable, and a type per field is an unbounded
// namespace that grows every time a canonical form gains a member.
type EnvelopeIncompleteError struct {
	// Kind is the canonical-form family word used in the message
	// ("attribution", "resolution"). It is not the receipt type string.
	Kind string
	// FormVersion is set only when the requirement is specific to a form
	// version (the v3-jcs / v4-jcs mandatory signing-identity fields).
	// Empty when the field is required by every form of this kind.
	FormVersion string
	// MissingFields names every absent field.
	//
	// ORDER IS A SPEC SLOT. Until §9.2 specifies the field-list ordering for the
	// reason-code payload, fields are collected in the order the pre-existing
	// presence checks ran. That order is what keeps Error() byte-identical to the
	// message it replaced (see below), which the 1.7 release requires.
	MissingFields []string
}

// Error reports only the FIRST missing field, reproducing byte-for-byte the
// message of the fmt.Errorf this type replaced.
//
// The full list is deliberately NOT rendered here. technical_detail is part of
// the --json surface, which VERSIONING.md lists as breaking, so its content is
// frozen for 1.7 even though naming every absent field would be more useful.
// The complete list rides on MissingFields, where the reason code reads it.
// When §9.6 rewrites this copy the messages change anyway; name them all then.
func (e *EnvelopeIncompleteError) Error() string {
	if len(e.MissingFields) == 0 {
		return fmt.Sprintf("%s receipt missing a required field", e.Kind)
	}
	first := e.MissingFields[0]
	if e.FormVersion == "" {
		return fmt.Sprintf("%s receipt missing %s", e.Kind, first)
	}
	return fmt.Sprintf("%s %s receipt missing required field: %s",
		e.FormVersion, e.Kind, first)
}
