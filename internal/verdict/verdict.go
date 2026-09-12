// Package verdict defines the three-state verification vocabulary and the
// single aggregation rule that every count, summary line, exit code and
// bundle-level verdict must route through.
//
// The three states are a DISPLAY vocabulary. For any pass/fail decision they
// collapse to two, and cannot_verify groups with NOT VERIFIED — never with
// verified. CountsAsVerified is the only place that collapse happens. Fourteen
// sites in this repo each re-derive the verdict today; that duplication is why
// an unknown canonical form version is reported as TAMPERED in a bundle
// summary. One rule, one function, one test.
//
// SPEC SLOTS — deliberately absent from this package:
//
//   - the wire spelling of each state (§9.1)
//   - the reason-code namespace that discriminates within CannotVerify (§9.2)
//   - the exit-code mapping (§9.7, unwritten)
//   - the name of the third per-receipt count field (§9.2)
//
// Those belong to §9 of DSR-V5-CANONICAL-FIELD-SET.md and are NOT guessed here.
// Do not add a String() or MarshalJSON method to State until §9.1 is in hand:
// a guessed wire spelling is how two implementations independently derive one
// vocabulary, which is the defect class this package exists to close.
package verdict

// State is the verification verdict for one receipt or one check.
//
// The zero value is Unset, NOT Verified. This is deliberate and load-bearing:
// a struct whose State field was never populated must not aggregate as a pass.
// Go's zero value is the most likely way this vocabulary gets silently
// defeated, so the zero value is the one state that counts as nothing.
type State uint8

const (
	// Unset is the zero value. It is not a verdict and must never reach an
	// aggregate. It counts as not-verified so that forgetting to populate a
	// State field fails closed.
	Unset State = iota

	// Verified means the check ran and the receipt satisfied it.
	Verified

	// Failed means the check ran to completion and the receipt did not satisfy it.
	//
	// THE RULE: Failed is reserved for a COMPLETED COMPARISON THAT DISAGREED.
	//
	// Failed is an accusation. It claims the evidence was altered. So it must not
	// be used for conditions that only establish that the verifier could not
	// finish — a missing key, an unimplemented form, an incomplete envelope, or
	// signature bytes that will not decode. Undecodable bytes are the sharpest
	// case: damage and alteration are different claims, transit corruption
	// produces the former, and a verifier that cannot distinguish them must not
	// assert the accusing one.
	Failed

	// CannotVerify means the check did not run to a conclusion. The verifier
	// lacked something it needed — an implemented canonical form, a complete
	// envelope, a key — so no assertion about the receipt is available.
	//
	// A CannotVerify message states what THIS VERIFIER could not do, never what
	// the receipt is. The receipt is not accused; the verifier is limited.
	CannotVerify
)

// CountsAsVerified reports whether s may be counted as a pass.
//
// This is the ONLY collapse from three display states to two decision states.
// Every aggregate must call it rather than test a State value directly:
// counts, summary lines, exit codes, bundle-level verdicts, audit-log results.
//
// Only Verified counts. Unset does not (fail closed on an unpopulated field),
// Failed does not, and CannotVerify does not — which is what stops the third
// state weakening the gate for a pre-v5 receipt whose canonical_form_version is
// unsigned and therefore attacker-controllable.
func CountsAsVerified(s State) bool {
	return s == Verified
}

// CountsAsVerified reports whether s may be counted as a pass.
// Method form of the package-level function; both must agree.
func (s State) CountsAsVerified() bool {
	return CountsAsVerified(s)
}

// IsVerdict reports whether s is an actual verdict rather than the zero value.
//
// Call it at the boundary where a State enters an aggregate. A false result
// means a State field was never populated — a programming error, not a
// receipt condition — and should be surfaced loudly rather than counted.
func (s State) IsVerdict() bool {
	return s == Verified || s == Failed || s == CannotVerify
}
