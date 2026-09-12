package verdict_test

import (
	"testing"

	"github.com/deja-app/dsr-verifier-cli/internal/verdict"
)

// highestState must equal the highest defined verdict.State.
//
// TestEnumIsExhaustive fails if a state is added past this one, which forces
// whoever adds it to decide explicitly whether it counts as verified rather
// than inheriting an answer. A test that only enumerates the states that exist
// today passes unchanged when a fourth is added, and would be a check that
// cannot fail.
const highestState = verdict.CannotVerify

// TestZeroValueIsNotVerified is the load-bearing guard in this package.
//
// Go's zero value is the most likely way a three-state vocabulary gets
// silently defeated: a struct whose State field is never populated aggregates
// as whatever State(0) means. If State(0) were Verified, every unpopulated
// field would count as a pass and the gate would fail open.
//
// PLANT TO PROVE THIS FIRES: in verdict.go, move Verified to the first
// position in the const block (so Verified == 0) and delete Unset. This test
// must fail on both assertions. Restore afterwards.
func TestZeroValueIsNotVerified(t *testing.T) {
	var zero verdict.State

	if zero != verdict.Unset {
		t.Errorf("State(0) = %d, want Unset (%d): the zero value must not be a verdict",
			zero, verdict.Unset)
	}
	if zero.CountsAsVerified() {
		t.Error("State(0).CountsAsVerified() = true: an unpopulated State field " +
			"must never aggregate as a pass")
	}
	if zero.IsVerdict() {
		t.Error("State(0).IsVerdict() = true: the zero value is not a verdict")
	}
}

// TestOnlyVerifiedCountsAsVerified pins the aggregation rule: cannot_verify
// groups with NOT VERIFIED in every aggregate, never with verified.
//
// PLANT TO PROVE THIS FIRES: change CountsAsVerified to
// `return s == Verified || s == CannotVerify`. The CannotVerify subtest must
// fail. Restore afterwards.
func TestOnlyVerifiedCountsAsVerified(t *testing.T) {
	cases := []struct {
		name string
		s    verdict.State
		want bool
	}{
		{"Unset", verdict.Unset, false},
		{"Verified", verdict.Verified, true},
		{"Failed", verdict.Failed, false},
		{"CannotVerify", verdict.CannotVerify, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.s.CountsAsVerified(); got != c.want {
				t.Errorf("%s.CountsAsVerified() = %v, want %v", c.name, got, c.want)
			}
			if got := verdict.CountsAsVerified(c.s); got != c.want {
				t.Errorf("CountsAsVerified(%s) = %v, want %v (function and method must agree)",
					c.name, got, c.want)
			}
		})
	}
}

// TestExactlyOneStateCountsAsVerified sweeps the whole enum range rather than
// the states named above, so a state added inside the range is still covered.
func TestExactlyOneStateCountsAsVerified(t *testing.T) {
	passing := 0
	for s := verdict.State(0); s <= highestState; s++ {
		if s.CountsAsVerified() {
			passing++
		}
	}
	if passing != 1 {
		t.Errorf("%d states count as verified across [0,%d], want exactly 1",
			passing, highestState)
	}
}

// TestEnumIsExhaustive fails when a state is added past highestState.
//
// IsVerdict enumerates the real verdicts. If a fourth state is added and
// IsVerdict is extended to include it, this assertion trips and the author
// must update highestState — at which point TestExactlyOneStateCountsAsVerified
// and TestOnlyVerifiedCountsAsVerified force a decision about the new state.
// If IsVerdict is NOT extended, the new state silently reports IsVerdict()
// false, which the boundary check surfaces.
//
// PLANT TO PROVE THIS FIRES: add `Provisional` after CannotVerify in
// verdict.go and include it in IsVerdict. This test must fail. Restore after.
func TestEnumIsExhaustive(t *testing.T) {
	beyond := highestState + 1
	if beyond.IsVerdict() {
		t.Errorf("State(%d) reports IsVerdict() = true but highestState is %d: "+
			"a state was added without updating highestState, so the aggregation "+
			"rule for it was never asserted", beyond, highestState)
	}
}
