package bundle

import (
	"os"
	"regexp"
	"sort"
	"testing"

	dsrerrors "github.com/deja-app/dsr-verifier-cli/internal/errors"
	"github.com/deja-app/dsr-verifier-cli/internal/verdict"
)

func failure(id string, state verdict.State, classes ...dsrerrors.ErrorClass) ReceiptFailure {
	f := ReceiptFailure{ReceiptID: id, Type: "R1", State: state}
	for _, c := range classes {
		f.Errors = append(f.Errors, dsrerrors.New(c, "msg", "detail"))
	}
	return f
}

func anomaliesFrom(failures ...ReceiptFailure) []Anomaly {
	res := &BundleVerifyResult{PerReceipt: PerReceiptResult{Failures: failures}}
	return ExtractAnomalies(res, nil)
}

// TestCannotVerifyNeverBecomesAnomaly is the gate.
//
// A receipt this verifier could not check must not become input to statistical
// tamper inference. Before the gate, an unimplemented canonical form reached
// error_class "signature_invalid" and was categorised as a signature mismatch,
// so it fed zone-concentration and temporal-clustering tests that emit
// p_value_lt "<0.001" — statistical evidence of tampering over receipts nobody
// touched.
//
// PLANT TO PROVE IT FIRES: delete the `if f.State != verdict.Failed { continue }`
// gate in ExtractAnomalies. This test must fail. Restore afterwards.
func TestCannotVerifyNeverBecomesAnomaly(t *testing.T) {
	cases := []struct {
		name  string
		class dsrerrors.ErrorClass
	}{
		{"unimplemented canonical form (collapses to signature_invalid)", dsrerrors.SignatureInvalid},
		{"incomplete envelope (collapses to signature_invalid)", dsrerrors.SignatureInvalid},
		{"unparseable receipt", dsrerrors.MalformedReceipt},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := anomaliesFrom(failure("r1", verdict.CannotVerify, c.class))
			if len(got) != 0 {
				t.Errorf("a cannot_verify receipt produced %d anomaly/anomalies (%v): "+
					"it will feed p-value inference about tampering that this verifier "+
					"never established", len(got), got)
			}
		})
	}
}

// TestFailedDoesBecomeAnomaly — the gate must not suppress real findings.
func TestFailedDoesBecomeAnomaly(t *testing.T) {
	got := anomaliesFrom(failure("r1", verdict.Failed, dsrerrors.SignatureInvalid))
	if len(got) != 1 {
		t.Fatalf("a genuine signature mismatch produced %d anomalies, want 1", len(got))
	}
	if got[0].Category != CategorySignatureMismatches {
		t.Errorf("Category = %q, want %q", got[0].Category, CategorySignatureMismatches)
	}
}

// TestUnsetStateIsNotAnAnomaly — fail closed. A ReceiptFailure whose State was
// never populated must not be treated as a finding.
func TestUnsetStateIsNotAnAnomaly(t *testing.T) {
	got := anomaliesFrom(failure("r1", verdict.Unset, dsrerrors.SignatureInvalid))
	if len(got) != 0 {
		t.Errorf("an unpopulated State produced %d anomalies: a forgotten assignment "+
			"must not manufacture a finding", len(got))
	}
}

// TestEveryErrorClassIsClassified is the test the card requires: it fails when a
// NEW class appears, not when the current ones work.
//
// A test enumerating signature_invalid, content_hash_mismatch and
// malformed_receipt and asserting their categories is green today and green
// after any future class is added — a check that cannot fail. This one forces a
// decision: every class must be either mapped to a category or explicitly
// excluded with a reason.
//
// PLANT TO PROVE IT FIRES: add a constant to dsrerrors.AllClasses without adding
// it to anomalyCategoryByClass or nonAnomalyClasses. This test must fail.
func TestEveryErrorClassIsClassified(t *testing.T) {
	var unclassified, both []string
	for _, c := range dsrerrors.AllClasses {
		_, mapped := anomalyCategoryByClass[c]
		_, excluded := nonAnomalyClasses[c]
		switch {
		case mapped && excluded:
			both = append(both, string(c))
		case !mapped && !excluded:
			unclassified = append(unclassified, string(c))
		}
	}
	if len(unclassified) > 0 {
		sort.Strings(unclassified)
		t.Errorf("error class(es) %v are in neither anomalyCategoryByClass nor "+
			"nonAnomalyClasses. A class nobody classified is silently dropped from "+
			"cluster analysis — the safe direction, but only if someone decided it. "+
			"Add each to a category, or to nonAnomalyClasses with the reason.", unclassified)
	}
	if len(both) > 0 {
		sort.Strings(both)
		t.Errorf("error class(es) %v appear in BOTH tables; the classification is "+
			"ambiguous", both)
	}
}

// TestAllClassesMatchesConstants closes the remaining hole: a class added to
// errors.go but NOT to AllClasses would escape the coverage test above.
//
// It reads the package source rather than reflecting, because Go cannot
// enumerate constants at runtime. Source-scanning is brittle in general; here it
// is scoped to one declaration form in one file, and the failure message says
// exactly what to do.
//
// PLANT TO PROVE IT FIRES: add `Foo ErrorClass = "foo"` to errors.go without
// adding Foo to AllClasses. This test must fail.
func TestAllClassesMatchesConstants(t *testing.T) {
	src, err := os.ReadFile("../errors/errors.go")
	if err != nil {
		t.Fatalf("read errors.go: %v", err)
	}
	re := regexp.MustCompile(`(?m)^\s*(\w+)\s+ErrorClass\s*=\s*"([^"]+)"`)
	var declared []string
	for _, m := range re.FindAllStringSubmatch(string(src), -1) {
		declared = append(declared, m[2])
	}
	if len(declared) == 0 {
		t.Fatal("found no ErrorClass constant declarations — the scan pattern has " +
			"drifted from the source and this test is no longer checking anything")
	}

	inAll := make(map[string]bool, len(dsrerrors.AllClasses))
	for _, c := range dsrerrors.AllClasses {
		inAll[string(c)] = true
	}
	var missing []string
	for _, d := range declared {
		if !inAll[d] {
			missing = append(missing, d)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("ErrorClass constant(s) %v are declared in errors.go but absent "+
			"from AllClasses, so TestEveryErrorClassIsClassified never sees them. "+
			"Add them to AllClasses.", missing)
	}
	if len(declared) != len(dsrerrors.AllClasses) {
		t.Errorf("errors.go declares %d ErrorClass constants but AllClasses has %d",
			len(declared), len(dsrerrors.AllClasses))
	}
}
