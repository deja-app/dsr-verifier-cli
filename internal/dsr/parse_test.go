package dsr_test

import (
	"strings"
	"testing"

	"github.com/deja-app/dsr-verifier-cli/internal/dsr"
	dsrerrors "github.com/deja-app/dsr-verifier-cli/internal/errors"
)

// minimalR1 is a valid ExternalDSREnvelope R1 receipt.
const minimalR1 = `{
	"dsr_version": "DSR/1.0.2",
	"type": "R1",
	"receipt_id": "rcpt_test_001",
	"vault_id": "vlt_test",
	"timestamp": "2026-05-12T12:42:08Z",
	"actor": "actor@example.com",
	"origin": "github",
	"signature": "dGVzdHNpZ25hdHVyZQ==",
	"repository": "github.com/org/repo",
	"pr_number": 42
}`

func TestParse_MinimalValid(t *testing.T) {
	e, err := dsr.Parse([]byte(minimalR1))
	if err != nil {
		t.Fatalf("Parse: %s — %s", err.Class, err.HumanMessage)
	}
	if e.ReceiptID != "rcpt_test_001" {
		t.Errorf("ReceiptID = %q", e.ReceiptID)
	}
	if e.Type != dsr.TypeR1 {
		t.Errorf("Type = %q", e.Type)
	}
	if e.VaultID != "vlt_test" {
		t.Errorf("VaultID = %q", e.VaultID)
	}
	if e.SigAlgo() != dsr.AlgoSHA256Legacy {
		t.Errorf("SigAlgo = %q, want %q", e.SigAlgo(), dsr.AlgoSHA256Legacy)
	}
	if e.FormVersion() != "v1-legacy" {
		t.Errorf("FormVersion = %q, want v1-legacy", e.FormVersion())
	}
}

// TestParse_Int64Fields proves that pr_number and time_to_resolution_ms are
// decoded as int64, not float64. 2^53+1 = 9007199254740993 — representable as
// int64 but not as float64 without precision loss.
func TestParse_Int64Fields(t *testing.T) {
	const big = `{
		"dsr_version": "DSR/1.0.2",
		"type": "R1",
		"receipt_id": "rcpt_int64",
		"vault_id": "vlt_test",
		"timestamp": "2026-06-01T00:00:00Z",
		"actor": "a@b.com",
		"origin": "github",
		"signature": "dGVzdA==",
		"pr_number": 9007199254740993
	}`
	e, err := dsr.Parse([]byte(big))
	if err != nil {
		t.Fatalf("Parse: %s", err.HumanMessage)
	}
	if e.PRNumber == nil {
		t.Fatal("PRNumber is nil")
	}
	want := int64(9007199254740993)
	if *e.PRNumber != want {
		t.Errorf("PRNumber = %d, want %d", *e.PRNumber, want)
	}
}

func TestParse_MissingRequired(t *testing.T) {
	cases := []struct {
		name   string
		remove string
	}{
		{"dsr_version", `"dsr_version": "DSR/1.0.2",`},
		{"type", `"type": "R1",`},
		{"receipt_id", `"receipt_id": "rcpt_test_001",`},
		{"vault_id", `"vault_id": "vlt_test",`},
		{"timestamp", `"timestamp": "2026-05-12T12:42:08Z",`},
		{"actor", `"actor": "actor@example.com",`},
		{"origin", `"origin": "github",`},
		{"signature", `"signature": "dGVzdHNpZ25hdHVyZQ==",`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := strings.Replace(minimalR1, tc.remove, "", 1)
			_, err := dsr.Parse([]byte(input))
			if err == nil {
				t.Fatalf("expected error for missing %s", tc.name)
			}
			if err.Class != dsrerrors.MalformedReceipt {
				t.Errorf("class = %q, want MalformedReceipt", err.Class)
			}
		})
	}
}

func TestParse_UnknownFieldsIgnored(t *testing.T) {
	// Lenient parser: unknown fields must NOT cause an error.
	input := strings.Replace(minimalR1, `"type": "R1"`,
		`"type": "R1", "unknown_future_field": "value"`, 1)
	_, err := dsr.Parse([]byte(input))
	if err != nil {
		t.Fatalf("unknown fields should be ignored, got: %s", err.HumanMessage)
	}
}

func TestParse_UnknownType(t *testing.T) {
	input := strings.Replace(minimalR1, `"type": "R1"`, `"type": "RX"`, 1)
	_, err := dsr.Parse([]byte(input))
	if err == nil {
		t.Fatal("expected error for unknown type RX")
	}
	if err.Class != dsrerrors.MalformedReceipt {
		t.Errorf("class = %q, want MalformedReceipt", err.Class)
	}
}

func TestParse_UnsupportedAlgorithm(t *testing.T) {
	algo := `"rsa-pkcs1"`
	input := strings.Replace(minimalR1, `"dGVzdHNpZ25hdHVyZQ=="`,
		`"dGVzdA==", "signature_algorithm": `+algo, 1)
	_, err := dsr.Parse([]byte(input))
	if err == nil {
		t.Fatal("expected error for unsupported algorithm rsa-pkcs1")
	}
	if err.Class != dsrerrors.UnsupportedAlgorithm {
		t.Errorf("class = %q, want UnsupportedAlgorithm", err.Class)
	}
}

func TestFormVersion_Defaults(t *testing.T) {
	// Absent canonical_form_version → v1-legacy
	e, err := dsr.Parse([]byte(minimalR1))
	if err != nil {
		t.Fatal(err.HumanMessage)
	}
	if e.FormVersion() != "v1-legacy" {
		t.Errorf("FormVersion() = %q, want v1-legacy", e.FormVersion())
	}

	// Explicit v2-jcs
	input := strings.Replace(minimalR1, `"origin": "github"`,
		`"origin": "github", "canonical_form_version": "v2-jcs"`, 1)
	e2, err2 := dsr.Parse([]byte(input))
	if err2 != nil {
		t.Fatal(err2.HumanMessage)
	}
	if e2.FormVersion() != "v2-jcs" {
		t.Errorf("FormVersion() = %q, want v2-jcs", e2.FormVersion())
	}
}

func TestSigAlgo_Defaults(t *testing.T) {
	// Absent signature_algorithm → sha256-legacy
	e, err := dsr.Parse([]byte(minimalR1))
	if err != nil {
		t.Fatal(err.HumanMessage)
	}
	if e.SigAlgo() != dsr.AlgoSHA256Legacy {
		t.Errorf("SigAlgo() = %q, want %q", e.SigAlgo(), dsr.AlgoSHA256Legacy)
	}

	// Explicit ed25519-v1
	algo := dsr.AlgoED25519V1
	input := strings.Replace(minimalR1, `"origin": "github"`,
		`"origin": "github", "signature_algorithm": "`+algo+`"`, 1)
	e2, err2 := dsr.Parse([]byte(input))
	if err2 != nil {
		t.Fatal(err2.HumanMessage)
	}
	if e2.SigAlgo() != algo {
		t.Errorf("SigAlgo() = %q, want %q", e2.SigAlgo(), algo)
	}
}
