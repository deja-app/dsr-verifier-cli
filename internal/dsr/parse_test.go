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

// An R1 or R1-L signed with no actor is the receipt as issued: Déjà signs a
// null actor when the attribution names no author. Parse must accept it.
// Every other type still requires the field.
func TestParse_ActorOptionalOnlyForR1AndR1L(t *testing.T) {
	noActor := strings.Replace(minimalR1, `"actor": "actor@example.com",`, "", 1)
	nullActor := strings.Replace(minimalR1, `"actor": "actor@example.com",`, `"actor": null,`, 1)
	emptyActor := strings.Replace(minimalR1, `"actor": "actor@example.com",`, `"actor": "",`, 1)

	for _, typ := range []string{"R1", "R1-L"} {
		for label, input := range map[string]string{"absent": noActor, "null": nullActor, "empty": emptyActor} {
			t.Run(typ+"/"+label, func(t *testing.T) {
				in := strings.Replace(input, `"type": "R1",`, `"type": "`+typ+`",`, 1)
				if _, err := dsr.Parse([]byte(in)); err != nil {
					t.Fatalf("%s with %s actor: got %s — %s", typ, label, err.Class, err.HumanMessage)
				}
			})
		}
	}

	for _, typ := range []string{"R1-N", "R2", "RV", "RE"} {
		t.Run(typ+"/absent", func(t *testing.T) {
			in := strings.Replace(noActor, `"type": "R1",`, `"type": "`+typ+`",`, 1)
			_, err := dsr.Parse([]byte(in))
			if err == nil {
				t.Fatalf("%s with no actor: expected MalformedReceipt, got none", typ)
			}
			if err.Class != dsrerrors.MalformedReceipt || !strings.Contains(err.HumanMessage, "actor") {
				t.Errorf("%s with no actor: got %s — %s", typ, err.Class, err.HumanMessage)
			}
		})
	}
}

// A v5-jcs receipt signs its actor, null where the receipt names none (R1-N
// always), so Parse accepts a v5 receipt of any type with no actor. Every
// older form keeps the rule above.
const minimalV5R1N = `{
	"dsr_version": "DSR/1.0.4",
	"type": "R1-N",
	"canonical_form_version": "v5-jcs",
	"receipt_id": "R1N-00000000-0000-4000-8000-00000000c336",
	"vault_id": "00000000-0000-4000-8000-0000000000b7",
	"organization_id": "00000000-0000-4000-8000-0000000000a1",
	"timestamp": "2026-09-25T12:00:00.000Z",
	"actor": null,
	"origin": "production",
	"prior_hash": "1b5e2e7d1e0e4c7e6f9d1a6f6d7a3a0c1d3b6a1f0e4d9c2b7a5f8e3d1c6b9a04",
	"signing_key_id": "deja-managed-v1",
	"signature_algorithm": "ed25519-v1",
	"signature": "dGVzdHNpZ25hdHVyZQ=="
}`

func TestParse_V5_ActorOptionalForEveryType(t *testing.T) {
	for _, typ := range []string{"R1-N", "R0", "R2", "R2-F", "R2-R", "RV", "RE"} {
		for label, actor := range map[string]string{
			"null":   `"actor": null,`,
			"empty":  `"actor": "",`,
			"absent": "",
		} {
			t.Run(typ+"/"+label, func(t *testing.T) {
				in := strings.Replace(minimalV5R1N, `"actor": null,`, actor, 1)
				in = strings.Replace(in, `"type": "R1-N",`, `"type": "`+typ+`",`, 1)
				if _, err := dsr.Parse([]byte(in)); err != nil {
					t.Fatalf("v5 %s with %s actor: got %s — %s", typ, label, err.Class, err.HumanMessage)
				}
			})
		}
	}

	// The same R1-N on its v1-legacy form still needs one.
	legacy := strings.Replace(minimalV5R1N, `"canonical_form_version": "v5-jcs",`, "", 1)
	if _, err := dsr.Parse([]byte(legacy)); err == nil || !strings.Contains(err.HumanMessage, "actor") {
		t.Fatalf("v1-legacy R1-N with a null actor: expected MalformedReceipt naming actor, got %v", err)
	}
}

// A v5-jcs envelope missing a core field that may not be null is refused as
// malformed, naming the field, instead of being verified over "" or null.
func TestParse_V5_CoreFieldsRequired(t *testing.T) {
	for _, field := range []string{"organization_id", "prior_hash", "signing_key_id", "signature_algorithm"} {
		for label, replace := range map[string]string{"absent": "", "empty": `"` + field + `": "",`, "null": `"` + field + `": null,`} {
			t.Run(field+"/"+label, func(t *testing.T) {
				lines := strings.Split(minimalV5R1N, "\n")
				for i, l := range lines {
					if strings.Contains(l, `"`+field+`":`) {
						lines[i] = "\t" + replace
					}
				}
				_, err := dsr.Parse([]byte(strings.Join(lines, "\n")))
				if err == nil {
					t.Fatalf("v5 R1-N with %s %s: expected MalformedReceipt, got none", label, field)
				}
				if err.Class != dsrerrors.MalformedReceipt || !strings.Contains(err.HumanMessage, field) {
					t.Errorf("v5 R1-N with %s %s: got %s — %s", label, field, err.Class, err.HumanMessage)
				}
			})
		}
	}

	// On an older form none of them is required, as before.
	legacy := strings.Replace(minimalV5R1N, `"canonical_form_version": "v5-jcs",`, "", 1)
	legacy = strings.Replace(legacy, `"actor": null,`, `"actor": "system",`, 1)
	legacy = strings.Replace(legacy, `"organization_id": "00000000-0000-4000-8000-0000000000a1",`, "", 1)
	legacy = strings.Replace(legacy, `"prior_hash": "1b5e2e7d1e0e4c7e6f9d1a6f6d7a3a0c1d3b6a1f0e4d9c2b7a5f8e3d1c6b9a04",`, "", 1)
	if _, err := dsr.Parse([]byte(legacy)); err != nil {
		t.Fatalf("v1-legacy R1-N without organization_id or prior_hash: got %s — %s", err.Class, err.HumanMessage)
	}
}
