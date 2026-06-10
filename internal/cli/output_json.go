package cli

import (
	"encoding/json"
	"fmt"
	"io"

	dsrerrors "github.com/deja-dev/dsr-verifier-cli/internal/errors"
)

// JSONOutput is the top-level --json output document.
type JSONOutput struct {
	Version        string        `json:"version"`
	ReceiptID      string        `json:"receipt_id"`
	ReceiptType    string        `json:"receipt_type"`
	VaultID        string        `json:"vault_id"`
	Algorithm      string        `json:"algorithm"`
	FormVersion    string        `json:"form_version"`
	Result         string        `json:"result"`
	Checks         JSONChecks    `json:"checks"`
	FailureReasons []JSONFailure `json:"failure_reasons"`
	DurationMS     int64         `json:"duration_ms"`
	Offline        bool          `json:"offline"`
}

// JSONChecks holds the per-check result summary.
type JSONChecks struct {
	KeyAuthority JSONCheckResult `json:"key_authority"`
	Signature    JSONCheckResult `json:"signature"`
}

// JSONCheckResult is the result of a single verification check.
type JSONCheckResult struct {
	Passed  bool            `json:"passed"`
	Skipped bool            `json:"skipped,omitempty"`
	Details json.RawMessage `json:"details,omitempty"`
}

// JSONFailure is one entry in failure_reasons.
type JSONFailure struct {
	Check           string `json:"check"`
	ErrorClass      string `json:"error_class"`
	HumanMessage    string `json:"human_message"`
	TechnicalDetail string `json:"technical_detail"`
}

// WriteJSON emits the JSON output document to w.
func WriteJSON(w io.Writer, r *VerifyResults) error {
	out := buildJSONOutput(r)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func buildJSONOutput(r *VerifyResults) *JSONOutput {
	result := "verified"
	if !r.AllPassed() {
		result = "failed"
	}

	out := &JSONOutput{
		Version:     Version,
		ReceiptID:   r.ReceiptID,
		ReceiptType: r.ReceiptType,
		VaultID:     r.VaultID,
		Algorithm:   r.Algorithm,
		FormVersion: r.FormVersion,
		Result:      result,
		DurationMS:  r.DurationMS,
		Offline:     true,
	}

	if r.KeyAuthority != nil {
		det := map[string]string{
			"claimed_key_id":  r.KeyAuthority.ClaimedKeyID,
			"provided_key_id": r.KeyAuthority.ProvidedKeyID,
		}
		b, _ := json.Marshal(det)
		out.Checks.KeyAuthority = JSONCheckResult{
			Passed:  r.KeyAuthority.Valid,
			Skipped: r.KeyAuthority.Skipped,
			Details: json.RawMessage(b),
		}
	}

	if r.Sig != nil {
		det := map[string]interface{}{
			"algorithm":        r.Sig.Algorithm,
			"canonical_len":    r.Sig.CanonicalLen,
			"public_key_sha256": r.Sig.PublicKeyDigest,
		}
		b, _ := json.Marshal(det)
		out.Checks.Signature = JSONCheckResult{
			Passed:  r.Sig.Valid,
			Details: json.RawMessage(b),
		}
	}

	for _, f := range []struct {
		name string
		err  *dsrerrors.VerificationError
	}{
		{"key_authority", r.KeyAuthority.Err},
		{"signature", r.Sig.Err},
	} {
		if f.err != nil {
			out.FailureReasons = append(out.FailureReasons, JSONFailure{
				Check:           f.name,
				ErrorClass:      string(f.err.Class),
				HumanMessage:    f.err.HumanMessage,
				TechnicalDetail: f.err.TechnicalDetail,
			})
		}
	}
	if out.FailureReasons == nil {
		out.FailureReasons = []JSONFailure{}
	}

	return out
}

// JSONInfoOutput is the --json output for the info command.
type JSONInfoOutput struct {
	Version     string `json:"version"`
	ReceiptID   string `json:"receipt_id"`
	ReceiptType string `json:"receipt_type"`
	VaultID     string `json:"vault_id"`
	Timestamp   string `json:"timestamp"`
	SigningKeyID string `json:"signing_key_id,omitempty"`
	Algorithm   string `json:"signing_algorithm"`
	Verified    bool   `json:"verified"`
	Note        string `json:"note"`
}

// WriteJSONInfo emits the info JSON document to w.
func WriteJSONInfo(w io.Writer, info *JSONInfoOutput) error {
	info.Verified = false
	info.Note = "INFO ONLY — receipt not verified; no signature check was performed"
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(info); err != nil {
		return fmt.Errorf("encode json info: %w", err)
	}
	return nil
}
