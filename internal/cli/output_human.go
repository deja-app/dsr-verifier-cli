package cli

import (
	"fmt"
	"strings"

	"github.com/deja-dev/dsr-verifier-cli/internal/verify"
	dsrerrors "github.com/deja-dev/dsr-verifier-cli/internal/errors"
)

// VerifyResults aggregates the output of all verification checks plus
// the metadata needed for output formatting.
type VerifyResults struct {
	ReceiptID   string
	ReceiptType string
	VaultID     string
	Timestamp   string
	Algorithm   string
	FormVersion string

	KeyAuthority *verify.KeyAuthorityResult
	Sig          *verify.SignatureResult

	DurationMS int64
	LogFile    string
}

// AllPassed reports whether all applicable checks passed.
func (r *VerifyResults) AllPassed() bool {
	if r.KeyAuthority != nil && !r.KeyAuthority.Valid {
		return false
	}
	return r.Sig != nil && r.Sig.Valid
}

// FailureCount returns the number of failed checks.
func (r *VerifyResults) FailureCount() int {
	count := 0
	if r.KeyAuthority != nil && !r.KeyAuthority.Valid {
		count++
	}
	if r.Sig != nil && !r.Sig.Valid {
		count++
	}
	return count
}

// PrintVerifyResults writes the full human-readable verification output to p.
func PrintVerifyResults(p *Printer, r *VerifyResults) {
	totalChecks := 2
	skippedChecks := 0

	// Key authority check
	if r.KeyAuthority.Skipped {
		skippedChecks++
		p.CheckLine(true, "Key authority check", "SKIPPED")
		p.Indent(p.Dim("sha256-legacy receipts do not use a public-key scheme"))
	} else {
		p.CheckLine(r.KeyAuthority.Valid, "Key authority check", statusLabel(r.KeyAuthority.Valid))
		if r.KeyAuthority.Valid {
			if r.KeyAuthority.ClaimedKeyID != "" {
				p.Detail("Claimed key ID", r.KeyAuthority.ClaimedKeyID)
			}
			if r.KeyAuthority.ProvidedKeyID != "" {
				p.Detail("Provided key ID", r.KeyAuthority.ProvidedKeyID)
			}
		} else {
			printFailDetails(p, r.KeyAuthority.Err, map[string]string{
				"Receipt key ID":  r.KeyAuthority.ClaimedKeyID,
				"Key file key ID": r.KeyAuthority.ProvidedKeyID,
			})
		}
	}
	p.Println("")

	// Signature check
	p.CheckLine(r.Sig.Valid, "Signature verification", statusLabel(r.Sig.Valid))
	if r.Sig.Valid {
		p.Detail("Algorithm", r.Sig.Algorithm)
		if r.Sig.PublicKeyDigest != "" {
			p.Detail("Public key", r.Sig.PublicKeyDigest)
		}
		p.Detail("Canonical payload", fmt.Sprintf("%d bytes", r.Sig.CanonicalLen))
	} else {
		printFailDetails(p, r.Sig.Err, map[string]string{
			"Algorithm": r.Sig.Algorithm,
		})
	}
	p.Println("")

	// Summary
	p.Separator()

	passedChecks := totalChecks - skippedChecks - r.FailureCount()

	if r.AllPassed() {
		p.Println(p.Green(p.Bold("Result: VERIFIED")) +
			fmt.Sprintf("  ·  %d check(s) passed", passedChecks))
		p.Printf("Receipt: %s  ·  %s  ·  %s\n",
			p.Dim(r.ReceiptID), p.Dim(r.ReceiptType), p.Dim(r.Algorithm))
	} else {
		fc := r.FailureCount()
		p.Println(p.Red(p.Bold("Result: FAILED")) +
			fmt.Sprintf("  ·  %d check(s) failed  ·  %d passed", fc, passedChecks))
		p.Println("")

		for _, f := range collectFailures(r) {
			p.Println(p.Red("Failure: ") + string(f.Class))
			p.Println("")
			for _, line := range wrapText(f.HumanMessage, lineWidth-2) {
				p.Indent(line)
			}
			p.Println("")
		}

		p.Println(p.Bold("Recommended actions for auditor:"))
		p.Println("")
		p.Indent("• Confirm the receipt file was not modified in transit")
		p.Indent("• Request a fresh receipt copy directly from the issuing organization's vault")
		p.Indent("• " + p.Red("Do NOT") + " trust the content of this receipt for audit purposes")
		p.Indent("• Report the discrepancy to the issuing organization and document in your audit")
		p.Println("")
	}

	p.Println("")
	p.Printf("%s · %s · duration %dms\n",
		p.Dim("offline"), p.Dim("zero network calls"), r.DurationMS)
	if r.LogFile != "" {
		p.Printf("Logged to: %s\n", p.Cyan(r.LogFile))
	}
	p.Separator()
}

// PrintInfo writes the human-readable info output (no verification).
func PrintInfo(p *Printer, receiptID, receiptType, vaultID, timestamp, keyID, algorithm string) {
	p.Separator()
	p.Println(p.Yellow(p.Bold("INFO ONLY — RECEIPT NOT VERIFIED")))
	p.Println(p.Dim("No signature verification was performed. Run 'verify' to verify."))
	p.Separator()
	p.Println("")

	p.Printf("Receipt:     %s\n", p.Bold(receiptID))
	p.Printf("Type:        %s  ·  %s\n", p.Bold(receiptType), receiptTypeLabel(receiptType))
	p.Printf("Vault:       %s\n", vaultID)
	p.Printf("Timestamp:   %s\n", timestamp)
	p.Println("")
	if keyID != "" {
		p.Printf("Signing key: %s\n", keyID)
	}
	p.Printf("Algorithm:   %s\n", algorithm)
	p.Println("")
	p.Println(p.Dim("To verify this receipt cryptographically, run:"))
	p.Println(p.Dim("  dsr-verify verify <receipt.dsr> --public-key <pubkey>"))
}

// statusLabel returns "OK" or "FAIL".
func statusLabel(passed bool) string {
	if passed {
		return "OK"
	}
	return "FAIL"
}

// receiptTypeLabel returns a human-readable label for a receipt type.
func receiptTypeLabel(t string) string {
	switch t {
	case "R0":
		return "No Attribution"
	case "R1":
		return "Attribution"
	case "R1-L":
		return "Low Confidence Attribution"
	case "R1-N":
		return "No Match"
	case "R2":
		return "Resolution"
	case "R2-F":
		return "Resolution Failed"
	case "R2-R":
		return "Reopened"
	case "RV":
		return "Vault Verification"
	case "RE":
		return "Exception"
	case "RG":
		return "Governance"
	default:
		return t
	}
}

// printFailDetails prints the short diagnostic block under a FAIL check line.
func printFailDetails(p *Printer, verr *dsrerrors.VerificationError, fields map[string]string) {
	if verr != nil {
		p.Indent(p.Dim("Error class: " + string(verr.Class)))
	}
	for k, v := range fields {
		if v != "" {
			p.Detail(k, v)
		}
	}
}

// collectFailures returns errors from all failed checks in order.
func collectFailures(r *VerifyResults) []*dsrerrors.VerificationError {
	var out []*dsrerrors.VerificationError
	for _, e := range []*dsrerrors.VerificationError{
		r.KeyAuthority.Err, r.Sig.Err,
	} {
		if e != nil {
			out = append(out, e)
		}
	}
	return out
}

// wrapText hard-wraps text at maxWidth characters, breaking at spaces.
func wrapText(text string, maxWidth int) []string {
	if maxWidth <= 0 {
		return []string{text}
	}
	words := strings.Fields(text)
	var lines []string
	var current strings.Builder

	for _, word := range words {
		need := current.Len()
		if need > 0 {
			need++
		}
		need += len(word)

		if current.Len() > 0 && need > maxWidth {
			lines = append(lines, current.String())
			current.Reset()
		}
		if current.Len() > 0 {
			current.WriteByte(' ')
		}
		current.WriteString(word)
	}
	if current.Len() > 0 {
		lines = append(lines, current.String())
	}
	return lines
}

// truncateHash returns the first 32 chars + "..." for display.
func truncateHash(h string) string {
	if len(h) > 32 {
		return h[:32] + "..."
	}
	return h
}
