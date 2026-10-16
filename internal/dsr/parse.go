package dsr

import (
	"encoding/json"
	"fmt"
	"strings"

	dsrerrors "github.com/deja-app/dsr-verifier-cli/internal/errors"
)

// Parse parses a DSR receipt from raw JSON bytes into an Envelope.
//
// The parser is intentionally lenient: unknown fields are silently ignored.
// This lets the verifier work with receipts that carry newer optional fields
// that this version of the CLI has not yet enumerated. Required field
// validation happens after parsing.
//
// Version policy: any dsr_version beginning with "DSR/" is accepted. The
// verifier does not gate on a specific patch version — the canonical form
// rules are additive and backward-compatible.
func Parse(data []byte) (*Envelope, *dsrerrors.VerificationError) {
	var e Envelope
	if err := json.Unmarshal(data, &e); err != nil {
		offset := jsonErrorOffset(err)
		return nil, dsrerrors.New(
			dsrerrors.MalformedReceipt,
			"The receipt file could not be parsed as valid JSON. "+
				"The file may be corrupt, truncated, or not a DSR receipt.",
			fmt.Sprintf("JSON parse error at byte offset %d: %s", offset, err.Error()),
		)
	}

	if verr := validateEnvelope(&e); verr != nil {
		return nil, verr
	}

	return &e, nil
}

func validateEnvelope(e *Envelope) *dsrerrors.VerificationError {
	var missing []string

	if e.DSRVersion == "" {
		missing = append(missing, "dsr_version")
	}
	if e.Type == "" {
		missing = append(missing, "type")
	}
	if e.ReceiptID == "" {
		missing = append(missing, "receipt_id")
	}
	// RG governance receipts are org-scoped and carry organization_id instead
	// of vault_id. All other types require vault_id.
	if e.VaultID == "" && !IsGovernanceType(e.Type) {
		missing = append(missing, "vault_id")
	}
	if IsGovernanceType(e.Type) && e.OrganizationID == "" {
		missing = append(missing, "organization_id")
	}
	if e.Timestamp == "" {
		missing = append(missing, "timestamp")
	}
	// R1 and R1-L may be signed with no actor. Déjà signs a null actor when the
	// attribution names no author (an edge from /v1/sde/edge-ingest, or a GitHub
	// payload with no user), and every canonical form omits an empty actor
	// (CanonicalPayload: `if e.Actor != ""`, and v5Core's null). The export
	// carries the value that was signed, so an absent actor is the receipt as
	// issued, not a damaged one. This also covers R1-L issued before DSR/1.0.2,
	// which had no actor field at all. Leniency here cannot make a tampered
	// receipt pass: an actor removed from, or added to, a receipt changes its
	// canonical bytes, and the signature step refuses it.
	//
	// Under v5-jcs the actor is part of the signed core for every type, null
	// where the receipt names no actor (DSR v5 §1, §3: absence is the literal
	// null). R1-N always signs null; any type may. So for a v5 receipt an
	// absent actor is also the receipt as issued, and v5Core serialises it as
	// the null that was signed.
	// Every other type, in every older form, still requires the field.
	isV5 := e.FormVersion() == "v5-jcs"
	actorRequired := e.Type != TypeR1 && e.Type != TypeR1L && !isV5
	if e.Actor == "" && actorRequired {
		missing = append(missing, "actor")
	}
	// A v5-jcs receipt signs organization_id, prior_hash, signing_key_id and
	// signature_algorithm for every type, and none of them may be null (v5
	// §1). An envelope without one cannot be checked: v5Core would put "" or
	// null in its place, bytes no issuer signed, and the signature step would
	// call a genuine receipt tampered. §3.2 and §6: a verifier that lacks a
	// value says so and never substitutes one. So refuse it here, as a file
	// this verifier cannot read, not as a forgery.
	if isV5 {
		if e.OrganizationID == "" && !IsGovernanceType(e.Type) {
			missing = append(missing, "organization_id")
		}
		if e.PriorHash == nil || *e.PriorHash == "" {
			missing = append(missing, "prior_hash")
		}
		if e.SigningKeyID == nil || *e.SigningKeyID == "" {
			missing = append(missing, "signing_key_id")
		}
		if e.SignatureAlgorithm == nil || *e.SignatureAlgorithm == "" {
			missing = append(missing, "signature_algorithm")
		}
	}
	if e.Origin == "" {
		missing = append(missing, "origin")
	}
	if e.Signature == "" {
		missing = append(missing, "signature")
	}

	if len(missing) > 0 {
		return dsrerrors.New(
			dsrerrors.MalformedReceipt,
			fmt.Sprintf(
				"The receipt is missing required envelope fields: %s.",
				strings.Join(missing, ", "),
			),
			fmt.Sprintf("missing fields: [%s]", strings.Join(missing, ", ")),
		)
	}

	if !strings.HasPrefix(e.DSRVersion, "DSR/") {
		return dsrerrors.New(
			dsrerrors.MalformedReceipt,
			fmt.Sprintf(
				"The receipt declares version %q which does not begin with \"DSR/\". "+
					"The file may not be a DSR receipt.",
				e.DSRVersion,
			),
			fmt.Sprintf("dsr_version: %q", e.DSRVersion),
		)
	}

	if !KnownTypes[e.Type] {
		return dsrerrors.New(
			dsrerrors.MalformedReceipt,
			fmt.Sprintf(
				"The receipt type %q is not a recognized DSR receipt type. "+
					"Valid types are: R0, R1, R1-L, R1-N, R2, R2-F, R2-R, RV, RE, RG.",
				e.Type,
			),
			fmt.Sprintf("type: %q", e.Type),
		)
	}

	algo := e.SigAlgo()
	switch algo {
	case AlgoSHA256Legacy, AlgoED25519V1, AlgoRSAPSSSHA256, AlgoECDSASHA256:
		// accepted
	default:
		return dsrerrors.New(
			dsrerrors.UnsupportedAlgorithm,
			fmt.Sprintf(
				"The receipt declares signing algorithm %q which this verifier does not support. "+
					"Supported algorithms: sha256-legacy, ed25519-v1, rsa-pss-sha256, ecdsa-sha256.",
				algo,
			),
			fmt.Sprintf("signature_algorithm: %q", algo),
		)
	}

	return nil
}

// dsrVersionAtLeast reports whether a DSR version string (e.g. "DSR/1.0.2")
// is at or above the given major.minor.patch threshold.
// Returns false for any unparseable version string.
func dsrVersionAtLeast(version string, major, minor, patch int) bool {
	s := strings.TrimPrefix(version, "DSR/")
	var ma, mi, pa int
	if _, err := fmt.Sscanf(s, "%d.%d.%d", &ma, &mi, &pa); err != nil {
		// Try two-part (e.g. "1.0")
		pa = 0
		if _, err2 := fmt.Sscanf(s, "%d.%d", &ma, &mi); err2 != nil {
			return false
		}
	}
	if ma != major {
		return ma > major
	}
	if mi != minor {
		return mi > minor
	}
	return pa >= patch
}

func jsonErrorOffset(err error) int64 {
	if se, ok := err.(*json.SyntaxError); ok {
		return se.Offset
	}
	if ue, ok := err.(*json.UnmarshalTypeError); ok {
		return ue.Offset
	}
	return -1
}
