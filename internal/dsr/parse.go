package dsr

import (
	"encoding/json"
	"fmt"
	"strings"

	dsrerrors "github.com/deja-dev/dsr-verifier-cli/internal/errors"
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
	if e.VaultID == "" {
		missing = append(missing, "vault_id")
	}
	if e.Timestamp == "" {
		missing = append(missing, "timestamp")
	}
	if e.Actor == "" {
		missing = append(missing, "actor")
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

func jsonErrorOffset(err error) int64 {
	if se, ok := err.(*json.SyntaxError); ok {
		return se.Offset
	}
	if ue, ok := err.(*json.UnmarshalTypeError); ok {
		return ue.Offset
	}
	return -1
}
