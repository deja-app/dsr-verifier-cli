// Package verify implements offline cryptographic verification of DSR receipts
// in the ExternalDSREnvelope format. Every function is stateless and pure —
// given the same inputs they produce the same output, with zero network calls.
//
// Verification steps for a single receipt:
//
//  1. KeyAuthority  — key_id in receipt matches key_id in provided key file
//  2. Signature     — cryptographic check; dispatches on signature_algorithm
//  3. ChainHash     — bundle-internal prior_hash consistency (optional)
//
// sha256-legacy receipts use a hash-comparison "signature" (not a public-key
// scheme); KeyAuthority is skipped and no public key is required.
package verify

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/deja-dev/dsr-verifier-cli/internal/dsr"
	dsrerrors "github.com/deja-dev/dsr-verifier-cli/internal/errors"
)

// ─────────────────────────────────────────────────────────────────────────────
// 1. Key authority
// ─────────────────────────────────────────────────────────────────────────────

// KeyAuthorityResult is returned by KeyAuthority.
type KeyAuthorityResult struct {
	Valid         bool
	ClaimedKeyID  string
	ProvidedKeyID string
	Skipped       bool // true for sha256-legacy (no public-key scheme)
	Err           *dsrerrors.VerificationError
}

// KeyAuthority compares the receipt's signing_key_id against the key_id
// declared in the provided public key file. A mismatch means the auditor is
// holding the wrong key for this receipt — surface the root cause before
// spending cycles on crypto.
//
// sha256-legacy receipts do not use a public key; KeyAuthority is a no-op
// (returns Valid=true, Skipped=true) for those receipts.
func KeyAuthority(e *dsr.Envelope, provided *PublicKeyWithID) *KeyAuthorityResult {
	if e.SigAlgo() == dsr.AlgoSHA256Legacy {
		return &KeyAuthorityResult{Valid: true, Skipped: true}
	}

	claimedID := ""
	if e.SigningKeyID != nil {
		claimedID = *e.SigningKeyID
	}

	res := &KeyAuthorityResult{
		ClaimedKeyID: claimedID,
	}
	if provided != nil {
		res.ProvidedKeyID = provided.KeyID
	}

	if provided != nil && provided.KeyID != "" && claimedID != "" && claimedID != provided.KeyID {
		res.Valid = false
		res.Err = dsrerrors.New(
			dsrerrors.KeyAuthorityMismatch,
			fmt.Sprintf(
				"The receipt claims it was signed by key %q, but the provided public key "+
					"identifies as %q. You are likely using the wrong public key for this receipt.",
				claimedID, provided.KeyID,
			),
			fmt.Sprintf("receipt.signing_key_id=%q, key_file.key_id=%q", claimedID, provided.KeyID),
		)
		return res
	}

	res.Valid = true
	return res
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Signature
// ─────────────────────────────────────────────────────────────────────────────

// SignatureResult is returned by Signature.
type SignatureResult struct {
	Valid           bool
	Algorithm       string
	CanonicalLen    int
	PublicKeyDigest string // sha256:<16-hex-char prefix>
	Err             *dsrerrors.VerificationError
}

// Signature verifies the receipt's signature using the provided public key.
//
// Algorithm dispatch:
//   - sha256-legacy   → SHA-256(canonical) == signature_hex  (constant-time)
//   - ed25519-v1      → ed25519.Verify over raw canonical bytes (no pre-hash)
//   - rsa-pss-sha256  → rsa.VerifyPSS, SHA-256 digest, PSSSaltLengthAuto
//   - ecdsa-sha256    → ecdsa.VerifyASN1, SHA-256 digest (DER-encoded sig)
func Signature(e *dsr.Envelope, provided *PublicKeyWithID) *SignatureResult {
	algo := e.SigAlgo()
	res := &SignatureResult{Algorithm: algo}

	canonical, err := dsr.CanonicalPayload(e)
	if err != nil {
		res.Valid = false
		res.Err = dsrerrors.New(
			dsrerrors.SignatureInvalid,
			"The verifier could not construct the canonical signed payload for this receipt. "+
				"The receipt may be missing required type-specific fields.",
			fmt.Sprintf("CanonicalPayload error: %s", err.Error()),
		)
		return res
	}
	res.CanonicalLen = len(canonical)
	canonicalBytes := []byte(canonical)

	switch algo {
	case dsr.AlgoSHA256Legacy:
		return verifySHA256Legacy(e, canonicalBytes, res)

	case dsr.AlgoED25519V1:
		if provided == nil {
			res.Valid = false
			res.Err = dsrerrors.New(
				dsrerrors.SignatureInvalid,
				"The receipt uses algorithm \"ed25519-v1\" but no public key was provided. "+
					"Pass the managed public key with --public-key.",
				"provided key is nil for ed25519-v1 receipt",
			)
			return res
		}
		pub, ok := provided.Key.(ed25519.PublicKey)
		if !ok {
			res.Valid = false
			res.Err = dsrerrors.New(
				dsrerrors.SignatureInvalid,
				"The receipt uses algorithm \"ed25519-v1\" but the provided key is not an Ed25519 key.",
				fmt.Sprintf("key type: %T, expected: ed25519.PublicKey", provided.Key),
			)
			return res
		}
		res.PublicKeyDigest = keyDigest([]byte(pub))
		sigBytes, decErr := base64.StdEncoding.DecodeString(e.Signature)
		if decErr != nil {
			res.Valid = false
			res.Err = dsrerrors.New(
				dsrerrors.SignatureInvalid,
				"The receipt's signature field is not valid base64.",
				fmt.Sprintf("base64 decode error: %s", decErr.Error()),
			)
			return res
		}
		if !ed25519.Verify(pub, canonicalBytes, sigBytes) {
			res.Valid = false
			res.Err = signatureFailedErr(algo, e.SigningKeyID)
			return res
		}

	case dsr.AlgoRSAPSSSHA256:
		if provided == nil {
			res.Valid = false
			res.Err = dsrerrors.New(
				dsrerrors.SignatureInvalid,
				"The receipt uses algorithm \"rsa-pss-sha256\" but no BYOK public key was provided. "+
					"Pass the customer RSA key with --byok-key.",
				"provided key is nil for rsa-pss-sha256 receipt",
			)
			return res
		}
		pub, ok := provided.Key.(*rsa.PublicKey)
		if !ok {
			res.Valid = false
			res.Err = dsrerrors.New(
				dsrerrors.SignatureInvalid,
				"The receipt uses algorithm \"rsa-pss-sha256\" but the provided key is not an RSA key.",
				fmt.Sprintf("key type: %T, expected: *rsa.PublicKey", provided.Key),
			)
			return res
		}
		der, _ := marshalPKIX(pub)
		res.PublicKeyDigest = keyDigest(der)
		sigBytes, decErr := base64.StdEncoding.DecodeString(e.Signature)
		if decErr != nil {
			res.Valid = false
			res.Err = dsrerrors.New(
				dsrerrors.SignatureInvalid,
				"The receipt's signature field is not valid base64.",
				fmt.Sprintf("base64 decode error: %s", decErr.Error()),
			)
			return res
		}
		if !verifyRSAPSS(pub, canonicalBytes, sigBytes) {
			res.Valid = false
			res.Err = signatureFailedErr(algo, e.SigningKeyID)
			return res
		}

	case dsr.AlgoECDSASHA256:
		if provided == nil {
			res.Valid = false
			res.Err = dsrerrors.New(
				dsrerrors.SignatureInvalid,
				"The receipt uses algorithm \"ecdsa-sha256\" but no BYOK public key was provided. "+
					"Pass the customer ECDSA key with --byok-key.",
				"provided key is nil for ecdsa-sha256 receipt",
			)
			return res
		}
		pub, ok := provided.Key.(*ecdsa.PublicKey)
		if !ok {
			res.Valid = false
			res.Err = dsrerrors.New(
				dsrerrors.SignatureInvalid,
				"The receipt uses algorithm \"ecdsa-sha256\" but the provided key is not an ECDSA key.",
				fmt.Sprintf("key type: %T, expected: *ecdsa.PublicKey", provided.Key),
			)
			return res
		}
		der, _ := marshalPKIX(pub)
		res.PublicKeyDigest = keyDigest(der)
		sigBytes, decErr := base64.StdEncoding.DecodeString(e.Signature)
		if decErr != nil {
			res.Valid = false
			res.Err = dsrerrors.New(
				dsrerrors.SignatureInvalid,
				"The receipt's signature field is not valid base64.",
				fmt.Sprintf("base64 decode error: %s", decErr.Error()),
			)
			return res
		}
		hashed := sha256.Sum256(canonicalBytes)
		if !ecdsa.VerifyASN1(pub, hashed[:], sigBytes) {
			res.Valid = false
			res.Err = signatureFailedErr(algo, e.SigningKeyID)
			return res
		}

	default:
		res.Valid = false
		res.Err = dsrerrors.New(
			dsrerrors.UnsupportedAlgorithm,
			fmt.Sprintf("Algorithm %q is not supported by this verifier.", algo),
			fmt.Sprintf("signature_algorithm: %q", algo),
		)
		return res
	}

	res.Valid = true
	return res
}

func verifySHA256Legacy(e *dsr.Envelope, canonicalBytes []byte, res *SignatureResult) *SignatureResult {
	// sha256-legacy: signature IS SHA-256_hex(canonical_payload_bytes).
	// Constant-time comparison to prevent timing oracle attacks.
	sum := sha256.Sum256(canonicalBytes)
	computed := hex.EncodeToString(sum[:])

	storedBytes, err := hex.DecodeString(e.Signature)
	if err != nil {
		res.Valid = false
		res.Err = dsrerrors.New(
			dsrerrors.SignatureInvalid,
			"The receipt's signature field is not valid hex (expected for sha256-legacy).",
			fmt.Sprintf("hex decode error: %s", err.Error()),
		)
		return res
	}

	if subtle.ConstantTimeCompare(sum[:], storedBytes) != 1 {
		res.Valid = false
		res.Err = dsrerrors.New(
			dsrerrors.SignatureInvalid,
			fmt.Sprintf(
				"The SHA-256 hash of the canonical payload does not match the stored signature. "+
					"Computed: %s  Stored: %s",
				computed, e.Signature,
			),
			fmt.Sprintf("algorithm=sha256-legacy, computed=%s, stored=%s", computed, e.Signature),
		)
		return res
	}

	res.Valid = true
	return res
}

// verifyRSAPSS verifies an RSA-PSS SHA-256 signature.
// PSSSaltLengthAuto matches AWS KMS RSASSA_PSS_SHA_256 and Node.js padding:4 behavior.
func verifyRSAPSS(pub *rsa.PublicKey, canonicalBytes, sig []byte) bool {
	hashed := sha256.Sum256(canonicalBytes)
	opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: crypto.SHA256}
	return rsa.VerifyPSS(pub, crypto.SHA256, hashed[:], sig, opts) == nil
}

func signatureFailedErr(algo string, keyID *string) *dsrerrors.VerificationError {
	kid := ""
	if keyID != nil {
		kid = *keyID
	}
	return dsrerrors.New(
		dsrerrors.SignatureInvalid,
		fmt.Sprintf(
			"The %s signature on this receipt does not verify. "+
				"This means: (1) the receipt was not signed by this key, "+
				"(2) the signed fields were modified after issuance, or "+
				"(3) the signature bytes are corrupt. "+
				"Do not treat this receipt as audit evidence without resolving this failure.",
			algo,
		),
		fmt.Sprintf("algorithm=%s key_id=%q verify=false", algo, kid),
	)
}

func keyDigest(keyBytes []byte) string {
	sum := sha256.Sum256(keyBytes)
	return fmt.Sprintf("sha256:%s", hex.EncodeToString(sum[:])[:16])
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Chain hash (bundle-internal consistency)
// ─────────────────────────────────────────────────────────────────────────────

// ChainHashResult is returned by VerifyChainHash.
type ChainHashResult struct {
	Valid    bool
	Checked  int // number of consecutive pairs verified
	Skipped  bool
	Err      *dsrerrors.VerificationError
}

// VerifyChainHash checks that each receipt's prior_hash equals
// ChainHash(prev.prior_hash, canonical(prev)) for every consecutive pair in
// receipts. The receipts must be ordered oldest-first.
//
// This proves bundle-internal consistency: these receipts form an unbroken
// signed chain. It does NOT prove completeness — receipts outside the bundle
// may exist between any two entries.
//
// Returns Skipped=true when len(receipts) < 2 (nothing to check).
func VerifyChainHash(receipts []*dsr.Envelope) *ChainHashResult {
	if len(receipts) < 2 {
		return &ChainHashResult{Valid: true, Skipped: true}
	}

	for i := 1; i < len(receipts); i++ {
		prev := receipts[i-1]
		curr := receipts[i]

		if curr.PriorHash == nil {
			// Receipt declares no prior_hash — chain is not asserted, skip this pair.
			continue
		}

		prevCanonical, err := dsr.CanonicalPayload(prev)
		if err != nil {
			return &ChainHashResult{
				Valid: false,
				Err: dsrerrors.New(
					dsrerrors.HashChainBroken,
					fmt.Sprintf(
						"Could not compute canonical payload for receipt %q (position %d) "+
							"to verify the chain hash of receipt %q.",
						prev.ReceiptID, i-1, curr.ReceiptID,
					),
					fmt.Sprintf("CanonicalPayload error for receipt[%d]: %s", i-1, err.Error()),
				),
			}
		}

		expected := dsr.ChainHash(prev.PriorHash, prevCanonical)
		if *curr.PriorHash != expected {
			return &ChainHashResult{
				Valid: false,
				Err: dsrerrors.New(
					dsrerrors.HashChainBroken,
					fmt.Sprintf(
						"Receipt %q (position %d) has prior_hash %q but the computed hash of "+
							"the previous receipt %q is %q. "+
							"The receipts do not form a consistent signed chain — one may have been "+
							"substituted or the bundle is missing entries between these positions.",
						curr.ReceiptID, i, *curr.PriorHash, prev.ReceiptID, expected,
					),
					fmt.Sprintf(
						"curr=%q position=%d prior_hash=%q computed=%q prev=%q",
						curr.ReceiptID, i, *curr.PriorHash, expected, prev.ReceiptID,
					),
				),
			}
		}
	}

	return &ChainHashResult{Valid: true, Checked: len(receipts) - 1}
}
