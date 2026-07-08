package verify

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"

	dsrerrors "github.com/deja-app/dsr-verifier-cli/internal/errors"
)

// PublicKeyWithID bundles a parsed public key with the optional key_id extracted
// from the key file comment. The Key field holds one of:
//
//   - ed25519.PublicKey
//   - *rsa.PublicKey
//   - *ecdsa.PublicKey
type PublicKeyWithID struct {
	Key   interface{}
	KeyID string
}

// ParsePublicKeyFile auto-detects the key format and parses accordingly:
//   - If the file contains "-----BEGIN", parse as PKIX PEM.
//   - Otherwise, treat as a base64-encoded raw 32-byte Ed25519 public key.
//
// Both formats may include an optional header comment:
//
//	# key_id: <id>
//
// placed before the PEM block (or on its own line for base64 keys).
func ParsePublicKeyFile(data []byte) (*PublicKeyWithID, *dsrerrors.VerificationError) {
	if bytes.Contains(data, []byte("-----BEGIN")) {
		return parsePEMKey(data)
	}
	return parseED25519Base64Key(data)
}

// parsePEMKey parses a PKIX PEM-encoded public key ("BEGIN PUBLIC KEY").
// Supported key types: ed25519, RSA, ECDSA.
func parsePEMKey(data []byte) (*PublicKeyWithID, *dsrerrors.VerificationError) {
	keyID := extractKeyID(data)

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, dsrerrors.New(
			dsrerrors.KeyParseError,
			"The key file contains a PEM header but no valid PEM block was found. "+
				"Expected '-----BEGIN PUBLIC KEY-----'.",
			"pem.Decode returned nil",
		)
	}
	if block.Type != "PUBLIC KEY" {
		return nil, dsrerrors.New(
			dsrerrors.KeyParseError,
			fmt.Sprintf(
				"The key file contains a %q PEM block but this verifier expects a %q block "+
					"(PKIX SubjectPublicKeyInfo encoding).",
				block.Type, "PUBLIC KEY",
			),
			fmt.Sprintf("pem block type: %q, expected: %q", block.Type, "PUBLIC KEY"),
		)
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, dsrerrors.New(
			dsrerrors.KeyParseError,
			"The public key file could not be parsed. The PEM block may be corrupt or use "+
				"an encoding other than PKIX SubjectPublicKeyInfo.",
			fmt.Sprintf("x509.ParsePKIXPublicKey error: %s", err.Error()),
		)
	}

	switch k := pub.(type) {
	case ed25519.PublicKey:
		return &PublicKeyWithID{Key: k, KeyID: keyID}, nil
	case *rsa.PublicKey:
		return &PublicKeyWithID{Key: k, KeyID: keyID}, nil
	case *ecdsa.PublicKey:
		return &PublicKeyWithID{Key: k, KeyID: keyID}, nil
	default:
		return nil, dsrerrors.New(
			dsrerrors.KeyParseError,
			fmt.Sprintf(
				"The public key file contains a %T key but this verifier supports only "+
					"Ed25519, RSA, and ECDSA keys.",
				pub,
			),
			fmt.Sprintf("key type: %T", pub),
		)
	}
}

// parseED25519Base64Key parses a raw base64-encoded 32-byte Ed25519 public key.
// The file may contain comment lines (# ...) and blank lines; only non-comment,
// non-blank lines are treated as base64 data.
func parseED25519Base64Key(data []byte) (*PublicKeyWithID, *dsrerrors.VerificationError) {
	keyID := extractKeyID(data)

	var b64 strings.Builder
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		b64.WriteString(line)
	}

	raw, err := base64.StdEncoding.DecodeString(b64.String())
	if err != nil {
		raw, err = base64.URLEncoding.DecodeString(b64.String())
		if err != nil {
			return nil, dsrerrors.New(
				dsrerrors.KeyParseError,
				"The key file could not be decoded as a base64 Ed25519 public key. "+
					"Expected a base64-encoded 32-byte raw Ed25519 key or a PEM-encoded key.",
				fmt.Sprintf("base64 decode error: %s", err.Error()),
			)
		}
	}

	if len(raw) != ed25519.PublicKeySize {
		return nil, dsrerrors.New(
			dsrerrors.KeyParseError,
			fmt.Sprintf(
				"The decoded key is %d bytes but an Ed25519 public key must be exactly 32 bytes.",
				len(raw),
			),
			fmt.Sprintf("decoded length: %d, expected: 32", len(raw)),
		)
	}

	return &PublicKeyWithID{Key: ed25519.PublicKey(raw), KeyID: keyID}, nil
}

// extractKeyID scans the lines before the first PEM block (or all lines for
// base64 keys) for a comment of the form "# key_id: <value>" and returns the
// trimmed value. Returns an empty string if no such comment is found.
func extractKeyID(data []byte) string {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "-----BEGIN") {
			break
		}
		if strings.HasPrefix(line, "#") {
			rest := strings.TrimSpace(strings.TrimPrefix(line, "#"))
			if strings.HasPrefix(rest, "key_id:") {
				return strings.TrimSpace(strings.TrimPrefix(rest, "key_id:"))
			}
		}
	}
	return ""
}
