package cli_test

// cli_test.go — CLI integration tests for the verify command.
//
// These tests exercise cli.Run end-to-end: temp files on disk, key files,
// and the full verify pipeline. They cover the four exit codes that matter
// for scripted use:
//
//   exit 0 — VERIFIED (all checks passed)
//   exit 1 — one or more verification checks failed
//   exit 3 — file not found
//   exit 4 — key error

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deja-app/dsr-verifier-cli/internal/cli"
	"github.com/deja-app/dsr-verifier-cli/internal/dsr"
)

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

func cliMakeEd25519Pair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	return pub, priv
}

// writeTempFile creates a temp file with content and returns its path.
func writeTempFile(t *testing.T, dir, name string, content []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("WriteFile %q: %v", path, err)
	}
	return path
}

// signedR1Receipt builds and returns a signed R1 DSR envelope as JSON bytes.
func signedR1Receipt(t *testing.T, id string, pub ed25519.PublicKey, priv ed25519.PrivateKey) []byte {
	t.Helper()
	keyID := "key_cli_test"
	algo := dsr.AlgoED25519V1
	e := &dsr.Envelope{
		DSRVersion:         "DSR/1.0.2",
		Type:               "R1",
		ReceiptID:          id,
		VaultID:            "vlt_cli_test",
		Timestamp:          "2026-08-18T12:00:00Z",
		Actor:              "author@example.com",
		Origin:             "github.com/test/repo",
		Repository:         ptrStr("test/repo"),
		PRNumber:           ptrInt64(99),
		CCSScore:           ptrStr("0.8750"),
		Confidence:         ptrStr("high"),
		Matched:            ptrStr("true"),
		ServiceZone:        ptrStr("payments"),
		SignatureAlgorithm: &algo,
		SigningKeyID:       &keyID,
	}
	canonical, err := dsr.CanonicalPayload(e)
	if err != nil {
		t.Fatalf("CanonicalPayload: %v", err)
	}
	sig := ed25519.Sign(priv, []byte(canonical))
	e.Signature = base64.StdEncoding.EncodeToString(sig)

	b, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("json.Marshal receipt: %v", err)
	}
	return b
}

// ed25519PubKeyFile returns the raw base64 key file bytes.
func ed25519PubKeyFile(pub ed25519.PublicKey, keyID string) []byte {
	b64 := base64.StdEncoding.EncodeToString([]byte(pub))
	if keyID != "" {
		return []byte(fmt.Sprintf("# key_id: %s\n%s\n", keyID, b64))
	}
	return []byte(b64 + "\n")
}

func ptrStr(s string) *string  { return &s }
func ptrInt64(n int64) *int64  { return &n }

// ─────────────────────────────────────────────────────────────────────────────
// Passing cases
// ─────────────────────────────────────────────────────────────────────────────

func TestRun_Verify_ValidReceipt_ExitsZero(t *testing.T) {
	dir := t.TempDir()
	pub, priv := cliMakeEd25519Pair(t)

	receiptPath := writeTempFile(t, dir, "receipt.dsr", signedR1Receipt(t, "rcpt_test_001", pub, priv))
	keyPath := writeTempFile(t, dir, "key.pub", ed25519PubKeyFile(pub, "key_cli_test"))

	var stdout, stderr bytes.Buffer
	code := cli.Run([]string{"verify", receiptPath, "--public-key", keyPath, "--no-log", "--no-color"}, &stdout, &stderr)
	if code != 0 {
		t.Errorf("expected exit 0, got %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "VERIFIED") {
		t.Errorf("expected VERIFIED in output\nstdout: %s", stdout.String())
	}
}

func TestRun_Verify_JSONOutput_ExitsZero(t *testing.T) {
	dir := t.TempDir()
	pub, priv := cliMakeEd25519Pair(t)

	receiptPath := writeTempFile(t, dir, "receipt.dsr", signedR1Receipt(t, "rcpt_json_001", pub, priv))
	keyPath := writeTempFile(t, dir, "key.pub", ed25519PubKeyFile(pub, "key_cli_test"))

	var stdout, stderr bytes.Buffer
	code := cli.Run([]string{"verify", receiptPath, "--public-key", keyPath, "--json", "--no-log"}, &stdout, &stderr)
	if code != 0 {
		t.Errorf("expected exit 0, got %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	var result map[string]interface{}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Errorf("JSON output is not valid JSON: %v\n%s", err, stdout.String())
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Failure cases
// ─────────────────────────────────────────────────────────────────────────────

func TestRun_Verify_TamperedSignature_ExitsOne(t *testing.T) {
	dir := t.TempDir()
	pub, priv := cliMakeEd25519Pair(t)

	receiptJSON := signedR1Receipt(t, "rcpt_tampered", pub, priv)

	// Corrupt the signature field in the JSON.
	var raw map[string]interface{}
	if err := json.Unmarshal(receiptJSON, &raw); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	raw["signature"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	tampered, _ := json.Marshal(raw)

	receiptPath := writeTempFile(t, dir, "receipt.dsr", tampered)
	keyPath := writeTempFile(t, dir, "key.pub", ed25519PubKeyFile(pub, "key_cli_test"))

	var stdout, stderr bytes.Buffer
	code := cli.Run([]string{"verify", receiptPath, "--public-key", keyPath, "--no-log", "--no-color"}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("tampered receipt should exit 1, got %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
}

func TestRun_Verify_WrongKey_ExitsOne(t *testing.T) {
	dir := t.TempDir()
	pub, priv := cliMakeEd25519Pair(t)
	wrongPub, _ := cliMakeEd25519Pair(t)

	receiptPath := writeTempFile(t, dir, "receipt.dsr", signedR1Receipt(t, "rcpt_wrongkey", pub, priv))
	keyPath := writeTempFile(t, dir, "key.pub", ed25519PubKeyFile(wrongPub, "key_cli_test"))

	var stdout, stderr bytes.Buffer
	code := cli.Run([]string{"verify", receiptPath, "--public-key", keyPath, "--no-log", "--no-color"}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("wrong key should exit 1, got %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// File-not-found cases
// ─────────────────────────────────────────────────────────────────────────────

func TestRun_Verify_MissingReceiptFile_ExitsThree(t *testing.T) {
	dir := t.TempDir()
	pub, _ := cliMakeEd25519Pair(t)
	keyPath := writeTempFile(t, dir, "key.pub", ed25519PubKeyFile(pub, "key_cli_test"))

	var stdout, stderr bytes.Buffer
	code := cli.Run([]string{"verify", "/nonexistent/path/receipt.dsr", "--public-key", keyPath, "--no-log"}, &stdout, &stderr)
	if code != 3 {
		t.Errorf("missing receipt file should exit 3, got %d", code)
	}
}

func TestRun_Verify_MissingKeyFile_ExitsThree(t *testing.T) {
	dir := t.TempDir()
	pub, priv := cliMakeEd25519Pair(t)
	receiptPath := writeTempFile(t, dir, "receipt.dsr", signedR1Receipt(t, "rcpt_test", pub, priv))

	var stdout, stderr bytes.Buffer
	code := cli.Run([]string{"verify", receiptPath, "--public-key", "/nonexistent/key.pub", "--no-log"}, &stdout, &stderr)
	if code != 3 {
		t.Errorf("missing key file should exit 3, got %d", code)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Key authority mismatch
// ─────────────────────────────────────────────────────────────────────────────

func TestRun_Verify_KeyAuthorityMismatch_ExitsOne(t *testing.T) {
	dir := t.TempDir()
	pub, priv := cliMakeEd25519Pair(t)

	// Receipt has signing_key_id = "key_cli_test", but we provide key with
	// a different key_id comment — authority check must fail.
	receiptPath := writeTempFile(t, dir, "receipt.dsr", signedR1Receipt(t, "rcpt_auth", pub, priv))
	keyPath := writeTempFile(t, dir, "key.pub", ed25519PubKeyFile(pub, "WRONG_KEY_ID"))

	var stdout, stderr bytes.Buffer
	code := cli.Run([]string{"verify", receiptPath, "--public-key", keyPath, "--no-log", "--no-color"}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("key authority mismatch should exit 1, got %d\nstdout: %s\nstderr: %s",
			code, stdout.String(), stderr.String())
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Version and help commands
// ─────────────────────────────────────────────────────────────────────────────

func TestRun_Version_PrintsVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := cli.Run([]string{"--version"}, &stdout, &stderr)
	if code != 0 {
		t.Errorf("--version should exit 0, got %d", code)
	}
	if !strings.Contains(stdout.String(), "dsr-verifier-cli") {
		t.Errorf("expected version string in output, got: %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "Offline") {
		t.Errorf("expected 'Offline' in version output (offline guarantee label), got: %s", stdout.String())
	}
}

func TestRun_Help_ExitsZero(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := cli.Run([]string{"--help"}, &stdout, &stderr)
	if code != 0 {
		t.Errorf("--help should exit 0, got %d", code)
	}
}

func TestRun_UnknownCommand_ExitsTwo(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := cli.Run([]string{"notacommand"}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("unknown command should exit 2, got %d", code)
	}
}
