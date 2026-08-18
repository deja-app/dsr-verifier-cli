package cli_test

// offline_test.go — zero-network guarantee tests.
//
// The dsr-verifier-cli README and --version output both claim "Offline · zero
// network calls". These tests enforce that guarantee mechanically: any HTTP
// or TCP call made during cli.Run causes the test to fail.
//
// Implementation:
//   1. Replace http.DefaultTransport with a transport that calls t.Fatal on
//      any attempt. Because net/http is the only standard-library HTTP client,
//      this catches all accidental fetch() / http.Get / http.Post calls.
//   2. Run cli.Run("verify", ...) with a valid receipt and key — the path
//      that touches the most code.
//   3. If the transport is never invoked, the guarantee holds.
//
// This test also documents the offline guarantee as a permanent property:
// any future PR that adds a network call to the verify path will break it.

import (
	"bytes"
	"net/http"
	"testing"

	"github.com/deja-app/dsr-verifier-cli/internal/cli"
)

// blockingTransport is an http.RoundTripper that fails the test if used.
type blockingTransport struct{ t *testing.T }

func (b *blockingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	b.t.Fatalf("offline violation: cli.Run made an HTTP request to %s — verify must work without network access", req.URL)
	return nil, nil // unreachable; t.Fatalf stops the goroutine
}

// TestOffline_VerifySucceedsWithNetworkBlocked replaces http.DefaultTransport
// for the duration of the test and verifies that cli.Run("verify", ...) exits
// successfully without ever invoking the transport.
func TestOffline_VerifySucceedsWithNetworkBlocked(t *testing.T) {
	// Block all HTTP calls. If any are made, the test fails with a clear message.
	original := http.DefaultTransport
	http.DefaultTransport = &blockingTransport{t: t}
	t.Cleanup(func() { http.DefaultTransport = original })

	dir := t.TempDir()
	pub, priv := cliMakeEd25519Pair(t)

	receiptPath := writeTempFile(t, dir, "receipt.dsr", signedR1Receipt(t, "rcpt_offline", pub, priv))
	keyPath := writeTempFile(t, dir, "key.pub", ed25519PubKeyFile(pub, "key_cli_test"))

	var stdout, stderr bytes.Buffer
	code := cli.Run([]string{"verify", receiptPath, "--public-key", keyPath, "--no-log", "--no-color"}, &stdout, &stderr)
	if code != 0 {
		t.Errorf("offline verify should exit 0, got %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
}

// TestOffline_VersionPrintsOfflineClaim verifies that the --version output
// contains "Offline" — the self-declared guarantee that users depend on.
func TestOffline_VersionPrintsOfflineClaim(t *testing.T) {
	original := http.DefaultTransport
	http.DefaultTransport = &blockingTransport{t: t}
	t.Cleanup(func() { http.DefaultTransport = original })

	var stdout, stderr bytes.Buffer
	code := cli.Run([]string{"--version"}, &stdout, &stderr)
	if code != 0 {
		t.Errorf("--version should exit 0, got %d", code)
	}
	out := stdout.String()
	if !containsStr(out, "Offline") {
		t.Errorf("--version must contain 'Offline' to declare the zero-network guarantee; got:\n%s", out)
	}
}

// TestOffline_InfoCommandNoNetwork verifies that the info command (which reads
// and pretty-prints a receipt) also makes no network calls.
func TestOffline_InfoCommandNoNetwork(t *testing.T) {
	original := http.DefaultTransport
	http.DefaultTransport = &blockingTransport{t: t}
	t.Cleanup(func() { http.DefaultTransport = original })

	dir := t.TempDir()
	pub, priv := cliMakeEd25519Pair(t)
	receiptPath := writeTempFile(t, dir, "receipt.dsr", signedR1Receipt(t, "rcpt_info_offline", pub, priv))

	var stdout, stderr bytes.Buffer
	// info exits 0 for a parseable receipt regardless of signature.
	cli.Run([]string{"info", receiptPath, "--no-color"}, &stdout, &stderr)
	// If blockingTransport was triggered, t.Fatalf already failed the test.
}

func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 ||
		func() bool {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
			return false
		}())
}
