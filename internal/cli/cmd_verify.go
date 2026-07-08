package cli

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/deja-app/dsr-verifier-cli/internal/dsr"
	"github.com/deja-app/dsr-verifier-cli/internal/verify"
)

// verifyOpts holds parsed flags for the verify command.
type verifyOpts struct {
	keyFile     string // --public-key / --key: managed Ed25519 key (base64 or SPKI PEM)
	byokKeyFile string // --byok-key: BYOK customer key (RSA or ECDSA PEM)
	json        bool
	quiet       bool
	noLog       bool
	noColor     bool
}

// parseVerifyArgs scans args in any order. Returns the receipt path, parsed
// options, a help-requested boolean, and any parse error.
func parseVerifyArgs(args []string, stderr io.Writer) (receipt string, opts verifyOpts, help bool, err error) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--public-key", "--key", "-key":
			i++
			if i >= len(args) {
				fmt.Fprintln(stderr, "error: --public-key requires a file path")
				err = fmt.Errorf("--public-key requires a value")
				return
			}
			opts.keyFile = args[i]
		case "--byok-key", "-byok-key":
			i++
			if i >= len(args) {
				fmt.Fprintln(stderr, "error: --byok-key requires a file path")
				err = fmt.Errorf("--byok-key requires a value")
				return
			}
			opts.byokKeyFile = args[i]
		case "--json", "-json":
			opts.json = true
		case "--quiet", "-quiet", "-q":
			opts.quiet = true
		case "--no-log", "-no-log":
			opts.noLog = true
		case "--no-color", "-no-color":
			opts.noColor = true
		case "--help", "-help", "-h":
			help = true
			return
		default:
			if strings.HasPrefix(arg, "-") {
				fmt.Fprintf(stderr, "error: unknown flag for verify: %s\n", arg)
				err = fmt.Errorf("unknown flag: %s", arg)
				return
			}
			if receipt != "" {
				fmt.Fprintf(stderr, "error: unexpected argument: %s\n", arg)
				err = fmt.Errorf("unexpected argument: %s", arg)
				return
			}
			receipt = arg
		}
	}
	return
}

func runVerify(args []string, stdout, stderr io.Writer) int {
	receiptPath, opts, help, parseArgErr := parseVerifyArgs(args, stderr)
	if help {
		fmt.Fprint(stdout, verifyHelp)
		return exitSuccess
	}
	if parseArgErr != nil {
		return exitParseError
	}
	if receiptPath == "" {
		fmt.Fprintln(stderr, "error: verify requires a receipt file argument")
		fmt.Fprintln(stderr, "usage: dsr-verify verify <receipt.dsr> --public-key <pubkey>")
		return exitParseError
	}

	// Read receipt file.
	receiptData, err := os.ReadFile(receiptPath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintf(stderr, "error: receipt file not found: %s\n", receiptPath)
			return exitMissingFile
		}
		fmt.Fprintf(stderr, "error: cannot read receipt file %s: %v\n", receiptPath, err)
		return exitMissingFile
	}

	// Parse receipt.
	envelope, parseErr := dsr.Parse(receiptData)
	if parseErr != nil {
		fmt.Fprintf(stderr, "error: malformed receipt: %s\n", parseErr.HumanMessage)
		fmt.Fprintf(stderr, "detail: %s\n", parseErr.TechnicalDetail)
		return exitParseError
	}

	// Resolve the active key based on the receipt's algorithm.
	var activeKey *verify.PublicKeyWithID
	algo := envelope.SigAlgo()

	switch algo {
	case dsr.AlgoSHA256Legacy:
		// No key required; hash comparison only.

	case dsr.AlgoED25519V1:
		if opts.keyFile == "" {
			fmt.Fprintf(stderr, "error: receipt uses ed25519-v1 — provide the managed public key with --public-key\n")
			return exitKeyError
		}
		keyData, readErr := os.ReadFile(opts.keyFile)
		if readErr != nil {
			if os.IsNotExist(readErr) {
				fmt.Fprintf(stderr, "error: key file not found: %s\n", opts.keyFile)
				return exitMissingFile
			}
			fmt.Fprintf(stderr, "error: cannot read key file %s: %v\n", opts.keyFile, readErr)
			return exitMissingFile
		}
		parsed, keyErr := verify.ParsePublicKeyFile(keyData)
		if keyErr != nil {
			fmt.Fprintf(stderr, "error: invalid key file: %s\n", keyErr.HumanMessage)
			fmt.Fprintf(stderr, "detail: %s\n", keyErr.TechnicalDetail)
			return exitKeyError
		}
		activeKey = parsed

	case dsr.AlgoRSAPSSSHA256, dsr.AlgoECDSASHA256:
		if opts.byokKeyFile == "" {
			fmt.Fprintf(stderr, "error: receipt uses %s — provide the BYOK public key with --byok-key\n", algo)
			return exitKeyError
		}
		keyData, readErr := os.ReadFile(opts.byokKeyFile)
		if readErr != nil {
			if os.IsNotExist(readErr) {
				fmt.Fprintf(stderr, "error: BYOK key file not found: %s\n", opts.byokKeyFile)
				return exitMissingFile
			}
			fmt.Fprintf(stderr, "error: cannot read BYOK key file %s: %v\n", opts.byokKeyFile, readErr)
			return exitMissingFile
		}
		parsed, keyErr := verify.ParsePublicKeyFile(keyData)
		if keyErr != nil {
			fmt.Fprintf(stderr, "error: invalid BYOK key file: %s\n", keyErr.HumanMessage)
			fmt.Fprintf(stderr, "detail: %s\n", keyErr.TechnicalDetail)
			return exitKeyError
		}
		activeKey = parsed
	}

	// Run verification checks.
	start := time.Now()
	authResult := verify.KeyAuthority(envelope, activeKey)
	sigResult := verify.Signature(envelope, activeKey)
	durationMS := time.Since(start).Milliseconds()

	timestamp := envelope.Timestamp
	if envelope.IssuedAt != nil {
		timestamp = *envelope.IssuedAt
	}

	keyID := ""
	if envelope.SigningKeyID != nil {
		keyID = *envelope.SigningKeyID
	}

	results := &VerifyResults{
		ReceiptID:    envelope.ReceiptID,
		ReceiptType:  envelope.Type,
		VaultID:      envelope.VaultID,
		Timestamp:    timestamp,
		Algorithm:    algo,
		FormVersion:  envelope.FormVersion(),
		KeyAuthority: authResult,
		Sig:          sigResult,
		DurationMS:   durationMS,
	}
	_ = keyID

	exitCode := exitSuccess
	if !results.AllPassed() {
		exitCode = exitVerifyFailed
	}

	logResult := "verified"
	if exitCode != exitSuccess {
		logResult = "failed"
	}

	if !opts.noLog {
		results.LogFile = DefaultLogFile
		if lerr := WriteLogEntry(DefaultLogFile, "verify", receiptPath, logResult, durationMS); lerr != nil {
			fmt.Fprintf(stderr, "warning: audit log write failed: %v\n", lerr)
		}
	}

	if opts.quiet {
		return exitCode
	}

	if opts.json {
		if encErr := WriteJSON(stdout, results); encErr != nil {
			fmt.Fprintf(stderr, "error: JSON encode failed: %v\n", encErr)
			return exitParseError
		}
		return exitCode
	}

	p := NewPrinter(stdout, !opts.noColor)
	p.Header(receiptPath, opts.keyFile)
	PrintVerifyResults(p, results)
	return exitCode
}

const verifyHelp = `
Usage: dsr-verify verify <receipt.dsr> [flags]

Verify a DSR receipt's signature and key authority. All checks run offline
with zero network calls to Déjà or any external service.

Arguments:
  <receipt.dsr>        path to the .dsr receipt file to verify

Flags:
  --public-key <file>  path to the managed Ed25519 public key
                       (base64 raw 32 bytes, or SPKI PEM)
  --byok-key <file>    path to the BYOK customer public key (PEM, RSA or ECDSA)
                       required for rsa-pss-sha256 and ecdsa-sha256 receipts
  --json               machine-readable JSON output
  --quiet              minimal output; rely on exit code
  --no-log             disable the local audit log (./verifier.log by default)
  --no-color           disable ANSI color codes in output
  --help               this help

Algorithm selection:
  sha256-legacy        no key required
  ed25519-v1           --public-key required
  rsa-pss-sha256       --byok-key required
  ecdsa-sha256         --byok-key required

Exit codes:
  0   all checks passed
  1   one or more verification checks failed
  2   receipt file is malformed or cannot be parsed
  3   receipt or key file not found
  4   key file is not a valid public key
`
