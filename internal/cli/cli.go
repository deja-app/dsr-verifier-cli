// Package cli implements the dsr-verifier-cli command surface.
//
// Entry point: cli.Run(args, stdout, stderr) — returns an exit code.
// main.go calls os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr)).
//
// This indirection keeps every command testable without subprocess execution:
// tests call Run() with io.Writer buffers and check the return code and output.
package cli

import (
	"fmt"
	"io"
)

// Exit codes — standard Unix conventions.
const (
	exitSuccess      = 0
	exitVerifyFailed = 1 // one or more verification checks failed
	exitParseError   = 2 // receipt file is malformed or cannot be parsed
	exitMissingFile  = 3 // receipt or key file not found
	exitKeyError     = 4 // key file is not a valid ed25519 public key
)

// Run is the top-level entry point. args is os.Args[1:].
// Returns an exit code; the caller is responsible for os.Exit.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stdout, rootHelp)
		return exitSuccess
	}

	switch args[0] {
	case "verify":
		return runVerify(args[1:], stdout, stderr)
	case "verify-bundle":
		return runVerifyBundle(args[1:], stdout, stderr)
	case "info":
		return runInfo(args[1:], stdout, stderr)
	case "--version", "-version", "version":
		fmt.Fprintf(stdout, "dsr-verifier-cli v%s (commit: %s)\n", Version, BuildCommit)
		fmt.Fprintln(stdout, "DSR/1.0.2 · Apache-2.0 · https://github.com/deja-app/dsr-verifier-cli")
		fmt.Fprintln(stdout, "Offline · zero network calls")
		return exitSuccess
	case "--help", "-help", "-h", "help":
		fmt.Fprintln(stdout, rootHelp)
		return exitSuccess
	default:
		fmt.Fprintf(stderr, "unknown command: %q\n", args[0])
		fmt.Fprintln(stderr, "Run 'dsr-verifier-cli --help' for usage.")
		return exitParseError
	}
}

const rootHelp = `dsr-verifier-cli — offline DSR receipt verifier

Usage:
  dsr-verifier-cli verify        <receipt.dsr> [--public-key <file>] [--byok-key <file>]
  dsr-verifier-cli verify-bundle <bundle.dsr.bundle> --public-key <file>
  dsr-verifier-cli info          <receipt.dsr>
  dsr-verifier-cli --version
  dsr-verifier-cli --help

Key flags:
  --public-key <file>   Déjà managed key (PEM or base64 Ed25519; see keys/deja-managed-v1.pub)
  --byok-key <file>     Customer BYOK key (RSA-PSS or ECDSA PEM)
  sha256-legacy receipts require no key flag

Common flags:
  --json          machine-readable JSON output
  --quiet         exit code only (for scripting)
  --no-log        disable local audit log (./verifier.log)
  --no-color      disable ANSI color codes

Exit codes:
  0   all checks passed
  1   one or more verification checks failed
  2   parse or format error
  3   missing file (receipt or key)
  4   key error (invalid format)

Run 'dsr-verifier-cli <command> --help' for command-specific help.`
