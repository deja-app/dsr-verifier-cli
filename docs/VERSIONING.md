# Versioning Policy

`dsr-verifier-cli` follows [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

---

## Current release

**v1.1.0** — released 2026-06-02

See the [changelog](#changelog) below for what changed in this release.

---

## Compatibility commitments

### Receipt format compatibility

**1.x verifies all DSR/1.0 receipts forever.**

Once a receipt passes verification under any `1.x` release, it will pass under all
future `1.x` releases — including receipts issued years earlier. An auditor reviewing
a receipt from 2026 using a `1.x` CLI released in 2030 will get the same result.

This is a hard commitment, not a best-effort goal. DSR/1.0.1 is a fixed specification;
the verification math does not change.

### Command-line interface

Within a major version, the following are stable:

- Command names (`verify`, `verify-bundle`, `info`)
- Flag names (`--key`, `--json`, `--no-color`, `--no-log`)
- Exit codes (0 verified, 1 failed, 2 parse error, 3 not found, 4 invalid key)
- JSON output field names and types

Additions (new commands, new optional flags, new JSON fields) are non-breaking and
may appear in minor releases.

### What constitutes a breaking change

Breaking changes require a major version increment:

- Removing or renaming a command
- Removing or renaming a flag
- Changing an exit code's meaning
- Removing a JSON output field
- Dropping support for a receipt format version previously verified
- Changing the canonical signed-payload or content-canonicalization rules in a way
  that would cause a previously-passing receipt to fail

---

## Support window

| Release stream | Support ends |
|---------------|-------------|
| 1.x | No earlier than 2031-01-01 (5 years from initial release) |
| 0.x | Already superseded by 1.0 — no active support |

Security fixes are backported to the supported major stream. Fixes that address a
false-negative verification result (i.e., a tampered receipt incorrectly passes)
are treated as critical and released promptly.

---

## Pre-release versions

Versions tagged `-alpha`, `-beta`, or `-rc` make no compatibility guarantees.
They are for internal testing only and should not be used in audit engagements.

---

## Receipt format versions

The CLI advertises which DSR receipt format versions it supports in the `--version`
output:

```
dsr-verifier-cli v1.1.0 (commit: <git-sha>)
DSR/1.0.1 · MIT License · https://github.com/deja-dev/dsr-verifier-cli
```

When a new DSR format version is released (e.g., DSR/2.0.0), support for it will
appear in a minor or major release of the CLI depending on whether the new format
is backward compatible with the previous specification.

Receipts that declare an unsupported format version produce exit code 2 and a clear
error message directing the auditor to update the CLI.

---

## Go toolchain compatibility

The CLI is built and tested against the pinned Go version listed in `go.mod` (currently
Go 1.22.3). The CI pipeline also tests against the latest stable Go release. Production
binaries are always built with the pinned version for reproducibility.

The minimum Go version required to build from source will not be increased within a
major release without a deprecation notice in the release notes.

---

## Changelog

### v1.1.0 (2026-07-08)

**cluster_analysis_v1 — anomaly pattern analysis**

- `verify-bundle` now runs `cluster_analysis_v1` after the four verification
  checks complete. When a bundle has ≥10 anomalies the module runs three
  statistical tests and emits a `pattern_signature` and `confidence_score`.
- **Zone concentration** — chi-squared test across service zones; fires when
  p < 0.001 (dominant zone holds a disproportionate share of anomalies).
- **Temporal clustering** — Poisson multiplier over a fixed 72-hour scan
  window; fires when the burst rate exceeds 10× the baseline.
- **Cascade detection** — Jaccard similarity between anomaly-category sets;
  fires when two or more categories share ≥50% of implicated receipt IDs.
- **Pattern signatures**: `consistent_with_targeted_deletion`,
  `consistent_with_mass_rekey`, `consistent_with_isolated_corruption`,
  or `nominal` (nothing detected or fewer than 10 anomalies).
- **Fisher's method** (`combinePValuesFisher`) combines p-values from the
  tests that ran using the chi-squared identity for even degrees of freedom,
  producing a `confidence_score` in [0, 0.999]. Partial p-values (when a
  test cannot run) are excluded rather than padded with conservative values.
- Human output adds a `confidence N.NN` annotation to the pattern line and
  a Fisher-combined confidence score line. JSON output adds a
  `cluster_analysis` object to the report (omitted when nil).
- Zero external dependencies: the chi-squared survival function is
  implemented exactly via the Poisson CDF identity using only `math.Exp`
  and `math.Log` — no gonum or other third-party packages.

**BYOK key-type support**

- RSA-PSS receipts are now verified using `crypto/rsa.VerifyPSS` with
  `PSSSaltLengthAuto`, accepting receipts signed by AWS KMS RSA_2048/RSA_4096
  keys in RSASSA_PSS mode.
- ECDSA receipts are now verified using `crypto/ecdsa.VerifyASN1`, accepting
  the DER-encoded signatures produced by AWS KMS ECC keys. Both P-256 and P-384
  curves are supported.
- Previously only Ed25519 keys were accepted; BYOK customers using RSA-PSS or
  ECDSA signing keys can now run offline verification without any server
  dependency.

**RV receipt canonical form (10-field)**

- The receipt canonical form for RV (Retention Verification) receipt types has
  been extended from 8 fields to 10 fields, matching the server-side
  `rv-receipt-canonical.ts` implementation.
- The `DSR/1.0` version string is now accepted in addition to `DSR/1.0.1` for
  RV-type receipts, covering receipts issued by earlier server builds.
- Receipts issued under the prior 8-field form continue to verify correctly
  (backward-compatible).

**V7.2-F1 — protocol test-vector pinning**

- A CI parity check pins the CLI canonical-form output against the server
  `rv-receipt-canonical.ts` test vectors, ensuring the two implementations
  stay in sync across releases.

**V7.1-F1 — zero-network empirical proof**

- An import-graph audit and functional offline verification test confirm that
  the CLI makes no network calls at any point during `verify` or `info`
  execution. The proof is reproducible in CI without network access.

**M-6.3-D — reproducible build proof**

- The release pipeline now records SHA-256 checksums of binaries across
  independent build runs and asserts bit-identical output, providing a
  verifiable reproducible-build guarantee for all shipped artifacts.

---

### v1.0.0 (2026-01-15)

Initial stable release.

- `verify` and `info` commands for DSR/1.0.1 receipts.
- Ed25519 signature verification (zero external dependencies).
- Human and JSON (`--json`) output modes.
- Persistent audit log at `~/.dsr-verifier/audit.log`.
- Exit codes: 0 verified, 1 failed, 2 parse error, 3 not found, 4 invalid key.
- Homebrew tap distribution for macOS (arm64, amd64) and Linux (arm64, amd64).
