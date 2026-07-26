# Offline Receipt Verification

The `dsr-verify verify` command verifies DSR receipts fully offline — zero network calls to Déjà or any external service.

## Evidence bundle format (DSR/1.0.4+)

Starting at DSR/1.0.4 the API emits receipts as a two-key evidence bundle:

```json
{
  "receipt": { ...receipt fields... },
  "signal_observation": {
    "source": "sentry",
    "source_event_id": "SENTRY-EVT-abc123",
    "observed_at": "2026-01-01T00:00:00.000Z",
    "error_type": "ValueError",
    "error_value": "out of bounds",
    "extracted_field": "service_name",
    "extraction_method": "direct",
    "service": "payments-api",
    "raw_payload_sha256": null
  }
}
```

The bundle is always emitted in this shape even when `signal_observation` is null (pre-1.0.4 receipts, or receipts where no qualifying signal observation was available).

### What the verifier checks for bundles

When a bundle is detected and `signal_observation` is non-null:

1. The verifier computes `sha256hex(JCS(signal_observation))` offline.
2. It compares the result against `signal_observation_hash` in the signed receipt canonical form.
3. A mismatch fails verification — the observation was tampered with after signing.

This lets auditors confirm the triggering signal (what Déjà saw that prompted attribution) without access to the original raw provider payload. The raw payload is excluded by construction — `raw_payload_sha256` carries a one-way reference only.

## Bare receipt format (pre-1.0.4)

Pre-1.0.4 receipts are bare JSON objects without a wrapper. The verifier accepts both formats and auto-detects which applies.

## Checks performed

| Check | Always | Bundle + obs | Description |
|---|---|---|---|
| Key authority | ✓ | ✓ | Public key matches the key ID claimed in the receipt |
| Signature | ✓ | ✓ | Ed25519/RSA-PSS/ECDSA signature over canonical bytes |
| Signal obs hash | — | ✓ | sha256hex(JCS(signal_observation)) matches signed hash |

## Usage

```sh
# Bare receipt (pre-1.0.4 or null signal_observation)
dsr-verify verify receipt.dsr --public-key vault.pub

# Evidence bundle (DSR/1.0.4+)
dsr-verify verify bundle.dsr --public-key vault.pub

# BYOK receipt
dsr-verify verify receipt.dsr --byok-key customer.pem

# JSON output (for scripting)
dsr-verify verify receipt.dsr --public-key vault.pub --json
```

## Exit codes

| Code | Meaning |
|---|---|
| 0 | All checks passed |
| 1 | One or more verification checks failed |
| 2 | Receipt/bundle file is malformed |
| 3 | File not found |
| 4 | Key file is not a valid public key |

## Version ladder

| Version | New canonical fields |
|---|---|
| DSR/1.0 | Base attribution receipt (R1) |
| DSR/1.0.1 | `is_synthetic` on R1 |
| DSR/1.0.2 | `actor` (bare numeric ID) on R1-L |
| DSR/1.0.3 | `incident_id` nullable on R1-N |
| DSR/1.0.4 | `actor` (github: prefix) on R1; `incident_id` on R1; `signal_observation_hash` on R1/R1-L/R1-N |

Pre-1.0.4 bare actors on R1-L (format `"86881100"` without prefix) remain valid — the canonical form stored the value as-is at signing time.
