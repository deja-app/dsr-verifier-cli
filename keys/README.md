# Déjà Managed Signing Key

## Key: `deja-managed-v1`

File: `keys/deja-managed-v1.pub`  
Algorithm: Ed25519  
Format: Base64-encoded raw 32-byte public key  
Key ID: `deja-managed-v1`

## Trust path

Three independent ways to obtain and verify this key:

**1. This repository (git history)**  
The key is committed at `keys/deja-managed-v1.pub`. The commit is signed and appears in GitHub's commit graph. You can verify the key has not changed since initial publication by checking `git log --follow keys/deja-managed-v1.pub`.

**2. Well-known URL (stable endpoint)**  
```
https://deja.dev/.well-known/dsr-signing-key
```
Returns the same base64 public key. Independent of this repository.

**3. Rekor transparency log**  
The key is logged to the Sigstore Rekor public transparency log. Entry URL will be published here once logged. This provides a third-party, append-only record that the key existed at a specific point in time.

## Using the key

```bash
# Verify a receipt with the managed key
dsr-verifier verify receipt.dsr --public-key keys/deja-managed-v1.pub

# Or using the well-known URL directly (requires network)
curl -s https://deja.dev/.well-known/dsr-signing-key > managed.pub
dsr-verifier verify receipt.dsr --public-key managed.pub
```

## Key rotation

If Déjà ever rotates the managed signing key, the new key will be published under a new name (e.g. `deja-managed-v2`) and the old key will remain in this repository for verifying historical receipts. Rotation will be announced in the repository changelog.
