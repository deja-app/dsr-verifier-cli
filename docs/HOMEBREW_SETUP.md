# Homebrew tap setup (deja-app)

Per the CLI verifier spec, macOS auditors install via Homebrew. This uses a **second repository** alongside the CLI.

| Repo | Homebrew name | Install command |
|------|----------------|-----------------|
| [deja-app/homebrew-tap](https://github.com/deja-app/homebrew-tap) | `deja-app/tap` | `brew install deja-app/tap/dsr-verifier-cli` |
| [deja-app/dsr-verifier-cli](https://github.com/deja-app/dsr-verifier-cli) | — | source + GitHub Releases |

---

## Step 1 — Create `homebrew-tap` on GitHub

1. GitHub → **deja-app** org (or your user) → **New repository**
2. Name: **`homebrew-tap`** (exact name — Homebrew maps `deja-app/homebrew-tap` → `deja-app/tap`)
3. Public, empty, no README required

## Step 2 — Push the tap contents

From the sibling folder in this monorepo checkout (or copy from `homebrew/` templates):

```bash
cd /path/to/homebrew-tap
git init
git add Formula .github README.md
git commit -m "feat: add dsr-verifier-cli formula and update workflow"
git remote add origin git@github.com:deja-app/homebrew-tap.git
git push -u origin main
```

Until the first CLI release, SHA-256 placeholders stay as `REPLACE_WITH_*`; the first release dispatch fills them in.

## Step 3 — `HOMEBREW_TAP_TOKEN` on `dsr-verifier-cli`

Create a GitHub **Personal Access Token**:

- **Classic:** scope **`repo`** (or limit to `homebrew-tap` if using a machine user)
- **Fine-grained:** repository access **only** `deja-app/homebrew-tap`, permissions **Contents** (Read and write), **Metadata** (Read), **Actions** (Read and write)

Add to [dsr-verifier-cli → Settings → Secrets → Actions](https://github.com/deja-app/dsr-verifier-cli/settings/secrets/actions):

- Name: `HOMEBREW_TAP_TOKEN`
- Value: `ghp_...` or `github_pat_...`

## Step 4 — First release

After `GPG_SIGNING_KEY` / `GPG_PASSPHRASE` are set:

```bash
git tag -a v1.0.0 -m "dsr-verifier-cli v1.0.0"
git push origin v1.0.0
```

Release workflow will:

1. Publish binaries on `deja-app/dsr-verifier-cli` Releases  
2. POST `repository_dispatch` to `deja-app/homebrew-tap`  
3. Tap workflow commits updated checksums  

## Step 5 — Verify install

```bash
brew install deja-app/tap/dsr-verifier-cli
dsr-verifier-cli --version
```

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| Dispatch 404 | Repo must be `deja-app/homebrew-tap` |
| Dispatch 401 | Regenerate `HOMEBREW_TAP_TOKEN` |
| `brew install` 404 | No release yet, or formula SHA placeholders not updated — check tap repo commits |
| Wrong binary URL | Formula must use `github.com/deja-app/dsr-verifier-cli/releases/...` |
