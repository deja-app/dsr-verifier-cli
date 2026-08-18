.PHONY: test vet build verify-vector-parity generate-parity-vectors check-parity-drift

test:
	go test -race -count=1 -timeout=120s ./...

vet:
	go vet ./...

build:
	go build -trimpath -buildvcs=false ./cmd/dsr-verifier-cli

# verify-vector-parity — diff the vendored RV canonical vector against the
# authoritative copy in the wallow repo. Requires WALLOW_REPO to point at
# the root of the wallow repository checkout (default: ../wallow).
WALLOW_REPO ?= ../wallow

verify-vector-parity:
	@diff -q testdata/protocol/rv-canonical-vector.json \
	  $(WALLOW_REPO)/docs/dsr/rv-canonical-vector.json || \
	  (echo "ERROR: RV vector copies have diverged — sync required" && exit 1)
	@echo "vector-parity OK"

# generate-parity-vectors — run the TypeScript generator to (re)produce all
# cross-implementation parity fixtures.  The fixtures are committed to the repo
# so CI can verify them without a wallow checkout.
#
# Run this whenever the canonical form changes in either repo, commit the
# updated fixtures, and confirm that `go test ./internal/verify/` still passes.
#
# Requires: Node.js + tsx available in PATH; WALLOW_REPO pointing at wallow root.
generate-parity-vectors:
	@echo "Generating parity vectors (TypeScript issuer → Go verifier)..."
	cd $(WALLOW_REPO)/packages/api && \
	  npx tsx scripts/generate-parity-vectors.ts \
	    --out-dir $(CURDIR)/internal/verify/testdata/parity
	@echo "Done.  Run 'go test ./internal/verify/ -run TestParityMatrix' to verify."

# check-parity-drift — regenerate vectors in a temp dir and diff against
# the committed copies.  Any difference means the committed vectors are stale.
# Run in CI after any canonical-form change to enforce freshness.
check-parity-drift:
	@TMPDIR=$$(mktemp -d) && \
	  cd $(WALLOW_REPO)/packages/api && \
	  npx tsx scripts/generate-parity-vectors.ts --out-dir $$TMPDIR && \
	  diff -rq $$TMPDIR $(CURDIR)/internal/verify/testdata/parity && \
	  rm -rf $$TMPDIR && \
	  echo "parity-drift OK (no drift)" || \
	  (rm -rf $$TMPDIR; \
	   echo "ERROR: committed parity vectors are stale — run: make generate-parity-vectors WALLOW_REPO=$(WALLOW_REPO)"; \
	   exit 1)
