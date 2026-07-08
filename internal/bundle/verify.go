package bundle

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"sort"
	"time"

	"github.com/deja-app/dsr-verifier-cli/internal/dsr"
	dsrerrors "github.com/deja-app/dsr-verifier-cli/internal/errors"
	"github.com/deja-app/dsr-verifier-cli/internal/verify"
)

// ─────────────────────────────────────────────────────────────────────────────
// Result types
// ─────────────────────────────────────────────────────────────────────────────

// BundleVerifyResult aggregates the results of all bundle-level checks.
type BundleVerifyResult struct {
	BundleID    string
	VaultID     string
	PeriodStart string
	PeriodEnd   string
	Frameworks  []string
	IssuerKeyID string

	ManifestSig    ManifestSigResult
	SequenceInteg  SeqIntegResult
	PerReceipt     PerReceiptResult
	CausalChain    CausalChainResult
	RVCoverage     RVCoverageResult
	ClusterAnalysis ClusterAnalysisResult

	DurationMS int64
	ReportFile string
}

// AllPassed reports whether all bundle-level checks passed.
func (r *BundleVerifyResult) AllPassed() bool {
	return r.ManifestSig.Valid &&
		r.SequenceInteg.Valid &&
		r.PerReceipt.Failed == 0 &&
		r.CausalChain.Valid
}

// Tampered returns the count of receipts with signature failures.
func (r *BundleVerifyResult) Tampered() int {
	count := 0
	for _, f := range r.PerReceipt.Failures {
		for _, e := range f.Errors {
			if e.Class == dsrerrors.SignatureInvalid {
				count++
				break
			}
		}
	}
	return count
}

// Missing returns the count of receipts that could not be parsed.
func (r *BundleVerifyResult) Missing() int {
	count := 0
	for _, f := range r.PerReceipt.Failures {
		for _, e := range f.Errors {
			if e.Class == dsrerrors.MalformedReceipt {
				count++
				break
			}
		}
	}
	return count
}

// ManifestSigResult is returned by VerifyManifestSignature.
type ManifestSigResult struct {
	Valid   bool
	KeyID   string
	Err     *dsrerrors.VerificationError
}

// SeqIntegResult is returned by VerifySequenceIntegrity.
type SeqIntegResult struct {
	Valid  bool
	MinSeq int
	MaxSeq int
	Count  int
	Gaps   []int
	Err    *dsrerrors.VerificationError
}

// PerReceiptResult aggregates per-receipt verification across the bundle.
type PerReceiptResult struct {
	Total    int
	Passed   int
	Failed   int
	ByType   map[string]*TypeResult
	Failures []ReceiptFailure
}

// TypeResult counts passed/failed within one receipt type.
type TypeResult struct {
	Total  int
	Passed int
	Failed int
}

// ReceiptFailure holds the failure details for one receipt.
type ReceiptFailure struct {
	Seq       int
	ReceiptID string
	Type      string
	Errors    []*dsrerrors.VerificationError
}

// CausalChainResult is returned by VerifyCausalChain.
type CausalChainResult struct {
	Valid        bool
	Total        int
	Resolved     int
	Unresolvable []string
	Err          *dsrerrors.VerificationError
}

// RVCoverageResult summarises the RV receipt coverage.
type RVCoverageResult struct {
	TotalRV     int
	DaysCovered int
	Streak      int
}

// ClusterAnalysis holds the cluster_analysis_v1 result for this bundle.
// Populated after all four verification checks have run.

// ─────────────────────────────────────────────────────────────────────────────
// VerifyBundle
// ─────────────────────────────────────────────────────────────────────────────

func VerifyBundle(b *Bundle, provided *verify.PublicKeyWithID) *BundleVerifyResult {
	res := &BundleVerifyResult{
		BundleID:    b.Manifest.BundleID,
		VaultID:     b.Manifest.VaultID,
		PeriodStart: b.Manifest.PeriodStart,
		PeriodEnd:   b.Manifest.PeriodEnd,
		Frameworks:  b.Manifest.Frameworks,
		IssuerKeyID: b.Manifest.IssuerKeyID,
	}

	res.ManifestSig = VerifyManifestSignature(b.Manifest, provided)
	res.SequenceInteg = VerifySequenceIntegrity(b.Manifest)
	res.PerReceipt = VerifyPerReceipt(b.Receipts, provided)
	res.CausalChain = VerifyCausalChain(b.Receipts)
	res.RVCoverage = AnalyseRVCoverage(b.Receipts)

	// cluster_analysis_v1: post-process the anomalies already detected above.
	anomalies := ExtractAnomalies(res, b.Receipts)
	res.ClusterAnalysis = AnalyseClusterPatterns(anomalies)

	return res
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Manifest signature
// ─────────────────────────────────────────────────────────────────────────────

// VerifyManifestSignature verifies the bundle manifest's signature using the
// provided public key. It supports the same three algorithms used for individual
// receipt verification: ed25519, RSA-PSS SHA-256, and ECDSA SHA-256. The key
// type is detected from the provided PublicKeyWithID — no algorithm field is
// declared in the manifest itself, so the key material drives dispatch.
func VerifyManifestSignature(m *Manifest, provided *verify.PublicKeyWithID) ManifestSigResult {
	res := ManifestSigResult{KeyID: m.IssuerKeyID}

	payload, err := CanonicalManifestPayload(m)
	if err != nil {
		res.Valid = false
		res.Err = dsrerrors.New(
			dsrerrors.SignatureInvalid,
			"The verifier could not construct the canonical manifest payload. "+
				"The manifest may have malformed fields.",
			fmt.Sprintf("CanonicalManifestPayload error: %s", err.Error()),
		)
		return res
	}

	var verified bool
	var algorithmLabel string

	switch pub := provided.Key.(type) {
	case ed25519.PublicKey:
		algorithmLabel = "ed25519"
		verified = ed25519.Verify(pub, payload, m.Signature)

	case *rsa.PublicKey:
		algorithmLabel = "rsa-pss-sha256"
		hashed := sha256.Sum256(payload)
		opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: crypto.SHA256}
		verified = rsa.VerifyPSS(pub, crypto.SHA256, hashed[:], m.Signature, opts) == nil

	case *ecdsa.PublicKey:
		algorithmLabel = "ecdsa-sha256"
		hashed := sha256.Sum256(payload)
		verified = ecdsa.VerifyASN1(pub, hashed[:], m.Signature)

	default:
		res.Valid = false
		res.Err = dsrerrors.New(
			dsrerrors.SignatureInvalid,
			fmt.Sprintf(
				"The provided public key type %T is not supported for bundle manifest verification. "+
					"Supported key types: ed25519, RSA, ECDSA.",
				provided.Key,
			),
			fmt.Sprintf("unsupported key type: %T", provided.Key),
		)
		return res
	}

	if !verified {
		res.Valid = false
		res.Err = dsrerrors.New(
			dsrerrors.SignatureInvalid,
			fmt.Sprintf(
				"The bundle manifest's %s signature does not verify against key %q. "+
					"This means either: (1) the bundle was not signed by this key, "+
					"(2) the manifest fields or receipt list were modified after signing, or "+
					"(3) the signature is corrupt. "+
					"Do not treat this bundle as evidence without resolving this failure.",
				algorithmLabel, m.IssuerKeyID,
			),
			fmt.Sprintf("%s verify returned false for manifest; key_id=%s", algorithmLabel, m.IssuerKeyID),
		)
		return res
	}

	res.Valid = true
	return res
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Sequence integrity
// ─────────────────────────────────────────────────────────────────────────────

func VerifySequenceIntegrity(m *Manifest) SeqIntegResult {
	if len(m.Entries) == 0 {
		return SeqIntegResult{Valid: true}
	}

	seqSet := make(map[int]bool, len(m.Entries))
	minSeq, maxSeq := m.Entries[0].Seq, m.Entries[0].Seq
	for _, e := range m.Entries {
		seqSet[e.Seq] = true
		if e.Seq < minSeq {
			minSeq = e.Seq
		}
		if e.Seq > maxSeq {
			maxSeq = e.Seq
		}
	}

	var gaps []int
	for s := minSeq; s <= maxSeq; s++ {
		if !seqSet[s] {
			gaps = append(gaps, s)
		}
	}

	res := SeqIntegResult{
		MinSeq: minSeq,
		MaxSeq: maxSeq,
		Count:  len(m.Entries),
		Gaps:   gaps,
	}

	if len(gaps) > 0 {
		res.Valid = false
		gapDisplay := gaps
		if len(gapDisplay) > 5 {
			gapDisplay = gapDisplay[:5]
		}
		res.Err = dsrerrors.New(
			dsrerrors.MalformedReceipt,
			fmt.Sprintf(
				"The bundle has %d missing sequence number(s) in the range %d–%d. "+
					"A complete bundle must include every receipt in its declared sequence range.",
				len(gaps), minSeq, maxSeq,
			),
			fmt.Sprintf("missing seq numbers (first 5): %v", gapDisplay),
		)
	} else {
		res.Valid = true
	}

	return res
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Per-receipt verification
// ─────────────────────────────────────────────────────────────────────────────

func VerifyPerReceipt(receipts []*ParsedReceipt, provided *verify.PublicKeyWithID) PerReceiptResult {
	res := PerReceiptResult{
		Total:  len(receipts),
		ByType: make(map[string]*TypeResult),
	}

	for _, pr := range receipts {
		typ := pr.Entry.Type
		if typ == "" && pr.Receipt != nil {
			typ = pr.Receipt.Type
		}
		if _, ok := res.ByType[typ]; !ok {
			res.ByType[typ] = &TypeResult{}
		}
		res.ByType[typ].Total++

		if pr.ParseErr != nil {
			res.ByType[typ].Failed++
			res.Failed++
			res.Failures = append(res.Failures, ReceiptFailure{
				Seq:       pr.Entry.Seq,
				ReceiptID: pr.Entry.ReceiptID,
				Type:      typ,
				Errors:    []*dsrerrors.VerificationError{pr.ParseErr},
			})
			continue
		}

		authRes := verify.KeyAuthority(pr.Receipt, provided)
		sigRes := verify.Signature(pr.Receipt, provided)

		var errs []*dsrerrors.VerificationError
		if authRes.Err != nil {
			errs = append(errs, authRes.Err)
		}
		if sigRes.Err != nil {
			errs = append(errs, sigRes.Err)
		}

		if len(errs) > 0 {
			res.ByType[typ].Failed++
			res.Failed++
			res.Failures = append(res.Failures, ReceiptFailure{
				Seq:       pr.Entry.Seq,
				ReceiptID: pr.Receipt.ReceiptID,
				Type:      typ,
				Errors:    errs,
			})
		} else {
			res.ByType[typ].Passed++
			res.Passed++
		}
	}

	return res
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Causal chain consistency
// ─────────────────────────────────────────────────────────────────────────────

func VerifyCausalChain(receipts []*ParsedReceipt) CausalChainResult {
	bundleIDs := make(map[string]bool, len(receipts))
	for _, pr := range receipts {
		if pr.Receipt != nil {
			bundleIDs[pr.Receipt.ReceiptID] = true
		}
	}

	res := CausalChainResult{Valid: true}

	for _, pr := range receipts {
		if pr.Receipt == nil {
			continue
		}
		// R2 receipts carry attribution_receipt_id pointing to their R1.
		if !dsr.IsResolutionType(pr.Receipt.Type) {
			continue
		}
		if pr.Receipt.AttributionReceiptID == nil || *pr.Receipt.AttributionReceiptID == "" {
			continue
		}

		res.Total++
		if bundleIDs[*pr.Receipt.AttributionReceiptID] {
			res.Resolved++
		} else {
			res.Unresolvable = append(res.Unresolvable, *pr.Receipt.AttributionReceiptID)
		}
	}

	return res
}

// ─────────────────────────────────────────────────────────────────────────────
// RV coverage analysis
// ─────────────────────────────────────────────────────────────────────────────

// AnalyseRVCoverage counts RV receipts and computes day coverage from Timestamp.
func AnalyseRVCoverage(receipts []*ParsedReceipt) RVCoverageResult {
	var res RVCoverageResult
	daySet := make(map[string]bool)

	for _, pr := range receipts {
		if pr.Receipt == nil || pr.Receipt.Type != dsr.TypeRV {
			continue
		}
		res.TotalRV++

		if t, err := time.Parse(time.RFC3339, pr.Receipt.Timestamp); err == nil {
			day := t.UTC().Format("2006-01-02")
			daySet[day] = true
		}
	}

	res.DaysCovered = len(daySet)

	if len(daySet) > 0 {
		days := make([]string, 0, len(daySet))
		for d := range daySet {
			days = append(days, d)
		}
		sort.Strings(days)
		streak, best := 1, 1
		for i := 1; i < len(days); i++ {
			t0, _ := time.Parse("2006-01-02", days[i-1])
			t1, _ := time.Parse("2006-01-02", days[i])
			if t1.Sub(t0) == 24*time.Hour {
				streak++
			} else {
				streak = 1
			}
			if streak > best {
				best = streak
			}
		}
		res.Streak = best
	}

	return res
}
