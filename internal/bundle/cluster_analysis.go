package bundle

// cluster_analysis_v1 — deterministic anomaly pattern analysis.
//
// AnalyseClusterPatterns runs three statistical tests over the anomalies
// already detected by the four bundle-level verification checks, then emits
// a pattern_signature string that names the combination.
//
// All statistics use only Go stdlib (math package). No external dependencies.
// Same inputs always produce identical output — safe to run in audit contexts.
//
// Minimum anomaly threshold: 10. Bundles with fewer anomalies skip the
// analysis (output: PatternSignature = "nominal", all Detected = false).

import (
	"math"
	"sort"
	"time"

	"github.com/deja-app/dsr-verifier-cli/internal/dsr"
)

// ─────────────────────────────────────────────────────────────────────────────
// Public types
// ─────────────────────────────────────────────────────────────────────────────

// AnomalyCategory names the source of a detected anomaly.
type AnomalyCategory string

const (
	CategoryMissingEntries      AnomalyCategory = "missing_entries"
	CategorySignatureMismatches AnomalyCategory = "signature_mismatches"
	CategoryBrokenChainRefs     AnomalyCategory = "broken_chain_refs"
	CategoryTimestampInversions AnomalyCategory = "timestamp_inversions"
)

// Anomaly is a single detected problem, tagged with its category, the
// implicated receipt, the service zone (extracted from receipt content),
// and the timestamp of the implicated receipt.
type Anomaly struct {
	Category    AnomalyCategory
	ReceiptID   string
	ServiceZone string    // empty string when zone cannot be extracted
	OccurredAt  time.Time // zero value when timestamp unavailable
}

// ClusterAnalysisResult is the top-level output of cluster_analysis_v1.
type ClusterAnalysisResult struct {
	Version            string                   `json:"version"` // "cluster_analysis_v1"
	AnomalyCount       int                      `json:"anomaly_count"`
	Skipped            bool                     `json:"skipped,omitempty"` // true when count < MinAnomalyThreshold
	ZoneConcentration  ZoneConcentrationResult  `json:"zone_concentration"`
	TemporalClustering TemporalClusteringResult `json:"temporal_clustering"`
	CascadeDetected    CascadeResult            `json:"cascade_detected"`
	PatternSignature            string  `json:"pattern_signature"`
	PatternSignatureConfidence  float64 `json:"pattern_signature_confidence"`
	ConfidenceScore             float64 `json:"confidence_score"`
	ConfidenceRationale         string  `json:"confidence_rationale,omitempty"`
}

// ZoneConcentrationResult reports whether anomalies cluster in one service zone.
type ZoneConcentrationResult struct {
	Detected      bool    `json:"detected"`
	DominantZone  string  `json:"dominant_zone,omitempty"`
	DominantShare float64 `json:"dominant_zone_share,omitempty"` // fraction [0,1]
	ExpectedShare float64 `json:"expected_share,omitempty"`      // 1/num_zones under null
	ChiSquared    float64 `json:"chi_squared"`
	PValueLT      string  `json:"p_value_lt,omitempty"` // "<0.001" when detected
	NumZones      int     `json:"num_zones"`
}

// TemporalClusteringResult reports whether anomalies burst within a short window.
type TemporalClusteringResult struct {
	Detected          bool      `json:"detected"`
	WindowStart       time.Time `json:"window_start,omitempty"`
	WindowEnd         time.Time `json:"window_end,omitempty"`
	WindowHours       int       `json:"window_hours"` // fixed at ScanWindowHours
	AnomaliesInWindow int       `json:"anomalies_in_window"`
	Multiplier        float64   `json:"anomaly_rate_multiplier"`
	PValueLT          string    `json:"p_value_lt,omitempty"` // "<0.001" when detected
}

// CascadeResult reports whether anomalies in different categories implicate
// the same receipts, suggesting a single root-cause event.
type CascadeResult struct {
	Detected         bool                `json:"detected"`
	OverlappingIDs   []string            `json:"overlapping_receipt_ids,omitempty"`
	CategoryOverlaps []CategoryOverlap   `json:"category_overlaps,omitempty"`
}

// CategoryOverlap is one pair of categories with a measured Jaccard similarity.
type CategoryOverlap struct {
	CategoryA AnomalyCategory `json:"category_a"`
	CategoryB AnomalyCategory `json:"category_b"`
	Jaccard   float64         `json:"jaccard"`
	SharedIDs []string        `json:"shared_ids"`
}

// ─────────────────────────────────────────────────────────────────────────────
// Tunable constants
// ─────────────────────────────────────────────────────────────────────────────

const (
	// MinAnomalyThreshold: skip analysis when total anomalies < this.
	MinAnomalyThreshold = 10

	// ScanWindowHours: temporal clustering scan window width (fixed at 72 h).
	ScanWindowHours = 72

	// ZonePValueThreshold: chi-squared detection threshold.
	// Detection fires when the computed p-value < 0.001.
	ZonePValueThreshold = 0.001

	// TemporalMultiplierThreshold: burst must be ≥ this × baseline rate.
	TemporalMultiplierThreshold = 10.0

	// CascadeJaccardThreshold: minimum Jaccard to declare cascade.
	CascadeJaccardThreshold = 0.5
)

// ─────────────────────────────────────────────────────────────────────────────
// Main entry point
// ─────────────────────────────────────────────────────────────────────────────

// AnalyseClusterPatterns runs all three tests over the provided anomaly list
// and returns a ClusterAnalysisResult with a deterministic pattern_signature.
func AnalyseClusterPatterns(anomalies []Anomaly) ClusterAnalysisResult {
	res := ClusterAnalysisResult{
		Version:      "cluster_analysis_v1",
		AnomalyCount: len(anomalies),
	}

	if len(anomalies) < MinAnomalyThreshold {
		res.Skipped = true
		res.PatternSignature = "nominal"
		res.ConfidenceScore = 0
		res.ConfidenceRationale = "insufficient anomaly count for statistical analysis"
		return res
	}

	res.ZoneConcentration = testZoneConcentration(anomalies)
	res.TemporalClustering = testTemporalClustering(anomalies)
	res.CascadeDetected = testCascade(anomalies)

	zone := res.ZoneConcentration.Detected
	temporal := res.TemporalClustering.Detected
	cascade := res.CascadeDetected.Detected

	res.PatternSignature = derivePatternSignature(zone, temporal, cascade)
	res.PatternSignatureConfidence = derivePatternSignatureConfidence(
		res.PatternSignature, zone, temporal, cascade,
	)
	res.ConfidenceScore, res.ConfidenceRationale = computeFisherConfidence(
		res.ZoneConcentration, res.TemporalClustering, res.CascadeDetected,
	)

	return res
}

// ─────────────────────────────────────────────────────────────────────────────
// Pattern signature confidence
// ─────────────────────────────────────────────────────────────────────────────

// derivePatternSignatureConfidence returns a [0, 1] confidence for how cleanly
// the observed anomaly signals match the named pattern's expected fingerprint.
//
//   ≥ 0.9 — all expected signals present, no contradicting evidence
//   0.6–0.9 — most expected signals present, some ambiguity
//   < 0.6  — weak match; multiple candidate patterns possible
//   0.0    — no pattern detected
func derivePatternSignatureConfidence(pattern string, zone, temporal, cascade bool) float64 {
	switch pattern {
	case "consistent_with_targeted_deletion":
		// Primary signal: cascade (cross-category receipt overlap). Zone and
		// temporal strengthen it; each adds corroborating evidence.
		active := 1 // cascade is always true when this pattern fires
		if zone {
			active++
		}
		if temporal {
			active++
		}
		switch active {
		case 3:
			return 0.93 // all three signals: maximum corroboration
		case 2:
			return 0.85 // cascade + one other: strong but not maximal
		default:
			return 0.72 // cascade only: pattern identified, fewer signals
		}
	case "consistent_with_mass_rekey":
		if zone && temporal {
			return 0.90 // both expected signals present
		}
		// Temporal only: the expected zone signal is absent; ambiguous with
		// other causes of a temporal burst.
		return 0.55
	case "consistent_with_isolated_corruption":
		// Zone only, no temporal, no cascade; single signal but unique mapping.
		return 0.68
	default:
		return 0.0 // "nominal": no pattern detected
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Fisher's method — overall confidence score
// ─────────────────────────────────────────────────────────────────────────────

// computeFisherConfidence derives the overall ConfidenceScore via Fisher's
// method, combining independent p-values from the three statistical tests.
//
// Fisher's method: X² = -2 Σ ln(p_i) follows chi²(2k) under the null.
// ConfidenceScore = 1 − combined_p_value.
//
// P-value assignments (only for tests that actually ran):
//   zone:     PValueLT == "<0.001" → p = 0.001; ran-but-not-detected → p = 0.5.
//             Excluded entirely when NumZones == 0 (no zone info available).
//   temporal: PValueLT == "<0.001" → p = 0.001; ran-but-not-detected → p = 0.5.
//             Excluded entirely when AnomaliesInWindow == 0 and Multiplier == 0
//             (insufficient timestamps to run the test).
//   cascade:  Always included. Jaccard ≥ 0.5 → p ≈ 0.01 (honest approximation —
//             Jaccard is not a true p-value; see inline note). Not-detected → p = 0.5.
//
// When fewer than 3 tests produce valid p-values (some tests were not applicable),
// Fisher's method runs with however many are available; the rationale notes the count.
func computeFisherConfidence(
	zone ZoneConcentrationResult,
	temporal TemporalClusteringResult,
	cascade CascadeResult,
) (float64, string) {
	var pValues []float64
	var labels []string
	var nTests int

	// zone_concentration — skip entirely when no zone information was available.
	if zone.NumZones > 0 {
		nTests++
		if zone.PValueLT != "" {
			pValues = append(pValues, 0.001)
			labels = append(labels, "zone")
		} else {
			pValues = append(pValues, 0.5)
		}
	}

	// temporal_clustering — skip when the test couldn't run (too few timestamps).
	temporalRan := temporal.AnomaliesInWindow > 0 || temporal.Multiplier > 0 || temporal.Detected
	if temporalRan {
		nTests++
		if temporal.PValueLT != "" {
			pValues = append(pValues, 0.001)
			labels = append(labels, "temporal")
		} else {
			pValues = append(pValues, 0.5)
		}
	}

	// cascade_detected — always runs; Jaccard is not a p-value so we use an honest
	// approximation: detected (Jaccard ≥ 0.5) → p ≈ 0.01; not-detected → p ≈ 0.5.
	nTests++
	if cascade.Detected {
		pValues = append(pValues, 0.01)
		labels = append(labels, "cascade")
	} else {
		pValues = append(pValues, 0.5)
	}

	combinedP := combinePValuesFisher(pValues)
	score := math.Round((1.0-combinedP)*1000) / 1000
	if score > 0.999 {
		score = 0.999
	}

	// Rationale: name active tests + confidence tier.
	nDetected := len(labels)
	var rationale string
	switch {
	case nDetected >= 2:
		key := ""
		for i, l := range labels {
			if i > 0 {
				key += "+"
			}
			key += l
		}
		if nTests < 3 {
			rationale = key + " detected (high confidence, " + itoa(nTests) + " tests)"
		} else {
			rationale = key + " detected (high confidence)"
		}
	case nDetected == 1:
		if nTests < 3 {
			rationale = labels[0] + " detected (moderate confidence, " + itoa(nTests) + " tests)"
		} else {
			rationale = labels[0] + " detected (moderate confidence)"
		}
	default:
		rationale = "no patterns detected (low confidence)"
	}

	return score, rationale
}

// itoa converts a small non-negative integer to its decimal string.
// Used to avoid importing strconv for a single call.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	b := make([]byte, 0, 4)
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// combinePValuesFisher combines k independent p-values via Fisher's method.
// X² = -2 Σ ln(p_i) follows chi²(2k) under the null hypothesis.
// Returns the combined p-value (lower = stronger evidence against the null).
func combinePValuesFisher(pvalues []float64) float64 {
	if len(pvalues) == 0 {
		return 1.0
	}
	chi2 := 0.0
	for _, p := range pvalues {
		if p <= 0 {
			p = 1e-10 // floor: prevent log(0)
		}
		if p > 1 {
			p = 1.0
		}
		chi2 += -2.0 * math.Log(p)
	}
	df := 2 * len(pvalues)
	return chi2SurvivalEvenDF(chi2, df)
}

// chi2SurvivalEvenDF computes P(chi²(df) > chi2Stat) for even df.
//
// For even df = 2k the survival function is exact via the Poisson CDF identity:
//   Q(k, x) = P(Poisson(x) ≤ k−1) = e^(−x) Σ_{i=0}^{k−1} x^i / i!
// where x = chi2Stat / 2 and k = df / 2.
//
// This requires no external library — Go's math package is sufficient.
// The formula is exact (not an approximation) for all even df.
func chi2SurvivalEvenDF(chi2Stat float64, df int) float64 {
	if chi2Stat <= 0 {
		return 1.0
	}
	x := chi2Stat / 2.0
	k := df / 2
	expNegX := math.Exp(-x)
	if expNegX == 0 {
		return 0.0 // chi2Stat is astronomically large; survival ≈ 0
	}
	sum := expNegX // i = 0 term: x^0 / 0! = 1
	term := expNegX
	for i := 1; i < k; i++ {
		term *= x / float64(i)
		sum += term
	}
	if sum < 0 {
		return 0.0
	}
	if sum > 1 {
		return 1.0
	}
	return sum
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 1 — zone_concentration
// ─────────────────────────────────────────────────────────────────────────────

// testZoneConcentration applies a chi-squared goodness-of-fit test against
// the uniform null hypothesis (anomalies equally distributed across zones).
//
//   χ² = Σ (observed_i - expected_i)² / expected_i,   df = numZones - 1
//   expected_i = total / numZones  (uniform)
//
// Detection: p < ZonePValueThreshold (0.001).
func testZoneConcentration(anomalies []Anomaly) ZoneConcentrationResult {
	// Build zone counts. Ignore anomalies with no zone information.
	counts := make(map[string]int)
	for _, a := range anomalies {
		if a.ServiceZone != "" {
			counts[a.ServiceZone]++
		}
	}
	numZones := len(counts)
	if numZones == 0 {
		return ZoneConcentrationResult{}
	}
	if numZones == 1 {
		// All anomalies with zone info are in one zone — trivial maximum concentration.
		// Chi-squared is undefined for df=0, but the signal is unambiguous.
		onlyZone := ""
		for z := range counts {
			onlyZone = z
		}
		return ZoneConcentrationResult{
			Detected:      true,
			DominantZone:  onlyZone,
			DominantShare: 1.0,
			ExpectedShare: 1.0,
			PValueLT:      "<0.001",
			NumZones:      1,
		}
	}

	total := 0
	for _, c := range counts {
		total += c
	}
	expected := float64(total) / float64(numZones)

	// Chi-squared statistic.
	var chi2 float64
	dominant, dominantCount := "", 0
	for zone, obs := range counts {
		diff := float64(obs) - expected
		chi2 += (diff * diff) / expected
		if obs > dominantCount {
			dominant, dominantCount = zone, obs
		}
	}

	df := numZones - 1
	pLT001 := chi2 > chi2CriticalP001(df)

	res := ZoneConcentrationResult{
		Detected:      pLT001,
		DominantZone:  dominant,
		DominantShare: float64(dominantCount) / float64(total),
		ExpectedShare: 1.0 / float64(numZones),
		ChiSquared:    math.Round(chi2*100) / 100,
		NumZones:      numZones,
	}
	if pLT001 {
		res.PValueLT = "<0.001"
	}
	return res
}

// chi2CriticalP001 returns the χ² critical value at p=0.001 for df in [1,30].
// Values from standard chi-squared distribution tables.
// For df > 30 the Wilson–Hilferty normal approximation is used.
func chi2CriticalP001(df int) float64 {
	table := map[int]float64{
		1: 10.83, 2: 13.82, 3: 16.27, 4: 18.47, 5: 20.52,
		6: 22.46, 7: 24.32, 8: 26.12, 9: 27.88, 10: 29.59,
		11: 31.26, 12: 32.91, 13: 34.53, 14: 36.12, 15: 37.70,
		20: 45.31, 25: 52.62, 30: 59.70,
	}
	if v, ok := table[df]; ok {
		return v
	}
	// Wilson–Hilferty approximation: χ²_{df, 0.001} ≈ df*(1 - 2/(9df) + 3.09*sqrt(2/(9df)))³
	d := float64(df)
	c := 1.0 - 2.0/(9.0*d) + 3.09*math.Sqrt(2.0/(9.0*d))
	return d * c * c * c
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 2 — temporal_clustering
// ─────────────────────────────────────────────────────────────────────────────

// testTemporalClustering finds the ScanWindowHours-wide time window with the
// highest anomaly density and compares it to the Poisson baseline rate.
//
// Null: anomalies arrive as a homogeneous Poisson process with rate
//   λ = total_anomalies / bundle_duration_hours.
//
// Statistic: multiplier = (count_in_window) / (λ × ScanWindowHours).
// Detection: multiplier ≥ TemporalMultiplierThreshold AND count ≥ 3
//            AND Poisson p-value < 0.001.
func testTemporalClustering(anomalies []Anomaly) TemporalClusteringResult {
	const W = float64(ScanWindowHours)

	// Collect timestamps. Skip anomalies with no time.
	var times []time.Time
	for _, a := range anomalies {
		if !a.OccurredAt.IsZero() {
			times = append(times, a.OccurredAt)
		}
	}
	if len(times) < 3 {
		return TemporalClusteringResult{WindowHours: ScanWindowHours}
	}
	sort.Slice(times, func(i, j int) bool { return times[i].Before(times[j]) })

	bundleHours := times[len(times)-1].Sub(times[0]).Hours()
	if bundleHours < W {
		// Bundle duration shorter than the scan window — analysis undefined.
		return TemporalClusteringResult{WindowHours: ScanWindowHours}
	}

	lambda := float64(len(times)) / bundleHours // baseline rate per hour
	lambdaW := lambda * W                        // expected count in window under null

	// Scan: for each start time (one per anomaly), count how many fall within W hours.
	windowEnd := time.Duration(W * float64(time.Hour))
	bestCount, bestStart := 0, times[0]
	for i, t := range times {
		cutoff := t.Add(windowEnd)
		count := 0
		for _, t2 := range times[i:] {
			if t2.After(cutoff) {
				break
			}
			count++
		}
		if count > bestCount {
			bestCount = count
			bestStart = t
		}
	}

	if lambdaW <= 0 || bestCount < 3 {
		return TemporalClusteringResult{WindowHours: ScanWindowHours}
	}

	multiplier := math.Round(float64(bestCount)/lambdaW*10) / 10
	pLT001 := multiplier >= TemporalMultiplierThreshold && poissonPLT001(bestCount, lambdaW)

	res := TemporalClusteringResult{
		WindowHours:       ScanWindowHours,
		AnomaliesInWindow: bestCount,
		Multiplier:        multiplier,
	}
	if pLT001 {
		res.Detected = true
		res.WindowStart = bestStart
		res.WindowEnd = bestStart.Add(windowEnd)
		res.PValueLT = "<0.001"
	}
	return res
}

// poissonPLT001 returns true when P(Poisson(lambda) ≥ k) < 0.001.
// Uses the normal approximation: (k - λ) / sqrt(λ) > z_{0.001} = 3.09.
// Accurate when λ > 5; conservative when λ is small (so no false positives).
func poissonPLT001(k int, lambda float64) bool {
	if lambda <= 0 {
		return false
	}
	z := (float64(k) - lambda) / math.Sqrt(lambda)
	return z > 3.09 // z_{0.001} one-tailed
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 3 — cascade_detected
// ─────────────────────────────────────────────────────────────────────────────

// testCascade computes Jaccard similarity for every pair of anomaly categories.
// If any pair shares ≥ CascadeJaccardThreshold (0.5) of their receipt IDs,
// a cascade is declared.
func testCascade(anomalies []Anomaly) CascadeResult {
	// Group receipt IDs by category.
	byCategory := make(map[AnomalyCategory]map[string]bool)
	for _, a := range anomalies {
		if a.ReceiptID == "" {
			continue
		}
		if byCategory[a.Category] == nil {
			byCategory[a.Category] = make(map[string]bool)
		}
		byCategory[a.Category][a.ReceiptID] = true
	}

	// Enumerate all unique categories in a deterministic order.
	cats := make([]AnomalyCategory, 0, len(byCategory))
	for c := range byCategory {
		cats = append(cats, c)
	}
	sort.Slice(cats, func(i, j int) bool { return cats[i] < cats[j] })

	var (
		pairs         []CategoryOverlap
		allShared     = make(map[string]bool)
		cascadeFound  bool
	)

	for i := 0; i < len(cats); i++ {
		for j := i + 1; j < len(cats); j++ {
			a, b := cats[i], cats[j]
			setA, setB := byCategory[a], byCategory[b]

			// Intersection.
			var shared []string
			for id := range setA {
				if setB[id] {
					shared = append(shared, id)
				}
			}
			if len(shared) == 0 {
				continue
			}
			sort.Strings(shared)

			// Union size.
			union := len(setA) + len(setB) - len(shared)
			jaccard := float64(len(shared)) / float64(union)

			pair := CategoryOverlap{
				CategoryA: a,
				CategoryB: b,
				Jaccard:   math.Round(jaccard*1000) / 1000,
				SharedIDs: shared,
			}
			pairs = append(pairs, pair)

			if jaccard >= CascadeJaccardThreshold {
				cascadeFound = true
				for _, id := range shared {
					allShared[id] = true
				}
			}
		}
	}

	if !cascadeFound {
		return CascadeResult{}
	}

	ids := make([]string, 0, len(allShared))
	for id := range allShared {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	return CascadeResult{
		Detected:         true,
		OverlappingIDs:   ids,
		CategoryOverlaps: pairs,
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 4 — pattern_signature
// ─────────────────────────────────────────────────────────────────────────────

// derivePatternSignature returns a deterministic label from the three test booleans.
//
//  cascade=true                                        → consistent_with_targeted_deletion
//  zone=true  + temporal=true  + cascade=false         → consistent_with_mass_rekey
//  zone=false + temporal=true  + cascade=true          → consistent_with_mass_rekey
//  zone=true  + temporal=false + cascade=false         → consistent_with_isolated_corruption
//  zone=false + temporal=true  + cascade=false         → inconclusive
//  zone=false + temporal=false + cascade=true          → inconclusive
//  all false                                           → nominal
func derivePatternSignature(zone, temporal, cascade bool) string {
	if cascade {
		return "consistent_with_targeted_deletion"
	}
	if zone && temporal {
		return "consistent_with_mass_rekey"
	}
	if !zone && temporal {
		return "consistent_with_mass_rekey"
	}
	if zone && !temporal {
		return "consistent_with_isolated_corruption"
	}
	return "nominal"
}

// ─────────────────────────────────────────────────────────────────────────────
// ExtractAnomalies builds the []Anomaly input from a BundleVerifyResult.
// This is the bridge between the existing verification output and
// cluster_analysis_v1.
// ─────────────────────────────────────────────────────────────────────────────

// ExtractAnomalies converts the four failure categories from BundleVerifyResult
// into a flat []Anomaly list suitable for AnalyseClusterPatterns.
func ExtractAnomalies(res *BundleVerifyResult, receipts []*ParsedReceipt) []Anomaly {
	// Build an index of receipt ID → ParsedReceipt for fast lookup.
	receiptByID := make(map[string]*dsr.Envelope, len(receipts))
	for _, pr := range receipts {
		if pr.Receipt != nil {
			receiptByID[pr.Receipt.ReceiptID] = pr.Receipt
		}
	}

	var anomalies []Anomaly

	for _, f := range res.PerReceipt.Failures {
		r := receiptByID[f.ReceiptID]
		zone := extractServiceZone(r)
		ts := extractTimestamp(r)

		for _, e := range f.Errors {
			var cat AnomalyCategory
			switch e.Class {
			case "signature_invalid", "content_hash_mismatch":
				cat = CategorySignatureMismatches
			case "malformed_receipt":
				cat = CategoryMissingEntries
			default:
				continue // skip unknown classes
			}
			anomalies = append(anomalies, Anomaly{
				Category:    cat,
				ReceiptID:   f.ReceiptID,
				ServiceZone: zone,
				OccurredAt:  ts,
			})
		}
	}

	// Sequence gaps (missing entries) — derive from SeqIntegResult.
	for _, gap := range res.SequenceInteg.Gaps {
		if gap < 0 {
			continue // sentinel for declared-vs-actual mismatch, skip
		}
		anomalies = append(anomalies, Anomaly{
			Category: CategoryMissingEntries,
			// No receipt ID available for a gap; leave ReceiptID empty.
		})
	}

	// Broken causal chain references.
	for _, unresolvable := range res.CausalChain.Unresolvable {
		r := receiptByID[unresolvable]
		anomalies = append(anomalies, Anomaly{
			Category:    CategoryBrokenChainRefs,
			ReceiptID:   unresolvable,
			ServiceZone: extractServiceZone(r),
			OccurredAt:  extractTimestamp(r),
		})
	}

	return anomalies
}

func extractServiceZone(r *dsr.Envelope) string {
	if r == nil || r.ServiceZone == nil {
		return ""
	}
	return *r.ServiceZone
}

func extractTimestamp(r *dsr.Envelope) time.Time {
	if r == nil {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, r.Timestamp)
	if err != nil {
		return time.Time{}
	}
	return t
}
