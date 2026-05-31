package bundle

import (
	"testing"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

func ts(offsetHours float64) time.Time {
	base := time.Date(2026, 2, 10, 0, 0, 0, 0, time.UTC)
	return base.Add(time.Duration(offsetHours * float64(time.Hour)))
}

func anomalies(n int, cat AnomalyCategory, zone string, startHour, stepHours float64) []Anomaly {
	out := make([]Anomaly, n)
	for i := range out {
		out[i] = Anomaly{
			Category:    cat,
			ReceiptID:   "rcpt-" + string(cat) + "-" + string(rune('a'+i)),
			ServiceZone: zone,
			OccurredAt:  ts(startHour + float64(i)*stepHours),
		}
	}
	return out
}

// ─────────────────────────────────────────────────────────────────────────────
// AnalyseClusterPatterns — threshold guard
// ─────────────────────────────────────────────────────────────────────────────

func TestAnalyseClusterPatterns_BelowThreshold(t *testing.T) {
	// 9 anomalies < MinAnomalyThreshold (10) → skipped, nominal
	input := anomalies(9, CategorySignatureMismatches, "zone-a", 0, 1)
	res := AnalyseClusterPatterns(input)

	if !res.Skipped {
		t.Errorf("expected Skipped=true for %d anomalies", len(input))
	}
	if res.PatternSignature != "nominal" {
		t.Errorf("expected nominal, got %q", res.PatternSignature)
	}
	if res.ZoneConcentration.Detected || res.TemporalClustering.Detected || res.CascadeDetected.Detected {
		t.Error("no test should fire below threshold")
	}
}

func TestAnalyseClusterPatterns_AtThreshold(t *testing.T) {
	// Exactly 10 anomalies, all in one zone — zone concentration should fire.
	input := anomalies(10, CategorySignatureMismatches, "payments-checkout", 0, 24)
	res := AnalyseClusterPatterns(input)
	if res.Skipped {
		t.Error("expected Skipped=false at exactly 10 anomalies")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// zone_concentration
// ─────────────────────────────────────────────────────────────────────────────

func TestZoneConcentration_Detected(t *testing.T) {
	// 47 anomalies in zone-a, 3 in zone-b, 1 in zone-c → strong concentration
	var input []Anomaly
	input = append(input, anomalies(47, CategorySignatureMismatches, "payments-checkout", 0, 1)...)
	input = append(input, anomalies(3, CategorySignatureMismatches, "auth-service", 0, 1)...)

	res := testZoneConcentration(input)

	if !res.Detected {
		t.Errorf("expected concentration to be detected (χ²=%.2f)", res.ChiSquared)
	}
	if res.DominantZone != "payments-checkout" {
		t.Errorf("expected dominant zone payments-checkout, got %q", res.DominantZone)
	}
	if res.PValueLT != "<0.001" {
		t.Errorf("expected p-value <0.001, got %q", res.PValueLT)
	}
	if res.NumZones != 2 {
		t.Errorf("expected 2 zones, got %d", res.NumZones)
	}
}

func TestZoneConcentration_NotDetected_Uniform(t *testing.T) {
	// 15 in each of 3 zones — uniform distribution, no detection expected
	var input []Anomaly
	for _, z := range []string{"zone-a", "zone-b", "zone-c"} {
		input = append(input, anomalies(15, CategorySignatureMismatches, z, 0, 1)...)
	}

	res := testZoneConcentration(input)

	if res.Detected {
		t.Errorf("unexpected concentration detected for uniform distribution (χ²=%.2f)", res.ChiSquared)
	}
}

func TestZoneConcentration_SingleZone_Detected(t *testing.T) {
	// Only one zone → trivial maximum concentration (100% in one zone → detected)
	input := anomalies(20, CategorySignatureMismatches, "only-zone", 0, 1)
	res := testZoneConcentration(input)
	if !res.Detected {
		t.Error("all anomalies in one zone should be detected as concentrated")
	}
	if res.DominantZone != "only-zone" {
		t.Errorf("expected dominant zone 'only-zone', got %q", res.DominantZone)
	}
	if res.DominantShare != 1.0 {
		t.Errorf("expected dominant share 1.0, got %f", res.DominantShare)
	}
}

func TestZoneConcentration_NoZoneInfo(t *testing.T) {
	// Anomalies with empty ServiceZone are ignored
	input := make([]Anomaly, 20)
	for i := range input {
		input[i] = Anomaly{Category: CategorySignatureMismatches, ReceiptID: "r" + string(rune('a'+i))}
	}
	res := testZoneConcentration(input)
	if res.Detected {
		t.Error("should not detect anything when all zones are empty")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// temporal_clustering
// ─────────────────────────────────────────────────────────────────────────────

func TestTemporalClustering_Detected(t *testing.T) {
	// 50 anomalies burst in ~25h at hour 1000; 1 background at hour 0.
	// duration = 1024.5h; λ = 51/1024.5 ≈ 0.050/h; λW = 0.050*72 ≈ 3.6
	// best_count = 50; multiplier ≈ 13.9 — well above the 10× threshold.
	var input []Anomaly
	// burst: 50 anomalies in 25 hours starting at hour 1000
	input = append(input, anomalies(50, CategorySignatureMismatches, "zone-a", 1000, 0.5)...)
	// background: 1 anomaly at hour 0 to establish bundle start
	input = append(input, Anomaly{
		Category:    CategorySignatureMismatches,
		ReceiptID:   "bg-0",
		ServiceZone: "zone-a",
		OccurredAt:  ts(0),
	})

	res := testTemporalClustering(input)

	if !res.Detected {
		t.Errorf("expected temporal clustering to be detected (multiplier=%.1f)", res.Multiplier)
	}
	if res.AnomaliesInWindow < 40 {
		t.Errorf("expected ≥40 anomalies in window, got %d", res.AnomaliesInWindow)
	}
	if res.Multiplier < TemporalMultiplierThreshold {
		t.Errorf("expected multiplier ≥%.0f, got %.1f", TemporalMultiplierThreshold, res.Multiplier)
	}
	if res.PValueLT != "<0.001" {
		t.Errorf("expected p-value <0.001, got %q", res.PValueLT)
	}
}

func TestTemporalClustering_NotDetected_Uniform(t *testing.T) {
	// 20 anomalies evenly spread over 720 hours — no burst
	input := anomalies(20, CategorySignatureMismatches, "zone-a", 0, 36)

	res := testTemporalClustering(input)

	if res.Detected {
		t.Errorf("unexpected temporal clustering detected (multiplier=%.1f)", res.Multiplier)
	}
}

func TestTemporalClustering_TooFewTimestamps(t *testing.T) {
	// Only 2 anomalies with timestamps — below minimum of 3
	input := []Anomaly{
		{Category: CategorySignatureMismatches, OccurredAt: ts(0)},
		{Category: CategorySignatureMismatches, OccurredAt: ts(10)},
	}
	res := testTemporalClustering(input)
	if res.Detected {
		t.Error("should not detect clustering with fewer than 3 timestamps")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// cascade_detected
// ─────────────────────────────────────────────────────────────────────────────

func TestCascade_Detected(t *testing.T) {
	// 4 broken_chain_refs and 3 timestamp_inversions all point at the same receipts
	shared := []string{"rcpt-001", "rcpt-002", "rcpt-003"}
	var input []Anomaly
	for _, id := range shared {
		input = append(input,
			Anomaly{Category: CategoryBrokenChainRefs, ReceiptID: id},
			Anomaly{Category: CategoryTimestampInversions, ReceiptID: id},
		)
	}
	// Add one extra broken_chain_ref with a different ID — still dominant overlap
	input = append(input, Anomaly{Category: CategoryBrokenChainRefs, ReceiptID: "rcpt-004"})

	res := testCascade(input)

	if !res.Detected {
		t.Error("expected cascade to be detected")
	}
	if len(res.OverlappingIDs) == 0 {
		t.Error("expected non-empty OverlappingIDs")
	}
}

func TestCascade_NotDetected_DisjointCategories(t *testing.T) {
	// sig mismatches and missing entries point at completely different receipts
	var input []Anomaly
	for i := 0; i < 10; i++ {
		input = append(input,
			Anomaly{Category: CategorySignatureMismatches, ReceiptID: "sig-" + string(rune('a'+i))},
			Anomaly{Category: CategoryMissingEntries, ReceiptID: "mis-" + string(rune('a'+i))},
		)
	}

	res := testCascade(input)

	if res.Detected {
		t.Errorf("unexpected cascade detected for disjoint category receipt sets")
	}
}

func TestCascade_SingleCategory(t *testing.T) {
	// Only one category — no pairs → no cascade possible
	input := anomalies(10, CategorySignatureMismatches, "zone-a", 0, 1)
	res := testCascade(input)
	if res.Detected {
		t.Error("should not detect cascade with a single category")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// pattern_signature
// ─────────────────────────────────────────────────────────────────────────────

func TestDerivePatternSignature(t *testing.T) {
	cases := []struct {
		zone, temporal, cascade bool
		want                    string
	}{
		// cascade=true → targeted deletion regardless of other tests
		{true, true, true, "consistent_with_targeted_deletion"},
		{true, false, true, "consistent_with_targeted_deletion"},
		{false, true, true, "consistent_with_targeted_deletion"},
		{false, false, true, "consistent_with_targeted_deletion"},
		// zone+temporal without cascade → mass rekey
		{true, true, false, "consistent_with_mass_rekey"},
		// temporal only → mass rekey
		{false, true, false, "consistent_with_mass_rekey"},
		// zone only → isolated corruption
		{true, false, false, "consistent_with_isolated_corruption"},
		// nothing → nominal
		{false, false, false, "nominal"},
	}

	for _, tc := range cases {
		got := derivePatternSignature(tc.zone, tc.temporal, tc.cascade)
		if got != tc.want {
			t.Errorf("derivePatternSignature(zone=%v, temporal=%v, cascade=%v) = %q, want %q",
				tc.zone, tc.temporal, tc.cascade, got, tc.want)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Determinism
// ─────────────────────────────────────────────────────────────────────────────

func TestAnalyseClusterPatterns_Deterministic(t *testing.T) {
	// Same input, called twice → identical output.
	var input []Anomaly
	input = append(input, anomalies(47, CategorySignatureMismatches, "payments-checkout", 240, 0.5)...)
	input = append(input, anomalies(3, CategorySignatureMismatches, "auth-service", 0, 1)...)
	input = append(input, anomalies(3, CategoryBrokenChainRefs, "payments-checkout", 240, 0.5)...)

	r1 := AnalyseClusterPatterns(input)
	r2 := AnalyseClusterPatterns(input)

	if r1.PatternSignature != r2.PatternSignature {
		t.Errorf("non-deterministic: %q vs %q", r1.PatternSignature, r2.PatternSignature)
	}
	if r1.ZoneConcentration.Detected != r2.ZoneConcentration.Detected {
		t.Error("zone_concentration non-deterministic")
	}
	if r1.TemporalClustering.Detected != r2.TemporalClustering.Detected {
		t.Error("temporal_clustering non-deterministic")
	}
	if r1.CascadeDetected.Detected != r2.CascadeDetected.Detected {
		t.Error("cascade_detected non-deterministic")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// End-to-end: targeted deletion scenario (matches marketing page demo)
// ─────────────────────────────────────────────────────────────────────────────

func TestAnalyseClusterPatterns_TargetedDeletion(t *testing.T) {
	// Mirrors the marketing demo: 50 anomalies in payments-checkout, burst
	// window Feb 14-17, broken_chain_refs and timestamp_inversions both
	// point at missing_entries receipts → cascade → targeted_deletion.
	const burstStart = float64(240) // hour 240 from base = Feb 20

	// 31 missing entries in payments-checkout over 72h
	missing := anomalies(31, CategoryMissingEntries, "payments-checkout", burstStart, 2.3)
	// 12 sig mismatches pointing at same receipts
	sigMis := make([]Anomaly, 12)
	for i := range sigMis {
		sigMis[i] = Anomaly{
			Category:    CategorySignatureMismatches,
			ReceiptID:   missing[i%len(missing)].ReceiptID, // overlap with missing
			ServiceZone: "payments-checkout",
			OccurredAt:  ts(burstStart + float64(i)*0.5),
		}
	}
	// 4 broken chain refs pointing at missing entry receipts
	broken := make([]Anomaly, 4)
	for i := range broken {
		broken[i] = Anomaly{
			Category:    CategoryBrokenChainRefs,
			ReceiptID:   missing[i].ReceiptID,
			ServiceZone: "payments-checkout",
			OccurredAt:  ts(burstStart + float64(i)),
		}
	}
	// 3 timestamp inversions pointing at missing entry receipts
	tsInv := make([]Anomaly, 3)
	for i := range tsInv {
		tsInv[i] = Anomaly{
			Category:    CategoryTimestampInversions,
			ReceiptID:   missing[i].ReceiptID,
			ServiceZone: "payments-checkout",
			OccurredAt:  ts(burstStart + float64(i)*0.3),
		}
	}

	var all []Anomaly
	all = append(all, missing...)
	all = append(all, sigMis...)
	all = append(all, broken...)
	all = append(all, tsInv...)

	res := AnalyseClusterPatterns(all)

	if res.PatternSignature != "consistent_with_targeted_deletion" {
		t.Errorf("expected consistent_with_targeted_deletion, got %q", res.PatternSignature)
	}
	if !res.ZoneConcentration.Detected {
		t.Error("expected zone_concentration to fire")
	}
	if !res.CascadeDetected.Detected {
		t.Error("expected cascade_detected to fire")
	}
	if res.ZoneConcentration.DominantZone != "payments-checkout" {
		t.Errorf("wrong dominant zone: %q", res.ZoneConcentration.DominantZone)
	}
}
