package cli_test

// output_bundle_test.go — rendering tests for PrintBundleResults and
// WriteBundleJSONReport with cluster analysis data.

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/deja-app/dsr-verifier-cli/internal/bundle"
	"github.com/deja-app/dsr-verifier-cli/internal/cli"
)

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

func assertContains(t *testing.T, s, sub string) {
	t.Helper()
	if !strings.Contains(s, sub) {
		t.Errorf("expected output to contain %q\ngot:\n%s", sub, s)
	}
}

func assertNotContains(t *testing.T, s, sub string) {
	t.Helper()
	if strings.Contains(s, sub) {
		t.Errorf("expected output NOT to contain %q\ngot:\n%s", sub, s)
	}
}

func minimalBundleVerifyResult() *bundle.BundleVerifyResult {
	return &bundle.BundleVerifyResult{
		BundleID:    "bundle_test_001",
		VaultID:     "vlt_test",
		PeriodStart: "2026-01-01",
		PeriodEnd:   "2026-01-31",
		IssuerKeyID: "key_test",
		ManifestSig: bundle.ManifestSigResult{Valid: true},
		SequenceInteg: bundle.SeqIntegResult{
			Valid:  true,
			MinSeq: 1,
			MaxSeq: 42,
		},
		PerReceipt: bundle.PerReceiptResult{
			Total:  42,
			Passed: 42,
			Failed: 0,
			ByType: map[string]*bundle.TypeResult{
				"R1": {Total: 42, Passed: 42},
			},
		},
		CausalChain: bundle.CausalChainResult{Valid: true},
		DurationMS:  123,
	}
}

func clusterResultAllDetected() *bundle.ClusterAnalysisResult {
	window := time.Date(2026, 2, 14, 0, 0, 0, 0, time.UTC)
	return &bundle.ClusterAnalysisResult{
		Version:                    "cluster_analysis_v1",
		AnomalyCount:               42,
		Skipped:                    false,
		PatternSignature:           "consistent_with_targeted_deletion",
		PatternSignatureConfidence: 0.93,
		ConfidenceScore:            0.999,
		ConfidenceRationale:        "zone+temporal+cascade detected (high confidence)",
		ZoneConcentration: bundle.ZoneConcentrationResult{
			Detected:      true,
			DominantZone:  "auth-service",
			DominantShare: 0.72,
			PValueLT:      "<0.001",
			ChiSquared:    45.12,
			NumZones:      3,
		},
		TemporalClustering: bundle.TemporalClusteringResult{
			Detected:          true,
			WindowStart:       window,
			WindowEnd:         window.Add(72 * time.Hour),
			WindowHours:       72,
			AnomaliesInWindow: 38,
			Multiplier:        18.3,
			PValueLT:          "<0.001",
		},
		CascadeDetected: bundle.CascadeResult{
			Detected:       true,
			OverlappingIDs: []string{"rcpt-001", "rcpt-002"},
			CategoryOverlaps: []bundle.CategoryOverlap{
				{
					CategoryA: bundle.CategoryBrokenChainRefs,
					CategoryB: bundle.CategoryMissingEntries,
					Jaccard:   0.74,
					SharedIDs: []string{"rcpt-001", "rcpt-002"},
				},
			},
		},
	}
}

func clusterResultSkipped() *bundle.ClusterAnalysisResult {
	return &bundle.ClusterAnalysisResult{
		Version:             "cluster_analysis_v1",
		AnomalyCount:        3,
		Skipped:             true,
		PatternSignature:    "nominal",
		ConfidenceScore:     0,
		ConfidenceRationale: "insufficient anomaly count for statistical analysis",
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Human output: PrintBundleResults with cluster analysis
// ─────────────────────────────────────────────────────────────────────────────

func TestPrintBundleResults_ClusterAnalysis_AllDetected(t *testing.T) {
	var buf bytes.Buffer
	p := cli.NewPrinter(&buf, false)
	res := minimalBundleVerifyResult()
	clusterRes := clusterResultAllDetected()

	cli.PrintBundleResults(p, res, "test.dsr.bundle", 1024*1024, "", clusterRes)

	output := buf.String()

	assertContains(t, output, "Anomaly Pattern Analysis")
	assertContains(t, output, "consistent_with_targeted_deletion")
	assertContains(t, output, "confidence 0.93")
	assertContains(t, output, "0.999")
	assertContains(t, output, "high confidence")
	assertContains(t, output, "42")
	assertContains(t, output, "auth-service")
	assertContains(t, output, "72%")
	assertContains(t, output, "18") // multiplier
	assertContains(t, output, "72h")
	assertContains(t, output, "0.74")
}

func TestPrintBundleResults_ClusterAnalysis_Skipped(t *testing.T) {
	var buf bytes.Buffer
	p := cli.NewPrinter(&buf, false)
	res := minimalBundleVerifyResult()
	clusterRes := clusterResultSkipped()

	cli.PrintBundleResults(p, res, "test.dsr.bundle", 0, "", clusterRes)

	output := buf.String()

	assertContains(t, output, "Anomaly Pattern Analysis")
	assertContains(t, output, "skipped")
	assertContains(t, output, "fewer than")
	assertNotContains(t, output, "consistent_with_targeted_deletion")
	assertNotContains(t, output, "Confidence")
}

func TestPrintBundleResults_ClusterAnalysis_Nil(t *testing.T) {
	var buf bytes.Buffer
	p := cli.NewPrinter(&buf, false)
	res := minimalBundleVerifyResult()

	cli.PrintBundleResults(p, res, "test.dsr.bundle", 0, "", nil)

	output := buf.String()
	assertNotContains(t, output, "Anomaly Pattern Analysis")
}

// ─────────────────────────────────────────────────────────────────────────────
// JSON output: WriteBundleJSONReport with cluster analysis
// ─────────────────────────────────────────────────────────────────────────────

func TestWriteBundleJSONReport_ClusterAnalysis_Present(t *testing.T) {
	var buf bytes.Buffer
	res := minimalBundleVerifyResult()
	clusterRes := clusterResultAllDetected()

	if err := cli.WriteBundleJSONReport(&buf, res, 123, clusterRes); err != nil {
		t.Fatalf("WriteBundleJSONReport: %v", err)
	}

	var report map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("invalid JSON: %v\nraw:\n%s", err, buf.String())
	}

	ca, ok := report["cluster_analysis"]
	if !ok {
		t.Fatal("JSON missing field cluster_analysis")
	}
	caMap, ok := ca.(map[string]interface{})
	if !ok {
		t.Fatalf("cluster_analysis is not an object: %T", ca)
	}

	if caMap["pattern_signature"] != "consistent_with_targeted_deletion" {
		t.Errorf("pattern_signature = %v", caMap["pattern_signature"])
	}
	if caMap["pattern_signature_confidence"] != 0.93 {
		t.Errorf("pattern_signature_confidence = %v, want 0.93", caMap["pattern_signature_confidence"])
	}
	if caMap["confidence_score"] != 0.999 {
		t.Errorf("confidence_score = %v, want 0.999", caMap["confidence_score"])
	}
	if caMap["anomaly_count"] != float64(42) {
		t.Errorf("anomaly_count = %v, want 42", caMap["anomaly_count"])
	}

	zc, ok := caMap["zone_concentration"].(map[string]interface{})
	if !ok {
		t.Fatal("zone_concentration missing or not an object")
	}
	if zc["detected"] != true {
		t.Errorf("zone_concentration.detected = %v, want true", zc["detected"])
	}

	tc, ok := caMap["temporal_clustering"].(map[string]interface{})
	if !ok {
		t.Fatal("temporal_clustering missing or not an object")
	}
	if tc["detected"] != true {
		t.Errorf("temporal_clustering.detected = %v, want true", tc["detected"])
	}

	cd, ok := caMap["cascade_detected"].(map[string]interface{})
	if !ok {
		t.Fatal("cascade_detected missing or not an object")
	}
	if cd["detected"] != true {
		t.Errorf("cascade_detected.detected = %v, want true", cd["detected"])
	}
}

func TestWriteBundleJSONReport_ClusterAnalysis_Nil(t *testing.T) {
	var buf bytes.Buffer
	res := minimalBundleVerifyResult()

	if err := cli.WriteBundleJSONReport(&buf, res, 100, nil); err != nil {
		t.Fatalf("WriteBundleJSONReport: %v", err)
	}

	var report map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if _, ok := report["cluster_analysis"]; ok {
		t.Error("cluster_analysis should be absent when nil (omitempty)")
	}

	for _, field := range []string{"version", "bundle_id", "vault_id", "result", "checks", "failures", "duration_ms", "offline"} {
		if _, ok := report[field]; !ok {
			t.Errorf("JSON missing required field %q", field)
		}
	}
}

func TestWriteBundleJSONReport_ClusterAnalysis_Skipped(t *testing.T) {
	var buf bytes.Buffer
	res := minimalBundleVerifyResult()
	clusterRes := clusterResultSkipped()

	if err := cli.WriteBundleJSONReport(&buf, res, 100, clusterRes); err != nil {
		t.Fatalf("WriteBundleJSONReport: %v", err)
	}

	var report map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	ca, ok := report["cluster_analysis"].(map[string]interface{})
	if !ok {
		t.Fatal("cluster_analysis missing or not an object")
	}
	if ca["skipped"] != true {
		t.Errorf("cluster_analysis.skipped = %v, want true", ca["skipped"])
	}
	if ca["confidence_score"] != float64(0) {
		t.Errorf("cluster_analysis.confidence_score = %v, want 0", ca["confidence_score"])
	}

	rationale, ok := ca["confidence_rationale"].(string)
	if !ok || !strings.Contains(rationale, "insufficient") {
		t.Errorf("confidence_rationale = %v, want string containing 'insufficient'", ca["confidence_rationale"])
	}
}
