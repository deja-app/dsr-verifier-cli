package cli_test

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/deja-app/dsr-verifier-cli/internal/bundle"
	"github.com/deja-app/dsr-verifier-cli/internal/cli"
	"github.com/deja-app/dsr-verifier-cli/internal/verify"
)

// These tests guard two instances of one root cause: encoding/json's omitempty
// is a NO-OP ON STRUCT TYPES, so a field the author meant to omit always
// marshals, carrying its zero value into an archived audit artefact.
//
// Both assertions are on KEY ABSENCE, never on the zero value. A test written as
// `if out.Checks.SignalObservation.Passed { ... }` passes against the defect,
// because false is exactly what the defect produces. Asserting the key is gone
// is the only form that can fail when the field is a value type again.

func checksMap(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	checks, ok := doc["checks"].(map[string]any)
	if !ok {
		t.Fatalf("checks object missing or wrong type in %s", raw)
	}
	return checks
}

// TestSignalObsAbsentWhenCheckNeverRan — a receipt with no
// signal_observation_hash must not produce a signal_observation_hash check.
//
// PLANT TO PROVE IT FIRES: in output_json.go change SignalObservation back to
// `JSONCheckResult` (value, not pointer) and drop the & at the population site.
// This test must fail on the key being present. Restore afterwards.
func TestSignalObsAbsentWhenCheckNeverRan(t *testing.T) {
	res := &cli.VerifyResults{
		ReceiptID:    "rcpt_absent",
		ReceiptType:  "R1",
		Algorithm:    "sha256-legacy",
		FormVersion:  "v1-legacy",
		KeyAuthority: &verify.KeyAuthorityResult{Valid: true, Skipped: true},
		Sig:          &verify.SignatureResult{Valid: true, Algorithm: "sha256-legacy"},
		SignalObs:    nil, // the check never ran: no signal_observation_hash on the receipt
	}

	var buf bytes.Buffer
	if err := cli.WriteJSON(&buf, res); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	checks := checksMap(t, buf.Bytes())

	if _, present := checks["signal_observation_hash"]; present {
		t.Errorf("signal_observation_hash is present when the check never ran: "+
			"a verdict is being reported for a check that did not execute.\nchecks = %v", checks)
	}
	// The checks that DID run must still be there — absence must be selective.
	for _, k := range []string{"key_authority", "signature"} {
		if _, present := checks[k]; !present {
			t.Errorf("check %q went missing: omitempty was applied too broadly", k)
		}
	}
}

// TestSignalObsPresentWhenCheckDidRun is the other half: making the field a
// pointer must not make a real result disappear.
func TestSignalObsPresentWhenCheckDidRun(t *testing.T) {
	res := &cli.VerifyResults{
		ReceiptID:    "rcpt_present",
		KeyAuthority: &verify.KeyAuthorityResult{Valid: true, Skipped: true},
		Sig:          &verify.SignatureResult{Valid: true},
		SignalObs:    &cli.SignalObsResult{Valid: true},
	}
	var buf bytes.Buffer
	if err := cli.WriteJSON(&buf, res); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	if _, present := checksMap(t, buf.Bytes())["signal_observation_hash"]; !present {
		t.Error("signal_observation_hash is absent when the check DID run")
	}
}

// TestNoFabricatedWindowTimestamp — when no burst window is detected, the
// bundle report must not carry a window_start or window_end at all.
//
// This is the COMMON path, not an edge case: WindowStart/WindowEnd are assigned
// only when a cluster is detected, and ClusterAnalysis is always non-nil, so
// before the fix essentially every bundle verification report ever produced
// contained "window_start":"0001-01-01T00:00:00Z" — a specific datetime that
// never happened, in an evidence product.
//
// PLANT TO PROVE IT FIRES: in cluster_analysis.go change WindowStart/WindowEnd
// back to `time.Time` (values) and assign them directly. This test must fail on
// the keys being present, and on the year-1 timestamp. Restore afterwards.
func TestNoFabricatedWindowTimestamp(t *testing.T) {
	cluster := &bundle.ClusterAnalysisResult{
		Version:      "cluster_analysis_v1",
		AnomalyCount: 12,
		TemporalClustering: bundle.TemporalClusteringResult{
			Detected:    false, // no burst found — the common outcome
			WindowHours: 6,
		},
	}
	res := &bundle.BundleVerifyResult{
		BundleID: "b1", VaultID: "v1",
		ManifestSig:   bundle.ManifestSigResult{Valid: true},
		SequenceInteg: bundle.SeqIntegResult{Valid: true},
		CausalChain:   bundle.CausalChainResult{Valid: true},
	}

	var buf bytes.Buffer
	if err := cli.WriteBundleJSONReport(&buf, res, 1, cluster); err != nil {
		t.Fatalf("WriteBundleJSONReport: %v", err)
	}
	raw := buf.String()

	// Assertion 1: the fabricated value must not appear anywhere in the artefact.
	if bytes.Contains(buf.Bytes(), []byte("0001-01-01")) {
		t.Errorf("report contains a year-1 timestamp — a datetime that never "+
			"happened, written into an audit artefact:\n%s", raw)
	}

	// Assertion 2: key absence, not zero value.
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	ca, ok := doc["cluster_analysis"].(map[string]any)
	if !ok {
		t.Fatalf("cluster_analysis missing from report")
	}
	tc, ok := ca["temporal_clustering"].(map[string]any)
	if !ok {
		t.Fatalf("temporal_clustering missing from cluster_analysis")
	}
	for _, k := range []string{"window_start", "window_end"} {
		if _, present := tc[k]; present {
			t.Errorf("%s is present when no window was detected: nil means "+
				"'no burst window identified', not midnight in year 1", k)
		}
	}
	// The fields that are always meaningful must survive.
	if _, present := tc["window_hours"]; !present {
		t.Error("window_hours went missing: omitempty applied too broadly")
	}
}

// TestWindowTimestampPresentWhenDetected — the other half.
func TestWindowTimestampPresentWhenDetected(t *testing.T) {
	start := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	end := start.Add(6 * time.Hour)
	cluster := &bundle.ClusterAnalysisResult{
		Version: "cluster_analysis_v1",
		TemporalClustering: bundle.TemporalClusteringResult{
			Detected: true, WindowStart: &start, WindowEnd: &end,
			WindowHours: 6, PValueLT: "<0.001",
		},
	}
	res := &bundle.BundleVerifyResult{BundleID: "b1"}
	var buf bytes.Buffer
	if err := cli.WriteBundleJSONReport(&buf, res, 1, cluster); err != nil {
		t.Fatalf("WriteBundleJSONReport: %v", err)
	}
	if !bytes.Contains(buf.Bytes(), []byte("2026-09-08T12:00:00Z")) {
		t.Errorf("a detected window's start timestamp is missing from the report:\n%s", buf.String())
	}
}
