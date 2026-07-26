package dsr

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// Bundle is the DSR/1.0.4 evidence bundle emitted by the API.
//
// Format: {"receipt": <receipt-object>, "signal_observation": <obs-object-or-null>}
//
// The bundle is always emitted even when signal_observation is null so consumers
// can rely on a single shape. Offline verifiers use signal_observation to
// recompute and check signal_observation_hash without access to the raw provider
// payload. Pre-1.0.4 receipts and R1-N receipts without signal context carry
// signal_observation: null.
type Bundle struct {
	Receipt           json.RawMessage `json:"receipt"`
	SignalObservation json.RawMessage `json:"signal_observation"`
}

// DetectBundle reports whether data is an evidence bundle.
// Returns (bundle, true) when the top-level JSON has a non-null "receipt" object;
// returns (nil, false) when data is a bare receipt.
func DetectBundle(data []byte) (*Bundle, bool) {
	var b Bundle
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, false
	}
	if len(b.Receipt) == 0 {
		return nil, false
	}
	// Check the receipt field is a JSON object, not a scalar or array.
	for _, c := range b.Receipt {
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			continue
		}
		if c != '{' {
			return nil, false
		}
		break
	}
	return &b, true
}

// VerifySignalObservationHash recomputes sha256hex(JCS(signalObsJSON)) and
// compares it against expectedHash. signalObsJSON must be a JSON object — null
// and empty inputs return (false, error). Returns (true, nil) on match.
func VerifySignalObservationHash(signalObsJSON []byte, expectedHash string) (bool, error) {
	if len(signalObsJSON) == 0 || string(signalObsJSON) == "null" {
		return false, fmt.Errorf("signal_observation is null — no hash to verify")
	}
	var obs map[string]interface{}
	if err := json.Unmarshal(signalObsJSON, &obs); err != nil {
		return false, fmt.Errorf("signal_observation parse error: %w", err)
	}
	m := make(map[string]any, len(obs))
	for k, v := range obs {
		m[k] = v
	}
	canonical, err := jcsSerialise(m)
	if err != nil {
		return false, fmt.Errorf("signal_observation JCS error: %w", err)
	}
	h := sha256.Sum256([]byte(canonical))
	computed := hex.EncodeToString(h[:])
	return computed == expectedHash, nil
}
