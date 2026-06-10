package dsr

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// CanonicalPayload derives the canonical signing payload for e.
// This is the exact byte sequence that was signed; it must match the issuer's
// output or signature verification will fail.
//
// Both canonical_form_version values ("v1-legacy" and "v2-jcs") produce
// byte-identical output for our flat receipt payloads (string/int64/bool/null).
// The distinction would only matter if future fields introduced nested objects
// or float values with ECMA-262 vs strconv divergence.
func CanonicalPayload(e *Envelope) (string, error) {
	switch {
	case IsAttributionType(e.Type):
		return attributionCanonical(e)
	case IsResolutionType(e.Type):
		return resolutionCanonical(e)
	default:
		return otherCanonical(e)
	}
}

func attributionCanonical(e *Envelope) (string, error) {
	if e.Repository == nil {
		return "", fmt.Errorf("attribution receipt missing repository")
	}
	if e.PRNumber == nil {
		return "", fmt.Errorf("attribution receipt missing pr_number")
	}

	// issued_at: use explicit field when present; fall back to timestamp.
	// The TypeScript issuer uses `receipt.issuedAt ?? receipt.timestamp`.
	var issuedAt string
	if e.IssuedAt != nil {
		issuedAt = *e.IssuedAt
	} else {
		issuedAt = e.Timestamp
	}

	m := map[string]any{
		"ccs_score":     strDeref(e.CCSScore, "0.0000"),
		"confidence":    strDeref(e.Confidence, ""),
		"error_class":   anyNullableStr(e.ErrorClass),
		"issued_at":     issuedAt,
		"matched":       strDeref(e.Matched, "false"),
		"missing_field": anyNullableStr(e.MissingField),
		"pr_number":     *e.PRNumber,
		"repository":    *e.Repository,
		"service_zone":  strDeref(e.ServiceZone, ""),
	}

	// Conditional fields: include only when non-null in the envelope.
	if e.ProducerGraphScore != nil {
		m["producer_graph_score"] = *e.ProducerGraphScore
	}
	if e.SchemaStabilityScore != nil {
		m["schema_stability_score"] = *e.SchemaStabilityScore
	}
	if e.IsSynthetic != nil {
		m["is_synthetic"] = *e.IsSynthetic
	}
	if e.IsInternalValidation != nil {
		m["is_internal_validation"] = *e.IsInternalValidation
	}
	if e.IsTrial != nil {
		m["is_trial"] = *e.IsTrial
	}
	if e.SigningKeyID != nil {
		m["signing_key_id"] = *e.SigningKeyID
	}
	// The canonical form field is "signing_algorithm"; its value comes from
	// the envelope's "signature_algorithm" field (different name, same value).
	if e.SignatureAlgorithm != nil {
		m["signing_algorithm"] = *e.SignatureAlgorithm
	}

	return jcsSerialise(m)
}

func resolutionCanonical(e *Envelope) (string, error) {
	if e.AttributionReceiptID == nil {
		return "", fmt.Errorf("resolution receipt missing attribution_receipt_id")
	}
	if e.IncidentID == nil {
		return "", fmt.Errorf("resolution receipt missing incident_id")
	}
	if e.ResolvedAt == nil {
		return "", fmt.Errorf("resolution receipt missing resolved_at")
	}
	if e.GateEvaluatedAt == nil {
		return "", fmt.Errorf("resolution receipt missing gate_evaluated_at")
	}
	if e.TimeToResolutionMs == nil {
		return "", fmt.Errorf("resolution receipt missing time_to_resolution_ms")
	}

	m := map[string]any{
		"attribution_receipt_id": *e.AttributionReceiptID,
		"duration_gate_score":    strDeref(e.DurationGateScore, "0.0000"),
		"feature_gate_score":     strDeref(e.FeatureGateScore, "0.0000"),
		"file_gate_score":        strDeref(e.FileGateScore, "0.0000"),
		"gate_evaluated_at":      *e.GateEvaluatedAt,
		"gates_passed":           boolDeref(e.GatesPassed, false),
		"incident_id":            *e.IncidentID,
		"infra_gate_score":       strDeref(e.InfraGateScore, "0.0000"),
		"issued_at":              e.Timestamp,
		"rate_gate_score":        strDeref(e.RateGateScore, "0.0000"),
		"resolved_at":            *e.ResolvedAt,
		"service_zone":           strDeref(e.ServiceZone, ""),
		"time_to_resolution_ms":  *e.TimeToResolutionMs,
		"vault_id":               e.VaultID,
	}

	if e.DSRFixCode != nil {
		m["dsr_fix_code"] = *e.DSRFixCode
	}
	if e.SigningKeyID != nil {
		m["signing_key_id"] = *e.SigningKeyID
	}
	if e.SignatureAlgorithm != nil {
		m["signing_algorithm"] = *e.SignatureAlgorithm
	}

	return jcsSerialise(m)
}

func otherCanonical(e *Envelope) (string, error) {
	m := map[string]any{
		"actor":      e.Actor,
		"receipt_id": e.ReceiptID,
		"timestamp":  e.Timestamp,
		"type":       e.Type,
		"vault_id":   e.VaultID,
		"version":    e.DSRVersion,
	}
	return jcsSerialise(m)
}

// jcsSerialise produces a compact JSON string for a flat map following RFC 8785
// (JCS) for the value types present in DSR receipt canonical forms:
//
//   - string → ECMA-262 JSON string escaping via encoding/json
//   - int64  → strconv.FormatInt (never float64 — no ECMA-262 divergence risk)
//   - bool   → "true" / "false"
//   - nil    → "null"
//
// Keys are sorted by raw Unicode code-point order. For the ASCII field names used
// in receipt payloads, this is identical to lexicographic byte order.
// This matches both the TypeScript v1-legacy (Object.keys().sort() + JSON.stringify)
// and v2-jcs (RFC 8785) implementations for flat string/int/bool/null payloads.
func jcsSerialise(m map[string]any) (string, error) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })

	var sb strings.Builder
	sb.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			sb.WriteByte(',')
		}
		kb, _ := json.Marshal(k)
		sb.Write(kb)
		sb.WriteByte(':')

		switch val := m[k].(type) {
		case nil:
			sb.WriteString("null")
		case bool:
			if val {
				sb.WriteString("true")
			} else {
				sb.WriteString("false")
			}
		case int64:
			sb.WriteString(strconv.FormatInt(val, 10))
		case string:
			vb, _ := json.Marshal(val)
			sb.Write(vb)
		default:
			return "", fmt.Errorf("canonical: unsupported value type %T for key %q", m[k], k)
		}
	}
	sb.WriteByte('}')
	return sb.String(), nil
}

// ChainHash computes H(n) = SHA-256_hex(UTF8(priorHash) ++ UTF8(canonicalPayload))
// where priorHash is "" for the genesis receipt (prior_hash absent or null).
// The result is the 64-character lowercase hex string stored as the next
// receipt's prior_hash field.
func ChainHash(priorHash *string, canonicalPayload string) string {
	prev := ""
	if priorHash != nil {
		prev = *priorHash
	}
	input := append([]byte(prev), []byte(canonicalPayload)...)
	h := sha256.Sum256(input)
	return hexEncode(h[:])
}

// helpers

func strDeref(p *string, def string) string {
	if p == nil {
		return def
	}
	return *p
}

func anyNullableStr(p *string) any {
	if p == nil {
		return nil
	}
	return *p
}

func boolDeref(p *bool, def bool) bool {
	if p == nil {
		return def
	}
	return *p
}
