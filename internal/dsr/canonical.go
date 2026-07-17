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
	case e.Type == TypeR1L:
		// R1-L has a distinct canonical form from R1: candidate_count, highest_ccs,
		// no repository/pr_number. Must be dispatched before IsAttributionType.
		return lowConfidenceCanonical(e)
	case e.Type == TypeR1N:
		// R1-N has a distinct canonical form from R1: no repository/pr_number,
		// carries highest_candidate_ccs, lookback_days, prs_evaluated, receipt_id.
		return noAttributionCanonical(e)
	case e.Type == TypeRV:
		// RV has a 13-field form including a checks_passed array; it never falls
		// to otherCanonical (which only carries 6 fields and would misverify).
		return rvCanonical(e)
	case IsAttributionType(e.Type):
		return attributionCanonical(e)
	case IsResolutionType(e.Type):
		return resolutionCanonical(e)
	case IsGovernanceType(e.Type):
		return governanceCanonical(e)
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
	// Sort order (alphabetical by canonical key name):
	//   anchoring_basis < ccs_score < ... < signing_algorithm < signing_key_id < temporal_basis
	if e.AnchoringBasis != nil {
		m["anchoring_basis"] = *e.AnchoringBasis
	}
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
	if e.TemporalBasis != nil {
		m["temporal_basis"] = *e.TemporalBasis
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

// governanceCanonical builds the 9-field canonical form for RG receipts.
//
// Canonical field order (Unicode sort):
//
//	actor, change_type, issued_at, new_state_hash, organization_id,
//	prior_state_hash, receipt_id, type, version
//
// RG receipts are signed over organization_id (not vault_id) and use
// issued_at (not timestamp). The signature is SHA-256-hex of this payload.
// prior_hash is storage-level chain linkage and is NOT part of the signed form.
func governanceCanonical(e *Envelope) (string, error) {
	if e.ChangeType == nil {
		return "", fmt.Errorf("governance receipt missing change_type")
	}
	if e.PriorStateHash == nil {
		return "", fmt.Errorf("governance receipt missing prior_state_hash")
	}
	if e.NewStateHash == nil {
		return "", fmt.Errorf("governance receipt missing new_state_hash")
	}

	// issued_at: use explicit field when present; fall back to timestamp.
	var issuedAt string
	if e.IssuedAt != nil {
		issuedAt = *e.IssuedAt
	} else {
		issuedAt = e.Timestamp
	}

	m := map[string]any{
		"actor":            e.Actor,
		"change_type":      *e.ChangeType,
		"issued_at":        issuedAt,
		"new_state_hash":   *e.NewStateHash,
		"organization_id":  e.OrganizationID,
		"prior_state_hash": *e.PriorStateHash,
		"receipt_id":       e.ReceiptID,
		"type":             e.Type,
		"version":          e.DSRVersion,
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

// rvCanonical builds the 13-field canonical form for RV (verification run) receipts.
//
// Field order (Unicode sort):
//
//	checks_passed, failed_check_type, failure_reason, issued_at, receipt_id,
//	receipts_attested_count, rv_type, vault_id, verification_completed_at,
//	verification_mode, verification_result, verification_run_id, verification_started_at
//
// checks_passed is a JSON array of strings (sorted within the array as received;
// no re-sorting — the issuer preserves insertion order, which is the check execution order).
// failed_check_type and failure_reason are null on passing runs.
//
// issued_at: uses the explicit IssuedAt field; falls back to Timestamp.
func rvCanonical(e *Envelope) (string, error) {
	var issuedAt string
	if e.IssuedAt != nil {
		issuedAt = *e.IssuedAt
	} else {
		issuedAt = e.Timestamp
	}
	var attested int64
	if e.ReceiptsAttestedCount != nil {
		attested = *e.ReceiptsAttestedCount
	}
	// checks_passed: nil slice serialises as empty array in JSON; preserve as-is.
	checks := e.ChecksPassed
	if checks == nil {
		checks = []string{}
	}
	m := map[string]any{
		"checks_passed":             checks,
		"failed_check_type":         anyNullableStr(e.FailedCheckType),
		"failure_reason":            anyNullableStr(e.FailureReason),
		"issued_at":                 issuedAt,
		"receipt_id":                e.ReceiptID,
		"receipts_attested_count":   attested,
		"rv_type":                   strDeref(e.RVType, ""),
		"vault_id":                  e.VaultID,
		"verification_completed_at": strDeref(e.VerificationCompletedAt, ""),
		"verification_mode":         strDeref(e.VerificationMode, ""),
		"verification_result":       strDeref(e.VerificationResult, ""),
		"verification_run_id":       strDeref(e.VerificationRunID, ""),
		"verification_started_at":   strDeref(e.VerificationStartedAt, ""),
	}
	return jcsSerialise(m)
}

// lowConfidenceCanonical builds the canonical form for R1-L (low-confidence) receipts.
//
// Field order (base set, sorted alphabetically):
//
//	candidate_count, highest_ccs, [incident_id], [is_synthetic], issued_at,
//	receipt_id, service_zone, type, vault_id, version
//
// candidate_count is serialised as int64 (never float64) to avoid ECMA-262 divergence.
// incident_id is omitted when nil. is_synthetic is omitted when nil (DSR/1.0.1+ pattern).
// issued_at comes from the explicit IssuedAt field; falls back to Timestamp.
//
// The signature is SHA-256 hex of the canonical string (sha256-legacy).
// Mirror of canonicaliseLowConfidenceReceipt() in packages/api/src/utils/canonical-receipt.ts.
func lowConfidenceCanonical(e *Envelope) (string, error) {
	var issuedAt string
	if e.IssuedAt != nil {
		issuedAt = *e.IssuedAt
	} else {
		issuedAt = e.Timestamp
	}

	var candidateCount int64
	if e.CandidateCount != nil {
		candidateCount = *e.CandidateCount
	}
	highestCcs := strDeref(e.HighestCcs, "0.000")

	m := map[string]any{
		"candidate_count": candidateCount,
		"highest_ccs":     highestCcs,
		"issued_at":       issuedAt,
		"receipt_id":      e.ReceiptID,
		"service_zone":    strDeref(e.ServiceZone, ""),
		"type":            e.Type,
		"vault_id":        e.VaultID,
		"version":         e.DSRVersion,
	}
	if e.IncidentID != nil {
		m["incident_id"] = *e.IncidentID
	}
	if e.IsSynthetic != nil {
		m["is_synthetic"] = *e.IsSynthetic
	}
	return jcsSerialise(m)
}

// noAttributionCanonical builds the canonical form for R1-N (no-attribution) receipts.
//
// Field order (base set, sorted alphabetically):
//
//	highest_candidate_ccs, [incident_id], [is_synthetic], issued_at,
//	lookback_days, prs_evaluated, receipt_id, service_zone, type, vault_id, version
//
// incident_id is omitted when null (DSR/1.0.3+). Pre-1.0.3 receipts always
// have a non-null incident_id and their canonical bytes are unchanged.
// is_synthetic is omitted when not set (DSR/1.0.1+ pattern).
//
// issued_at comes from the explicit IssuedAt field; fall back to Timestamp.
func noAttributionCanonical(e *Envelope) (string, error) {
	var issuedAt string
	if e.IssuedAt != nil {
		issuedAt = *e.IssuedAt
	} else {
		issuedAt = e.Timestamp
	}

	highest := strDeref(e.HighestCandidateCcs, "0.000")
	var lookback int64
	if e.LookbackDays != nil {
		lookback = *e.LookbackDays
	}
	var prsEval int64
	if e.PrsEvaluated != nil {
		prsEval = *e.PrsEvaluated
	}

	m := map[string]any{
		"highest_candidate_ccs": highest,
		"issued_at":             issuedAt,
		"lookback_days":         lookback,
		"prs_evaluated":         prsEval,
		"receipt_id":            e.ReceiptID,
		"service_zone":          strDeref(e.ServiceZone, ""),
		"type":                  e.Type,
		"vault_id":              e.VaultID,
		"version":               e.DSRVersion,
	}
	// DSR/1.0.3: omit incident_id when null so pre-1.0.3 receipts (always non-null) stay valid.
	if e.IncidentID != nil {
		m["incident_id"] = *e.IncidentID
	}
	// DSR/1.0.1+: only included when set — backward compatible with pre-1.0.1 receipts.
	if e.IsSynthetic != nil {
		m["is_synthetic"] = *e.IsSynthetic
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
		case []string:
			// Array of strings — used by RV checks_passed field.
			sb.WriteByte('[')
			for i, s := range val {
				if i > 0 {
					sb.WriteByte(',')
				}
				vb, _ := json.Marshal(s)
				sb.Write(vb)
			}
			sb.WriteByte(']')
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
