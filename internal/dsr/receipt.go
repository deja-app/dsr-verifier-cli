// Package dsr parses DSR receipts in the ExternalDSREnvelope format.
//
// The ExternalDSREnvelope is the JSON structure of a .dsr file shared with auditors.
// Field names match the JSON wire format exactly.
//
// Critical invariant: PRNumber and TimeToResolutionMs must be decoded as int64,
// never float64. The canonical form for both v1-legacy and v2-jcs passes these
// as JSON integers via strconv.FormatInt — if they were decoded as float64 and
// re-encoded, ECMA-262 vs Go float divergence could produce different bytes for
// large values, breaking signature verification.
package dsr

// Receipt type constants.
const (
	TypeR0  = "R0"
	TypeR1  = "R1"
	TypeR1L = "R1-L"
	TypeR1N = "R1-N"
	TypeR2  = "R2"
	TypeR2F = "R2-F"
	TypeR2R = "R2-R"
	TypeRV  = "RV"
	TypeRE  = "RE"
	TypeRG  = "RG"
)

// Signature algorithm constants.
const (
	AlgoSHA256Legacy = "sha256-legacy"
	AlgoED25519V1    = "ed25519-v1"
	AlgoRSAPSSSHA256 = "rsa-pss-sha256"
	AlgoECDSASHA256  = "ecdsa-sha256"
)

// KnownTypes is the complete set of accepted receipt types.
var KnownTypes = map[string]bool{
	TypeR0: true, TypeR1: true, TypeR1L: true, TypeR1N: true,
	TypeR2: true, TypeR2F: true, TypeR2R: true,
	TypeRV: true, TypeRE: true, TypeRG: true,
}

// Envelope is the parsed .dsr receipt shared with auditors.
type Envelope struct {
	DSRVersion           string      `json:"dsr_version"`
	Type                 string      `json:"type"`
	ReceiptID            string      `json:"receipt_id"`
	VaultID              string      `json:"vault_id"`
	OrganizationID       string      `json:"organization_id"` // RG receipts: org-scoped, no vault_id
	Timestamp            string      `json:"timestamp"`
	Actor                string      `json:"actor"`
	Origin               string      `json:"origin"`
	Signature            string      `json:"signature"`
	SignatureAlgorithm   *string     `json:"signature_algorithm"`
	CanonicalFormVersion *string     `json:"canonical_form_version"`
	PriorHash            *string     `json:"prior_hash"`
	SigningKeyID         *string     `json:"signing_key_id"`

	// Attribution fields (R1, R1-L, R1-N)
	Repository           *string     `json:"repository"`
	PRNumber             *int64      `json:"pr_number"`
	ServiceZone          *string     `json:"service_zone"`
	ErrorClass           *string     `json:"error_class"`
	MissingField         *string     `json:"missing_field"`
	CCSScore             *string     `json:"ccs_score"`
	Matched              *string     `json:"matched"`
	Confidence           *string     `json:"confidence"`
	ProducerGraphScore   *string     `json:"producer_graph_score"`
	SchemaStabilityScore *string     `json:"schema_stability_score"`
	IsSynthetic          *bool       `json:"is_synthetic"`
	IsInternalValidation *bool       `json:"is_internal_validation"`
	IsTrial              *bool       `json:"is_trial"`
	IssuedAt             *string     `json:"issued_at"`
	// AnchoringBasis ("deploy"|"merge") sorts before ccs_score; omit-null.
	AnchoringBasis       *string     `json:"anchoring_basis"`
	// TemporalBasis ("deployed"|"merged_fallback") sorts after signing_algorithm; omit-null.
	TemporalBasis        *string     `json:"temporal_basis"`
	CCSFactors           *CCSFactors `json:"ccs_factors"`

	// Governance fields (RG) — org-scoped, no vault_id
	ChangeType     *string `json:"change_type"`
	PriorStateHash *string `json:"prior_state_hash"`
	NewStateHash   *string `json:"new_state_hash"`

	// Resolution fields (R2, R2-F, R2-R)
	AttributionReceiptID *string `json:"attribution_receipt_id"`
	IncidentID           *string `json:"incident_id"`
	ResolvedAt           *string `json:"resolved_at"`
	TimeToResolutionMs   *int64  `json:"time_to_resolution_ms"`
	FileGateScore        *string `json:"file_gate_score"`
	RateGateScore        *string `json:"rate_gate_score"`
	InfraGateScore       *string `json:"infra_gate_score"`
	FeatureGateScore     *string `json:"feature_gate_score"`
	DurationGateScore    *string `json:"duration_gate_score"`
	GatesPassed          *bool   `json:"gates_passed"`
	GateEvaluatedAt      *string `json:"gate_evaluated_at"`
	DSRFixCode           *string `json:"dsr_fix_code"`
}

// CCSFactors holds the W1–W8 factor inputs for CCS recomputation.
type CCSFactors struct {
	W1 float64 `json:"w1"`
	W2 float64 `json:"w2"`
	W3 float64 `json:"w3"`
	W4 float64 `json:"w4"`
	W5 float64 `json:"w5"`
	W6 float64 `json:"w6"`
	W7 float64 `json:"w7"`
	W8 float64 `json:"w8"`
}

// SigAlgo returns the effective signature algorithm.
// Absent or empty → "sha256-legacy".
func (e *Envelope) SigAlgo() string {
	if e.SignatureAlgorithm == nil || *e.SignatureAlgorithm == "" {
		return AlgoSHA256Legacy
	}
	return *e.SignatureAlgorithm
}

// FormVersion returns the effective canonical form version.
// Absent, null, or unknown → "v1-legacy".
func (e *Envelope) FormVersion() string {
	if e.CanonicalFormVersion == nil {
		return "v1-legacy"
	}
	if *e.CanonicalFormVersion == "v2-jcs" {
		return "v2-jcs"
	}
	return "v1-legacy"
}

// IsAttributionType reports whether t is R1, R1-L, or R1-N.
func IsAttributionType(t string) bool {
	return t == TypeR1 || t == TypeR1L || t == TypeR1N
}

// IsResolutionType reports whether t is R2, R2-F, or R2-R.
func IsResolutionType(t string) bool {
	return t == TypeR2 || t == TypeR2F || t == TypeR2R
}

// IsGovernanceType reports whether t is RG.
// RG receipts are org-scoped (no vault_id) and use the 9-field governance
// canonical form: actor, change_type, issued_at, new_state_hash,
// organization_id, prior_state_hash, receipt_id, type, version.
func IsGovernanceType(t string) bool {
	return t == TypeRG
}
