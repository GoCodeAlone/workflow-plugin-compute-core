package protocol

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	SoftwareAgentSignaturePrefix   = "software-agent:"
	SoftwareRouterSignaturePrefix  = "software-router:"
	CredentialProofSignaturePrefix = "credential-hmac-sha256:"

	defaultReceiptVerifierProvider = "signed_receipt"
)

type ProofReceipt struct {
	ID                    string         `json:"id"`
	OrgID                 string         `json:"org_id"`
	TaskID                string         `json:"task_id"`
	TaskHash              string         `json:"task_hash"`
	InputHash             string         `json:"input_hash"`
	DependencyClosureHash string         `json:"dependency_closure_hash"`
	Executor              ExecutorRef    `json:"executor"`
	WorkerID              string         `json:"worker_id"`
	PoolID                string         `json:"pool_id"`
	PolicyID              string         `json:"policy_id"`
	StartedAt             time.Time      `json:"started_at"`
	FinishedAt            time.Time      `json:"finished_at"`
	ExitCode              int            `json:"exit_code,omitempty"`
	ResourceUsage         ResourceUsage  `json:"resource_usage"`
	ArtifactHash          string         `json:"artifact_hash"`
	ResultPreview         map[string]any `json:"result_preview,omitempty"`
	Verifier              VerifierResult `json:"verifier"`
	AgentSignature        string         `json:"agent_signature"`
}

type ServiceReceipt struct {
	ID             string                `json:"id"`
	OrgID          string                `json:"org_id"`
	TaskID         string                `json:"task_id"`
	ServiceLeaseID string                `json:"service_lease_id"`
	WorkerID       string                `json:"worker_id"`
	PoolID         string                `json:"pool_id"`
	PolicyID       string                `json:"policy_id"`
	Executor       ExecutorRef           `json:"executor"`
	DeploymentHash string                `json:"deployment_hash"`
	RequestID      string                `json:"request_id"`
	TraceID        string                `json:"trace_id"`
	RequestHash    string                `json:"request_hash"`
	ResponseHash   string                `json:"response_hash"`
	StartedAt      time.Time             `json:"started_at"`
	FinishedAt     time.Time             `json:"finished_at"`
	ResourceUsage  ResourceUsage         `json:"resource_usage"`
	ResourceLimits ResourceLimits        `json:"resource_limits,omitzero"`
	SLOEvidence    SLOEvidence           `json:"slo_evidence"`
	StatusEvidence ServiceStatusEvidence `json:"status_evidence,omitzero"`
	Verifier       VerifierResult        `json:"verifier"`
	AgentSignature string                `json:"agent_signature"`
}

type EdgeRequestReceipt struct {
	ProtocolVersion     string         `json:"protocol_version,omitempty"`
	ID                  string         `json:"id"`
	OrgID               string         `json:"org_id"`
	PoolID              string         `json:"pool_id"`
	ProductID           string         `json:"product_id"`
	Hostname            string         `json:"hostname"`
	RouteTarget         string         `json:"route_target"`
	ServiceLeaseID      string         `json:"service_lease_id,omitempty"`
	TaskID              string         `json:"task_id,omitempty"`
	WorkerID            string         `json:"worker_id,omitempty"`
	ContentRef          string         `json:"content_ref,omitempty"`
	RequestID           string         `json:"request_id"`
	TraceID             string         `json:"trace_id"`
	Method              string         `json:"method"`
	RequestClass        string         `json:"request_class"`
	RequestHash         string         `json:"request_hash"`
	ResponseHash        string         `json:"response_hash"`
	RequestBytes        int64          `json:"request_bytes,omitempty"`
	ResponseBytes       int64          `json:"response_bytes,omitempty"`
	StartedAt           time.Time      `json:"started_at"`
	FinishedAt          time.Time      `json:"finished_at"`
	ResourceUsage       ResourceUsage  `json:"resource_usage"`
	ServiceReceiptIDs   []string       `json:"service_receipt_ids,omitempty"`
	IngressEvidenceID   string         `json:"ingress_evidence_id,omitempty"`
	IngressEvidenceHash string         `json:"ingress_evidence_hash,omitempty"`
	Verifier            VerifierResult `json:"verifier"`
	RouterSignature     string         `json:"router_signature"`
}

type ReceiptVerificationOptions struct {
	CredentialTokenProofKey string
	AllowSoftwareFallback   bool
	VerifierProvider        string
	VerifierMessage         string
}

func TokenProofKey(token string) string {
	if token == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func SoftwareAgentProofSignature(receipt ProofReceipt) string {
	receipt.AgentSignature = ""
	return SoftwareAgentSignaturePrefix + strings.TrimPrefix(CanonicalHash(receipt), "sha256:")
}

func SoftwareAgentServiceSignature(receipt ServiceReceipt) string {
	receipt.AgentSignature = ""
	if !receipt.Executor.RequiresAttestation() {
		receipt.Verifier = VerifierResult{}
	}
	return SoftwareAgentSignaturePrefix + strings.TrimPrefix(CanonicalHash(receipt), "sha256:")
}

func SoftwareRouterEdgeSignature(receipt EdgeRequestReceipt) string {
	receipt.RouterSignature = ""
	receipt.Verifier = VerifierResult{}
	return SoftwareRouterSignaturePrefix + strings.TrimPrefix(CanonicalHash(receipt), "sha256:")
}

func CredentialProofSignature(receipt ProofReceipt, tokenProofKey string) string {
	if tokenProofKey == "" {
		return ""
	}
	receipt.AgentSignature = ""
	mac := hmac.New(sha256.New, []byte(tokenProofKey))
	_, _ = mac.Write([]byte(CanonicalHash(receipt)))
	return CredentialProofSignaturePrefix + hex.EncodeToString(mac.Sum(nil))
}

func CredentialServiceSignature(receipt ServiceReceipt, tokenProofKey string) string {
	if tokenProofKey == "" {
		return ""
	}
	receipt.AgentSignature = ""
	if !receipt.Executor.RequiresAttestation() {
		receipt.Verifier = VerifierResult{}
	}
	mac := hmac.New(sha256.New, []byte(tokenProofKey))
	_, _ = mac.Write([]byte(CanonicalHash(receipt)))
	return CredentialProofSignaturePrefix + hex.EncodeToString(mac.Sum(nil))
}

func CredentialEdgeSignature(receipt EdgeRequestReceipt, tokenProofKey string) string {
	if tokenProofKey == "" {
		return ""
	}
	receipt.RouterSignature = ""
	receipt.Verifier = VerifierResult{}
	mac := hmac.New(sha256.New, []byte(tokenProofKey))
	_, _ = mac.Write([]byte(CanonicalHash(receipt)))
	return CredentialProofSignaturePrefix + hex.EncodeToString(mac.Sum(nil))
}

func VerifyCredentialProofSignature(receipt ProofReceipt, tokenProofKey string) bool {
	if tokenProofKey == "" {
		return false
	}
	if !strings.HasPrefix(receipt.AgentSignature, CredentialProofSignaturePrefix) {
		return false
	}
	expected := CredentialProofSignature(receipt, tokenProofKey)
	return hmac.Equal([]byte(receipt.AgentSignature), []byte(expected))
}

func VerifyCredentialServiceSignature(receipt ServiceReceipt, tokenProofKey string) bool {
	if tokenProofKey == "" {
		return false
	}
	if !strings.HasPrefix(receipt.AgentSignature, CredentialProofSignaturePrefix) {
		return false
	}
	expected := CredentialServiceSignature(receipt, tokenProofKey)
	return hmac.Equal([]byte(receipt.AgentSignature), []byte(expected))
}

func VerifyCredentialEdgeSignature(receipt EdgeRequestReceipt, tokenProofKey string) bool {
	if tokenProofKey == "" {
		return false
	}
	if !strings.HasPrefix(receipt.RouterSignature, CredentialProofSignaturePrefix) {
		return false
	}
	expected := CredentialEdgeSignature(receipt, tokenProofKey)
	return hmac.Equal([]byte(receipt.RouterSignature), []byte(expected))
}

func VerifyServiceReceipt(receipt ServiceReceipt, opts ReceiptVerificationOptions) (ServiceReceipt, error) {
	for _, field := range []struct {
		name  string
		value string
	}{
		{name: "deployment_hash", value: receipt.DeploymentHash},
		{name: "request_hash", value: receipt.RequestHash},
		{name: "response_hash", value: receipt.ResponseHash},
	} {
		if !validSHA256Digest(field.value) {
			return ServiceReceipt{}, fmt.Errorf("%s must use sha256 digest", field.name)
		}
	}
	if !serviceReceiptSignatureValid(receipt, opts) {
		return ServiceReceipt{}, errors.New("service receipt agent_signature is invalid")
	}
	if !receipt.Executor.RequiresAttestation() {
		receipt.Verifier = receiptVerifierResult(opts, "service receipt signature verified; quorum and key-backed trust handled separately")
	}
	if err := receipt.Validate(); err != nil {
		return ServiceReceipt{}, err
	}
	return receipt, nil
}

func VerifyEdgeRequestReceipt(receipt EdgeRequestReceipt, opts ReceiptVerificationOptions) (EdgeRequestReceipt, error) {
	for _, field := range []struct {
		name  string
		value string
	}{
		{name: "request_hash", value: receipt.RequestHash},
		{name: "response_hash", value: receipt.ResponseHash},
	} {
		if !validSHA256Digest(field.value) {
			return EdgeRequestReceipt{}, fmt.Errorf("%s must use sha256 digest", field.name)
		}
	}
	if !edgeRequestReceiptSignatureValid(receipt, opts) {
		return EdgeRequestReceipt{}, errors.New("edge request receipt router_signature is invalid")
	}
	receipt.Verifier = receiptVerifierResult(opts, "edge request receipt signature verified; route target and accounting checked")
	if err := receipt.Validate(); err != nil {
		return EdgeRequestReceipt{}, err
	}
	return receipt, nil
}

func receiptVerifierResult(opts ReceiptVerificationOptions, defaultMessage string) VerifierResult {
	provider := strings.TrimSpace(opts.VerifierProvider)
	if provider == "" {
		provider = defaultReceiptVerifierProvider
	}
	message := opts.VerifierMessage
	if message == "" {
		message = defaultMessage
	}
	return VerifierResult{
		Provider: provider,
		Status:   VerificationAccepted,
		Message:  message,
	}
}

func serviceReceiptSignatureValid(receipt ServiceReceipt, opts ReceiptVerificationOptions) bool {
	if strings.HasPrefix(receipt.AgentSignature, CredentialProofSignaturePrefix) {
		return VerifyCredentialServiceSignature(receipt, opts.CredentialTokenProofKey)
	}
	return opts.AllowSoftwareFallback && receipt.AgentSignature == SoftwareAgentServiceSignature(receipt)
}

func edgeRequestReceiptSignatureValid(receipt EdgeRequestReceipt, opts ReceiptVerificationOptions) bool {
	if strings.HasPrefix(receipt.RouterSignature, CredentialProofSignaturePrefix) {
		return VerifyCredentialEdgeSignature(receipt, opts.CredentialTokenProofKey)
	}
	return opts.AllowSoftwareFallback && receipt.RouterSignature == SoftwareRouterEdgeSignature(receipt)
}

func (r ProofReceipt) Validate() error {
	var errs []error
	require := func(name, value string) {
		if value == "" {
			errs = append(errs, fmt.Errorf("%s is required", name))
		}
	}

	require("id", r.ID)
	require("org_id", r.OrgID)
	require("task_id", r.TaskID)
	require("task_hash", r.TaskHash)
	require("input_hash", r.InputHash)
	require("dependency_closure_hash", r.DependencyClosureHash)
	for _, field := range []struct {
		name  string
		value string
	}{
		{name: "task_hash", value: r.TaskHash},
		{name: "input_hash", value: r.InputHash},
		{name: "dependency_closure_hash", value: r.DependencyClosureHash},
		{name: "artifact_hash", value: r.ArtifactHash},
	} {
		if field.value != "" && !validSHA256Digest(field.value) {
			errs = append(errs, fmt.Errorf("%s must use sha256 digest", field.name))
		}
	}
	if err := r.Executor.ValidateForProof(); err != nil {
		errs = append(errs, err)
	}
	require("worker_id", r.WorkerID)
	require("pool_id", r.PoolID)
	require("policy_id", r.PolicyID)
	require("artifact_hash", r.ArtifactHash)
	require("verifier.provider", r.Verifier.Provider)
	require("agent_signature", r.AgentSignature)
	if err := ValidateRuntimeResultPreview(r.ResultPreview); err != nil {
		errs = append(errs, err)
	}
	if r.Verifier.Status != VerificationAccepted {
		errs = append(errs, fmt.Errorf("verifier.status must be %q", VerificationAccepted))
	}
	if r.Executor.RequiresAttestation() {
		if err := ValidateAttestedProofBinding(AttestedProofBinding{
			Executor:              r.Executor,
			PolicyID:              r.PolicyID,
			TaskID:                r.TaskID,
			TaskHash:              r.TaskHash,
			InputHash:             r.InputHash,
			DependencyClosureHash: r.DependencyClosureHash,
			WorkerID:              r.WorkerID,
			PoolID:                r.PoolID,
			StartedAt:             r.StartedAt,
			FinishedAt:            r.FinishedAt,
			Verifier:              r.Verifier,
		}); err != nil {
			errs = append(errs, err)
		}
	}
	if r.StartedAt.IsZero() {
		errs = append(errs, errors.New("started_at is required"))
	}
	if r.FinishedAt.IsZero() {
		errs = append(errs, errors.New("finished_at is required"))
	}
	if !r.StartedAt.IsZero() && !r.FinishedAt.IsZero() && r.FinishedAt.Before(r.StartedAt) {
		errs = append(errs, errors.New("finished_at must be after started_at"))
	}
	return errors.Join(errs...)
}

func (r ServiceReceipt) Validate() error {
	var errs []error
	require := func(name, value string) {
		if value == "" {
			errs = append(errs, fmt.Errorf("%s is required", name))
		}
	}
	require("id", r.ID)
	require("org_id", r.OrgID)
	require("task_id", r.TaskID)
	require("service_lease_id", r.ServiceLeaseID)
	require("worker_id", r.WorkerID)
	require("pool_id", r.PoolID)
	require("policy_id", r.PolicyID)
	if err := r.Executor.ValidateForProof(); err != nil {
		errs = append(errs, err)
	}
	require("deployment_hash", r.DeploymentHash)
	require("request_id", r.RequestID)
	require("trace_id", r.TraceID)
	require("request_hash", r.RequestHash)
	require("response_hash", r.ResponseHash)
	for _, field := range []struct {
		name  string
		value string
	}{
		{name: "deployment_hash", value: r.DeploymentHash},
		{name: "request_hash", value: r.RequestHash},
		{name: "response_hash", value: r.ResponseHash},
	} {
		if field.value != "" && !validSHA256Digest(field.value) {
			errs = append(errs, fmt.Errorf("%s must use sha256 digest", field.name))
		}
	}
	require("verifier.provider", r.Verifier.Provider)
	require("agent_signature", r.AgentSignature)
	if !validStoredProofStatus(r.Verifier.Status) {
		errs = append(errs, fmt.Errorf("verifier.status %q is unsupported", r.Verifier.Status))
	}
	if r.Executor.RequiresAttestation() {
		if err := ValidateAttestedServiceBinding(AttestedServiceBinding{
			Executor:       r.Executor,
			PolicyID:       r.PolicyID,
			TaskID:         r.TaskID,
			DeploymentHash: r.DeploymentHash,
			WorkerID:       r.WorkerID,
			PoolID:         r.PoolID,
			StartedAt:      r.StartedAt,
			FinishedAt:     r.FinishedAt,
			Verifier:       r.Verifier,
		}); err != nil {
			errs = append(errs, err)
		}
	}
	if r.StartedAt.IsZero() {
		errs = append(errs, errors.New("started_at is required"))
	}
	if r.FinishedAt.IsZero() {
		errs = append(errs, errors.New("finished_at is required"))
	}
	if !r.StartedAt.IsZero() && !r.FinishedAt.IsZero() && r.FinishedAt.Before(r.StartedAt) {
		errs = append(errs, errors.New("finished_at must be after started_at"))
	}
	if err := r.ResourceLimits.Validate(); err != nil {
		errs = append(errs, fmt.Errorf("resource_limits: %w", err))
	}
	if err := r.SLOEvidence.Validate(); err != nil {
		errs = append(errs, fmt.Errorf("slo_evidence: %w", err))
	}
	if err := r.StatusEvidence.Validate(); err != nil {
		errs = append(errs, fmt.Errorf("status_evidence: %w", err))
	}
	return errors.Join(errs...)
}

func (r EdgeRequestReceipt) Validate() error {
	var errs []error
	require := func(name, value string) {
		if value == "" {
			errs = append(errs, fmt.Errorf("%s is required", name))
		}
	}
	require("id", r.ID)
	require("org_id", r.OrgID)
	require("pool_id", r.PoolID)
	require("product_id", r.ProductID)
	require("hostname", r.Hostname)
	require("route_target", r.RouteTarget)
	require("request_id", r.RequestID)
	require("trace_id", r.TraceID)
	require("method", r.Method)
	require("request_class", r.RequestClass)
	require("request_hash", r.RequestHash)
	require("response_hash", r.ResponseHash)
	require("router_signature", r.RouterSignature)
	for _, field := range []struct {
		name  string
		value string
	}{
		{name: "org_id", value: r.OrgID},
		{name: "pool_id", value: r.PoolID},
		{name: "product_id", value: r.ProductID},
		{name: "request_id", value: r.RequestID},
		{name: "trace_id", value: r.TraceID},
		{name: "request_class", value: r.RequestClass},
	} {
		if field.value != "" {
			if err := validateIdentifier(field.name, field.value); err != nil {
				errs = append(errs, err)
			}
		}
	}
	if r.ID != "" {
		if err := validateIdentifier("id", r.ID); err != nil {
			errs = append(errs, err)
		}
	}
	if r.Hostname != "" {
		if err := validateNetworkHostname(r.Hostname); err != nil {
			errs = append(errs, fmt.Errorf("hostname: %w", err))
		}
	}
	if r.RouteTarget != "" && !strings.HasPrefix(r.RouteTarget, "service-route:") && !strings.HasPrefix(r.RouteTarget, "content-route:") {
		errs = append(errs, errors.New("route_target must be opaque service-route or content-route target"))
	}
	if strings.HasPrefix(r.RouteTarget, "service-route:") {
		require("ingress_evidence_id", r.IngressEvidenceID)
		require("ingress_evidence_hash", r.IngressEvidenceHash)
		if r.IngressEvidenceID != "" {
			if err := validateIdentifier("ingress_evidence_id", r.IngressEvidenceID); err != nil {
				errs = append(errs, err)
			}
		}
		if r.IngressEvidenceHash != "" && !validSHA256Digest(r.IngressEvidenceHash) {
			errs = append(errs, errors.New("ingress_evidence_hash must use sha256 digest"))
		}
	}
	if r.ContentRef != "" {
		if err := validateContentRef(r.ContentRef); err != nil {
			errs = append(errs, fmt.Errorf("content_ref: %w", err))
		}
	}
	switch r.Method {
	case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS":
	case "":
	default:
		errs = append(errs, fmt.Errorf("method %q is unsupported", r.Method))
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{name: "request_hash", value: r.RequestHash},
		{name: "response_hash", value: r.ResponseHash},
	} {
		if field.value != "" && !validSHA256Digest(field.value) {
			errs = append(errs, fmt.Errorf("%s must use sha256 digest", field.name))
		}
	}
	if r.RequestBytes < 0 {
		errs = append(errs, errors.New("request_bytes must be non-negative"))
	}
	if r.ResponseBytes < 0 {
		errs = append(errs, errors.New("response_bytes must be non-negative"))
	}
	if r.StartedAt.IsZero() {
		errs = append(errs, errors.New("started_at is required"))
	}
	if r.FinishedAt.IsZero() {
		errs = append(errs, errors.New("finished_at is required"))
	}
	if !r.StartedAt.IsZero() && !r.FinishedAt.IsZero() && r.FinishedAt.Before(r.StartedAt) {
		errs = append(errs, errors.New("finished_at must be after started_at"))
	}
	if len(r.ServiceReceiptIDs) > 0 {
		seen := map[string]struct{}{}
		for i, id := range r.ServiceReceiptIDs {
			if err := validateIdentifier(fmt.Sprintf("service_receipt_ids[%d]", i), id); err != nil {
				errs = append(errs, err)
			}
			if _, ok := seen[id]; ok {
				errs = append(errs, fmt.Errorf("service_receipt_ids[%d] duplicates %q", i, id))
			}
			seen[id] = struct{}{}
		}
	}
	require("verifier.provider", r.Verifier.Provider)
	if !validStoredProofStatus(r.Verifier.Status) {
		errs = append(errs, fmt.Errorf("verifier.status %q is unsupported", r.Verifier.Status))
	}
	return errors.Join(errs...)
}

func validStoredProofStatus(status VerificationStatus) bool {
	switch status {
	case VerificationPending, VerificationAccepted, VerificationRejected, VerificationConflicted:
		return true
	default:
		return false
	}
}

func validateContentRef(ref string) error {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return errors.New("ref is required")
	}
	if strings.ContainsAny(ref, " \t\r\n?&#") || strings.Contains(ref, "://") && !strings.HasPrefix(ref, "artifact://") {
		return errors.New("ref must be immutable digest/artifact ref without URL query or fragment")
	}
	if strings.HasPrefix(ref, "sha256:") {
		if !validSHA256Digest(ref) {
			return errors.New("sha256 ref must use 64 hex chars")
		}
		return nil
	}
	if strings.HasPrefix(ref, "artifact://") {
		path := strings.TrimPrefix(ref, "artifact://")
		if path == "" || strings.HasPrefix(path, "/") || strings.Contains(path, "..") {
			return errors.New("artifact ref path is invalid")
		}
		return nil
	}
	return errors.New("ref must use sha256 or artifact scheme")
}
