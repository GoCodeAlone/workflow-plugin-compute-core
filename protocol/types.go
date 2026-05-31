package protocol

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/netip"
	"net/url"
	"path"
	"strings"
	"time"

	pb "github.com/GoCodeAlone/workflow-plugin-compute-core/protocol/pb"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
)

const Version = "compute.v1alpha1"

const NetworkAuditProtocolVersion = Version

type NetworkOperatingMode string

const (
	NetworkModeBatch        NetworkOperatingMode = "batch"
	NetworkModeWarmService  NetworkOperatingMode = "warm-service"
	NetworkModeNodeService  NetworkOperatingMode = "node-service"
	NetworkModeInferenceAPI NetworkOperatingMode = "inference-api"
)

type WorkloadKind string

const (
	WorkloadCommand            WorkloadKind = "command"
	WorkloadContainerBuild     WorkloadKind = "container-build"
	WorkloadDockerComposeBuild WorkloadKind = "docker-compose-build"
	WorkloadBenchmark          WorkloadKind = "benchmark"
	WorkloadTraining           WorkloadKind = "training"
	WorkloadService            WorkloadKind = "service"
	WorkloadNodeService        WorkloadKind = "node-service"
	WorkloadContentCache       WorkloadKind = "content-cache"
	WorkloadSupervisor         WorkloadKind = "supervisor"
	WorkloadProductCapture     WorkloadKind = "product-capture"
	WorkloadProvider           WorkloadKind = "provider"
	WorkloadWASMComponent      WorkloadKind = "wasm-component"
)

type RuntimeProfile string

const (
	RuntimeProfileSandboxedOCI   RuntimeProfile = "sandboxed-oci-v1"
	RuntimeProfileContainerBuild RuntimeProfile = "container-build-v1"
	RuntimeProfileServiceOCI     RuntimeProfile = "service-oci-v1"
	RuntimeProfileWASMComponent  RuntimeProfile = "wasm-component-v1"
	RuntimeProfileBrowserWorker  RuntimeProfile = "browser-worker-wasm-v1"
)

type ContainerRuntimeTool string

const (
	ContainerRuntimePodman         ContainerRuntimeTool = "podman"
	ContainerRuntimeDocker         ContainerRuntimeTool = "docker"
	ContainerRuntimeNerdctl        ContainerRuntimeTool = "nerdctl"
	ContainerRuntimeAppleContainer ContainerRuntimeTool = "apple-container"
)

type RuntimePermission string

const (
	RuntimePermissionForbidden RuntimePermission = "forbidden"
	RuntimePermissionExplicit  RuntimePermission = "explicit"
	RuntimePermissionAllowed   RuntimePermission = "allowed"
)

type ResidueMode string

const (
	ResidueModeIsolated      ResidueMode = "isolated"
	ResidueModeNone          ResidueMode = "none"
	ResidueModeProviderBound ResidueMode = "provider-bound"
	ResidueModeWorkerBound   ResidueMode = "worker-bound"
	ResidueModeSessionBound  ResidueMode = "session-bound"
)

type ResiduePolicy struct {
	Mode                ResidueMode   `json:"mode,omitempty"`
	AllowedModes        []ResidueMode `json:"allowed_modes,omitempty"`
	SessionKey          string        `json:"session_key,omitempty"`
	PolicyHash          string        `json:"policy_hash,omitempty"`
	MaxAgeSeconds       int           `json:"max_age_seconds,omitempty"`
	MaxReuseCount       int           `json:"max_reuse_count,omitempty"`
	WipeOnFailure       bool          `json:"wipe_on_failure,omitempty"`
	ExplicitWorkerBound bool          `json:"explicit_worker_bound,omitempty"`
}

type ResiduePolicyValidation struct {
	NoWorkspaceAllowed         bool
	RequireSessionKey          bool
	RequireExplicitWorkerBound bool
	RequirePolicyHash          bool
}

type UpstreamClientConformance string

const (
	UpstreamClientConformanceShapeOnly  UpstreamClientConformance = "shape-only"
	UpstreamClientConformanceRealClient UpstreamClientConformance = "real-client"
)

type ExecutionSecurityTier string

const (
	ExecutionTrustedNative      ExecutionSecurityTier = "trusted-native"
	ExecutionHardenedContainer  ExecutionSecurityTier = "hardened-container"
	ExecutionSandboxedContainer ExecutionSecurityTier = "sandboxed-container"
	ExecutionMicroVM            ExecutionSecurityTier = "microvm"
	ExecutionConfidentialCPU    ExecutionSecurityTier = "confidential-cpu"
	ExecutionConfidentialGPU    ExecutionSecurityTier = "confidential-gpu"
	ExecutionWASMCapability     ExecutionSecurityTier = "wasm-capability"
)

type ProofTier string

const (
	ProofReceiptOnly      ProofTier = "receipt-only"
	ProofArtifactHash     ProofTier = "artifact-hash"
	ProofReplicatedQuorum ProofTier = "replicated-quorum"
	ProofAttestedReceipt  ProofTier = "attested-receipt"
	ProofAttestedQuorum   ProofTier = "attested-quorum"
	ProofZKReplay         ProofTier = "zk-replay"
)

type VerificationStatus string

const (
	VerificationUnknown    VerificationStatus = ""
	VerificationPending    VerificationStatus = "pending"
	VerificationAccepted   VerificationStatus = "accepted"
	VerificationRejected   VerificationStatus = "rejected"
	VerificationConflicted VerificationStatus = "conflicted"
)

type RuntimeAdapterKind string

const (
	RuntimeAdapterExecution      RuntimeAdapterKind = "execution"
	RuntimeAdapterServiceRun     RuntimeAdapterKind = "service-run"
	RuntimeAdapterServiceSession RuntimeAdapterKind = "service-session"
)

type RuntimeWorkspacePolicy string

const (
	RuntimeWorkspaceUnavailable RuntimeWorkspacePolicy = "unavailable"
	RuntimeWorkspaceOptional    RuntimeWorkspacePolicy = "optional"
	RuntimeWorkspaceRequired    RuntimeWorkspacePolicy = "required"
)

type RuntimeDescriptor struct {
	Name                  string                `json:"name"`
	Version               string                `json:"version"`
	ExecutionSecurityTier ExecutionSecurityTier `json:"execution_security_tier,omitempty"`
	ProofTier             ProofTier             `json:"proof_tier,omitempty"`
	ImageDigest           string                `json:"image_digest,omitempty"`
	RootFSDigest          string                `json:"rootfs_digest,omitempty"`
}

func (d RuntimeDescriptor) Validate() error {
	var errs []error
	if err := validateIdentifier("name", d.Name); err != nil {
		errs = append(errs, err)
	}
	if strings.TrimSpace(d.Version) == "" {
		errs = append(errs, errors.New("version is required"))
	} else if strings.ContainsAny(d.Version, " \t\r\n\x00") {
		errs = append(errs, errors.New("version must not contain whitespace"))
	}
	if !validExecutionSecurityTier(d.ExecutionSecurityTier) {
		errs = append(errs, fmt.Errorf("execution_security_tier %q is unsupported", d.ExecutionSecurityTier))
	}
	if !validProofTier(d.ProofTier) {
		errs = append(errs, fmt.Errorf("proof_tier %q is unsupported", d.ProofTier))
	}
	if d.ExecutionSecurityTier != ExecutionTrustedNative && d.ExecutionSecurityTier != ExecutionWASMCapability {
		if d.ImageDigest == "" {
			errs = append(errs, errors.New("image_digest is required for non-native runtime"))
		} else if !validSHA256Ref(d.ImageDigest) {
			errs = append(errs, errors.New("image_digest must be sha256:<64 hex chars>"))
		}
		if d.RootFSDigest == "" {
			errs = append(errs, errors.New("rootfs_digest is required for non-native runtime"))
		} else if !validSHA256Ref(d.RootFSDigest) {
			errs = append(errs, errors.New("rootfs_digest must be sha256:<64 hex chars>"))
		}
	}
	return errors.Join(errs...)
}

func (d RuntimeDescriptor) ExecutorRef(defaultProvider string) ExecutorRef {
	provider := d.Name
	if provider == "" {
		provider = defaultProvider
	}
	version := d.Version
	if version == "" {
		version = "dev"
	}
	return ExecutorRef{
		Provider:              provider,
		Version:               version,
		ExecutionSecurityTier: d.ExecutionSecurityTier,
		ProofTier:             d.ProofTier,
		ImageDigest:           d.ImageDigest,
		RootFSDigest:          d.RootFSDigest,
	}
}

type ExecutorRef struct {
	Provider              string                `json:"provider"`
	Version               string                `json:"version"`
	ExecutionSecurityTier ExecutionSecurityTier `json:"execution_security_tier,omitempty"`
	ProofTier             ProofTier             `json:"proof_tier,omitempty"`
	ImageDigest           string                `json:"image_digest,omitempty"`
	RootFSDigest          string                `json:"rootfs_digest,omitempty"`
}

func (e ExecutorRef) ValidateForProof() error {
	var errs []error
	if e.Provider == "" {
		errs = append(errs, errors.New("executor.provider is required"))
	}
	if e.Version == "" {
		errs = append(errs, errors.New("executor.version is required"))
	}
	if e.ExecutionSecurityTier == "" {
		errs = append(errs, errors.New("executor.execution_security_tier is required"))
	}
	if e.ProofTier == "" {
		errs = append(errs, errors.New("executor.proof_tier is required"))
	}
	if e.ExecutionSecurityTier != "" && e.ExecutionSecurityTier != ExecutionTrustedNative && e.ExecutionSecurityTier != ExecutionWASMCapability {
		if e.ImageDigest == "" {
			errs = append(errs, errors.New("executor.image_digest is required for non-native executor"))
		}
		if e.RootFSDigest == "" {
			errs = append(errs, errors.New("executor.rootfs_digest is required for non-native executor"))
		}
	}
	return errors.Join(errs...)
}

func (e ExecutorRef) RequiresAttestation() bool {
	switch e.ExecutionSecurityTier {
	case ExecutionConfidentialCPU, ExecutionConfidentialGPU:
		return true
	}
	switch e.ProofTier {
	case ProofAttestedReceipt, ProofAttestedQuorum:
		return true
	default:
		return false
	}
}

type SignatureEnvelope struct {
	Algorithm string `json:"algorithm,omitempty"`
	KeyID     string `json:"key_id,omitempty"`
	Value     string `json:"value,omitempty"`
	Verified  bool   `json:"verified,omitempty"`
}

type VerifierResult struct {
	Provider    string              `json:"provider"`
	Status      VerificationStatus  `json:"status"`
	Message     string              `json:"message,omitempty"`
	Attestation AttestationDecision `json:"attestation,omitzero"`
	KeyRelease  KeyReleaseDecision  `json:"key_release,omitzero"`
}

type AttestationDecision struct {
	Provider             string            `json:"provider,omitempty"`
	VerifierID           string            `json:"verifier_id,omitempty"`
	DecisionID           string            `json:"decision_id,omitempty"`
	HardwareClass        string            `json:"hardware_class,omitempty"`
	ExecutorImageDigest  string            `json:"executor_image_digest,omitempty"`
	ExecutorRootFSDigest string            `json:"executor_rootfs_digest,omitempty"`
	PolicyID             string            `json:"policy_id,omitempty"`
	Nonce                string            `json:"nonce,omitempty"`
	IssuedAt             time.Time         `json:"issued_at,omitzero"`
	ExpiresAt            time.Time         `json:"expires_at,omitzero"`
	SignatureVerified    bool              `json:"signature_verified,omitempty"`
	ConfidentialGPU      bool              `json:"confidential_gpu,omitempty"`
	Signature            SignatureEnvelope `json:"signature,omitzero"`
}

func (a AttestationDecision) BindingDigest() string {
	a.Signature = SignatureEnvelope{}
	a.SignatureVerified = false
	data, err := json.Marshal(a)
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

type KeyReleaseDecision struct {
	Provider              string            `json:"provider,omitempty"`
	DecisionID            string            `json:"decision_id,omitempty"`
	AttestationDecisionID string            `json:"attestation_decision_id,omitempty"`
	AttestationDigest     string            `json:"attestation_digest,omitempty"`
	AttestationProvider   string            `json:"attestation_provider,omitempty"`
	AttestationVerifierID string            `json:"attestation_verifier_id,omitempty"`
	AttestationKeyID      string            `json:"attestation_key_id,omitempty"`
	PolicyID              string            `json:"policy_id,omitempty"`
	TaskID                string            `json:"task_id,omitempty"`
	TaskHash              string            `json:"task_hash,omitempty"`
	InputHash             string            `json:"input_hash,omitempty"`
	DependencyClosureHash string            `json:"dependency_closure_hash,omitempty"`
	WorkerID              string            `json:"worker_id,omitempty"`
	PoolID                string            `json:"pool_id,omitempty"`
	KeyRefHash            string            `json:"key_ref_hash,omitempty"`
	Released              bool              `json:"released,omitempty"`
	ExpiresAt             time.Time         `json:"expires_at,omitzero"`
	Signature             SignatureEnvelope `json:"signature,omitzero"`
}

type AttestedProofBinding struct {
	Executor              ExecutorRef    `json:"executor"`
	PolicyID              string         `json:"policy_id"`
	TaskID                string         `json:"task_id"`
	TaskHash              string         `json:"task_hash"`
	InputHash             string         `json:"input_hash"`
	DependencyClosureHash string         `json:"dependency_closure_hash"`
	WorkerID              string         `json:"worker_id"`
	PoolID                string         `json:"pool_id"`
	StartedAt             time.Time      `json:"started_at"`
	FinishedAt            time.Time      `json:"finished_at"`
	Verifier              VerifierResult `json:"verifier"`
}

type AttestedServiceBinding struct {
	Executor       ExecutorRef    `json:"executor"`
	PolicyID       string         `json:"policy_id"`
	TaskID         string         `json:"task_id"`
	DeploymentHash string         `json:"deployment_hash"`
	WorkerID       string         `json:"worker_id"`
	PoolID         string         `json:"pool_id"`
	StartedAt      time.Time      `json:"started_at"`
	FinishedAt     time.Time      `json:"finished_at"`
	Verifier       VerifierResult `json:"verifier"`
}

func ValidateAttestedProofBinding(binding AttestedProofBinding) error {
	var errs []error
	require := func(name, value string) {
		if value == "" {
			errs = append(errs, fmt.Errorf("%s is required", name))
		}
	}

	if err := binding.Executor.ValidateForProof(); err != nil {
		errs = append(errs, err)
	}
	require("verifier.provider", binding.Verifier.Provider)
	if binding.Verifier.Status != VerificationAccepted {
		errs = append(errs, fmt.Errorf("verifier.status must be %q", VerificationAccepted))
	}

	attestation := binding.Verifier.Attestation
	require("verifier.attestation.provider", attestation.Provider)
	require("verifier.attestation.verifier_id", attestation.VerifierID)
	require("verifier.attestation.decision_id", attestation.DecisionID)
	require("verifier.attestation.hardware_class", attestation.HardwareClass)
	require("verifier.attestation.executor_image_digest", attestation.ExecutorImageDigest)
	require("verifier.attestation.executor_rootfs_digest", attestation.ExecutorRootFSDigest)
	require("verifier.attestation.policy_id", attestation.PolicyID)
	require("verifier.attestation.nonce", attestation.Nonce)
	if err := validateVerifiedSignature("verifier.attestation.signature", attestation.Signature); err != nil {
		errs = append(errs, err)
	}
	if !attestation.SignatureVerified {
		errs = append(errs, errors.New("verifier.attestation.signature_verified is required"))
	}
	if attestation.IssuedAt.IsZero() {
		errs = append(errs, errors.New("verifier.attestation.issued_at is required"))
	}
	if attestation.ExpiresAt.IsZero() {
		errs = append(errs, errors.New("verifier.attestation.expires_at is required"))
	}
	if !attestation.IssuedAt.IsZero() && !attestation.ExpiresAt.IsZero() && !attestation.ExpiresAt.After(attestation.IssuedAt) {
		errs = append(errs, errors.New("verifier.attestation.expires_at must be after issued_at"))
	}
	if attestation.PolicyID != "" && attestation.PolicyID != binding.PolicyID {
		errs = append(errs, errors.New("verifier.attestation.policy_id must match receipt policy_id"))
	}
	if attestation.HardwareClass != "" && attestation.HardwareClass != string(binding.Executor.ExecutionSecurityTier) {
		errs = append(errs, errors.New("verifier.attestation.hardware_class must match executor.execution_security_tier"))
	}
	if attestation.ExecutorImageDigest != "" && attestation.ExecutorImageDigest != binding.Executor.ImageDigest {
		errs = append(errs, errors.New("verifier.attestation.executor_image_digest must match executor.image_digest"))
	}
	if attestation.ExecutorRootFSDigest != "" && attestation.ExecutorRootFSDigest != binding.Executor.RootFSDigest {
		errs = append(errs, errors.New("verifier.attestation.executor_rootfs_digest must match executor.rootfs_digest"))
	}
	if binding.Executor.ExecutionSecurityTier == ExecutionConfidentialGPU && !attestation.ConfidentialGPU {
		errs = append(errs, errors.New("verifier.attestation.confidential_gpu is required for confidential GPU execution"))
	}

	keyRelease := binding.Verifier.KeyRelease
	require("verifier.key_release.provider", keyRelease.Provider)
	require("verifier.key_release.decision_id", keyRelease.DecisionID)
	require("verifier.key_release.attestation_decision_id", keyRelease.AttestationDecisionID)
	require("verifier.key_release.attestation_digest", keyRelease.AttestationDigest)
	require("verifier.key_release.attestation_provider", keyRelease.AttestationProvider)
	require("verifier.key_release.attestation_verifier_id", keyRelease.AttestationVerifierID)
	require("verifier.key_release.attestation_key_id", keyRelease.AttestationKeyID)
	require("verifier.key_release.policy_id", keyRelease.PolicyID)
	require("verifier.key_release.task_id", keyRelease.TaskID)
	require("verifier.key_release.task_hash", keyRelease.TaskHash)
	require("verifier.key_release.input_hash", keyRelease.InputHash)
	require("verifier.key_release.dependency_closure_hash", keyRelease.DependencyClosureHash)
	require("verifier.key_release.worker_id", keyRelease.WorkerID)
	require("verifier.key_release.pool_id", keyRelease.PoolID)
	require("verifier.key_release.key_ref_hash", keyRelease.KeyRefHash)
	if err := validateVerifiedSignature("verifier.key_release.signature", keyRelease.Signature); err != nil {
		errs = append(errs, err)
	}
	if !keyRelease.Released {
		errs = append(errs, errors.New("verifier.key_release.released is required"))
	}
	if keyRelease.ExpiresAt.IsZero() {
		errs = append(errs, errors.New("verifier.key_release.expires_at is required"))
	}
	if keyRelease.AttestationDecisionID != "" && attestation.DecisionID != "" && keyRelease.AttestationDecisionID != attestation.DecisionID {
		errs = append(errs, errors.New("verifier.key_release.attestation_decision_id must match verifier.attestation.decision_id"))
	}
	if keyRelease.AttestationDigest != "" && keyRelease.AttestationDigest != attestation.BindingDigest() {
		errs = append(errs, errors.New("verifier.key_release.attestation_digest must match verifier.attestation digest"))
	}
	if keyRelease.AttestationProvider != "" && keyRelease.AttestationProvider != attestation.Provider {
		errs = append(errs, errors.New("verifier.key_release.attestation_provider must match verifier.attestation.provider"))
	}
	if keyRelease.AttestationVerifierID != "" && keyRelease.AttestationVerifierID != attestation.VerifierID {
		errs = append(errs, errors.New("verifier.key_release.attestation_verifier_id must match verifier.attestation.verifier_id"))
	}
	if keyRelease.AttestationKeyID != "" && keyRelease.AttestationKeyID != attestation.Signature.KeyID {
		errs = append(errs, errors.New("verifier.key_release.attestation_key_id must match verifier.attestation.signature.key_id"))
	}
	if keyRelease.PolicyID != "" && keyRelease.PolicyID != binding.PolicyID {
		errs = append(errs, errors.New("verifier.key_release.policy_id must match receipt policy_id"))
	}
	if keyRelease.TaskID != "" && keyRelease.TaskID != binding.TaskID {
		errs = append(errs, errors.New("verifier.key_release.task_id must match receipt task_id"))
	}
	if keyRelease.TaskHash != "" && keyRelease.TaskHash != binding.TaskHash {
		errs = append(errs, errors.New("verifier.key_release.task_hash must match receipt task_hash"))
	}
	if keyRelease.InputHash != "" && keyRelease.InputHash != binding.InputHash {
		errs = append(errs, errors.New("verifier.key_release.input_hash must match receipt input_hash"))
	}
	if keyRelease.DependencyClosureHash != "" && keyRelease.DependencyClosureHash != binding.DependencyClosureHash {
		errs = append(errs, errors.New("verifier.key_release.dependency_closure_hash must match receipt dependency_closure_hash"))
	}
	if keyRelease.WorkerID != "" && keyRelease.WorkerID != binding.WorkerID {
		errs = append(errs, errors.New("verifier.key_release.worker_id must match receipt worker_id"))
	}
	if keyRelease.PoolID != "" && keyRelease.PoolID != binding.PoolID {
		errs = append(errs, errors.New("verifier.key_release.pool_id must match receipt pool_id"))
	}
	if !keyRelease.ExpiresAt.IsZero() && !attestation.ExpiresAt.IsZero() && keyRelease.ExpiresAt.After(attestation.ExpiresAt) {
		errs = append(errs, errors.New("verifier.key_release.expires_at must not exceed verifier.attestation.expires_at"))
	}
	if !binding.StartedAt.IsZero() && !attestation.IssuedAt.IsZero() && binding.StartedAt.Before(attestation.IssuedAt) {
		errs = append(errs, errors.New("started_at must not precede verifier.attestation.issued_at"))
	}
	if !binding.FinishedAt.IsZero() && !attestation.ExpiresAt.IsZero() && binding.FinishedAt.After(attestation.ExpiresAt) {
		errs = append(errs, errors.New("finished_at must not exceed verifier.attestation.expires_at"))
	}
	if !binding.FinishedAt.IsZero() && !keyRelease.ExpiresAt.IsZero() && binding.FinishedAt.After(keyRelease.ExpiresAt) {
		errs = append(errs, errors.New("finished_at must not exceed verifier.key_release.expires_at"))
	}

	return errors.Join(errs...)
}

func ValidateAttestedServiceBinding(binding AttestedServiceBinding) error {
	var errs []error
	require := func(name, value string) {
		if value == "" {
			errs = append(errs, fmt.Errorf("%s is required", name))
		}
	}

	if err := binding.Executor.ValidateForProof(); err != nil {
		errs = append(errs, err)
	}
	require("verifier.provider", binding.Verifier.Provider)
	if binding.Verifier.Status != VerificationAccepted {
		errs = append(errs, fmt.Errorf("verifier.status must be %q", VerificationAccepted))
	}

	attestation := binding.Verifier.Attestation
	require("verifier.attestation.provider", attestation.Provider)
	require("verifier.attestation.verifier_id", attestation.VerifierID)
	require("verifier.attestation.decision_id", attestation.DecisionID)
	require("verifier.attestation.hardware_class", attestation.HardwareClass)
	require("verifier.attestation.executor_image_digest", attestation.ExecutorImageDigest)
	require("verifier.attestation.executor_rootfs_digest", attestation.ExecutorRootFSDigest)
	require("verifier.attestation.policy_id", attestation.PolicyID)
	if err := validateVerifiedSignature("verifier.attestation.signature", attestation.Signature); err != nil {
		errs = append(errs, err)
	}
	if !attestation.SignatureVerified {
		errs = append(errs, errors.New("verifier.attestation.signature_verified is required"))
	}
	if attestation.PolicyID != "" && attestation.PolicyID != binding.PolicyID {
		errs = append(errs, errors.New("verifier.attestation.policy_id must match receipt policy_id"))
	}
	if attestation.HardwareClass != "" && attestation.HardwareClass != string(binding.Executor.ExecutionSecurityTier) {
		errs = append(errs, errors.New("verifier.attestation.hardware_class must match executor.execution_security_tier"))
	}
	if attestation.ExecutorImageDigest != "" && attestation.ExecutorImageDigest != binding.Executor.ImageDigest {
		errs = append(errs, errors.New("verifier.attestation.executor_image_digest must match executor.image_digest"))
	}
	if attestation.ExecutorRootFSDigest != "" && attestation.ExecutorRootFSDigest != binding.Executor.RootFSDigest {
		errs = append(errs, errors.New("verifier.attestation.executor_rootfs_digest must match executor.rootfs_digest"))
	}
	if binding.Executor.ExecutionSecurityTier == ExecutionConfidentialGPU && !attestation.ConfidentialGPU {
		errs = append(errs, errors.New("verifier.attestation.confidential_gpu is required for confidential GPU execution"))
	}

	keyRelease := binding.Verifier.KeyRelease
	require("verifier.key_release.decision_id", keyRelease.DecisionID)
	require("verifier.key_release.attestation_decision_id", keyRelease.AttestationDecisionID)
	require("verifier.key_release.attestation_digest", keyRelease.AttestationDigest)
	require("verifier.key_release.key_ref_hash", keyRelease.KeyRefHash)
	if err := validateVerifiedSignature("verifier.key_release.signature", keyRelease.Signature); err != nil {
		errs = append(errs, err)
	}
	if !keyRelease.Released {
		errs = append(errs, errors.New("verifier.key_release.released is required"))
	}
	if keyRelease.AttestationDecisionID != "" && attestation.DecisionID != "" && keyRelease.AttestationDecisionID != attestation.DecisionID {
		errs = append(errs, errors.New("verifier.key_release.attestation_decision_id must match verifier.attestation.decision_id"))
	}
	if keyRelease.AttestationDigest != "" && keyRelease.AttestationDigest != attestation.BindingDigest() {
		errs = append(errs, errors.New("verifier.key_release.attestation_digest must match verifier.attestation digest"))
	}
	if keyRelease.PolicyID != "" && keyRelease.PolicyID != binding.PolicyID {
		errs = append(errs, errors.New("verifier.key_release.policy_id must match receipt policy_id"))
	}
	if keyRelease.TaskID != "" && keyRelease.TaskID != binding.TaskID {
		errs = append(errs, errors.New("verifier.key_release.task_id must match receipt task_id"))
	}
	if keyRelease.DependencyClosureHash != "" && keyRelease.DependencyClosureHash != binding.DeploymentHash {
		errs = append(errs, errors.New("verifier.key_release.dependency_closure_hash must match receipt deployment_hash"))
	}
	if keyRelease.WorkerID != "" && keyRelease.WorkerID != binding.WorkerID {
		errs = append(errs, errors.New("verifier.key_release.worker_id must match receipt worker_id"))
	}
	if keyRelease.PoolID != "" && keyRelease.PoolID != binding.PoolID {
		errs = append(errs, errors.New("verifier.key_release.pool_id must match receipt pool_id"))
	}
	if !keyRelease.ExpiresAt.IsZero() && !attestation.ExpiresAt.IsZero() && keyRelease.ExpiresAt.After(attestation.ExpiresAt) {
		errs = append(errs, errors.New("verifier.key_release.expires_at must not exceed verifier.attestation.expires_at"))
	}
	if !binding.StartedAt.IsZero() && !attestation.IssuedAt.IsZero() && binding.StartedAt.Before(attestation.IssuedAt) {
		errs = append(errs, errors.New("started_at must not precede verifier.attestation.issued_at"))
	}
	if !binding.FinishedAt.IsZero() && !attestation.ExpiresAt.IsZero() && binding.FinishedAt.After(attestation.ExpiresAt) {
		errs = append(errs, errors.New("finished_at must not exceed verifier.attestation.expires_at"))
	}
	if !binding.FinishedAt.IsZero() && !keyRelease.ExpiresAt.IsZero() && binding.FinishedAt.After(keyRelease.ExpiresAt) {
		errs = append(errs, errors.New("finished_at must not exceed verifier.key_release.expires_at"))
	}

	return errors.Join(errs...)
}

func validateVerifiedSignature(prefix string, sig SignatureEnvelope) error {
	var errs []error
	if sig.Algorithm == "" {
		errs = append(errs, fmt.Errorf("%s.algorithm is required", prefix))
	}
	if sig.KeyID == "" {
		errs = append(errs, fmt.Errorf("%s.key_id is required", prefix))
	}
	if sig.Value == "" {
		errs = append(errs, fmt.Errorf("%s.value is required", prefix))
	}
	if !sig.Verified {
		errs = append(errs, fmt.Errorf("%s.verified is required", prefix))
	}
	return errors.Join(errs...)
}

func ExecutorMatchesPlacementRequirements(executor ExecutorRef, req PlacementRequirements) bool {
	if req.ExecutorProvider != "" && executor.Provider != req.ExecutorProvider {
		return false
	}
	if req.ExecutionSecurityTier != "" && executor.ExecutionSecurityTier != req.ExecutionSecurityTier {
		return false
	}
	if req.ProofTier != "" && executor.ProofTier != req.ProofTier {
		return false
	}
	return true
}

type ExecutorCapabilities struct {
	Executors      []ExecutorRef           `json:"executors,omitempty"`
	ExecutionTiers []ExecutionSecurityTier `json:"execution_tiers,omitempty"`
}

type ProviderCapabilityStatus string

const (
	ProviderCapabilitySupported   ProviderCapabilityStatus = "supported"
	ProviderCapabilityDegraded    ProviderCapabilityStatus = "degraded"
	ProviderCapabilityUnsupported ProviderCapabilityStatus = "unsupported"
)

type ProviderCapabilityReport struct {
	Provider string                   `json:"provider"`
	Status   ProviderCapabilityStatus `json:"status"`
	Reason   string                   `json:"reason,omitempty"`
}

type HardwareAttestation struct {
	Class      string    `json:"class"`
	Provider   string    `json:"provider"`
	VerifierID string    `json:"verifier_id"`
	KeyID      string    `json:"key_id"`
	Verified   bool      `json:"verified"`
	ExpiresAt  time.Time `json:"expires_at,omitzero"`
}

type HardwareSecurityCapabilities struct {
	TEE                  []string              `json:"tee,omitempty"`
	HardwareClasses      []string              `json:"hardware_classes,omitempty"`
	HardwareAttestations []HardwareAttestation `json:"hardware_attestations,omitempty"`
}

type HardwarePlacementCapabilities struct {
	GPUCount int                          `json:"gpu_count,omitempty"`
	Security HardwareSecurityCapabilities `json:"security,omitzero"`
	Now      time.Time                    `json:"now,omitzero"`
}

type PlacementRequirementCapabilities struct {
	CapabilityTags    []string                   `json:"capability_tags,omitempty"`
	ExecutorProviders []string                   `json:"executor_providers,omitempty"`
	ExecutionTiers    []ExecutionSecurityTier    `json:"execution_tiers,omitempty"`
	ProofTiers        []ProofTier                `json:"proof_tiers,omitempty"`
	CapabilityReports []ProviderCapabilityReport `json:"capability_reports,omitempty"`
	Executors         []ExecutorRef              `json:"executors,omitempty"`
}

func ValidatePlacementRequirementsAgainstCapabilities(req PlacementRequirements, caps PlacementRequirementCapabilities) error {
	var errs []error
	workerCapabilityTags := map[string]struct{}{}
	for _, tag := range caps.CapabilityTags {
		workerCapabilityTags[tag] = struct{}{}
	}
	requiredCapabilityTags := map[string]struct{}{}
	for i, tag := range req.RequiredCapabilities {
		if err := validateIdentifier(fmt.Sprintf("task requirements required_capabilities[%d]", i), tag); err != nil {
			errs = append(errs, err)
			continue
		}
		if _, ok := requiredCapabilityTags[tag]; ok {
			errs = append(errs, fmt.Errorf("task requirements required_capabilities[%d] %q is duplicated", i, tag))
		}
		requiredCapabilityTags[tag] = struct{}{}
		if _, ok := workerCapabilityTags[tag]; !ok {
			errs = append(errs, fmt.Errorf("worker missing required capability %q", tag))
		}
	}
	if req.ExecutionSecurityTier != "" && !validExecutionSecurityTier(req.ExecutionSecurityTier) {
		errs = append(errs, fmt.Errorf("task requirements execution_security_tier %q is unknown", req.ExecutionSecurityTier))
	}
	if req.ProofTier != "" && !validProofTier(req.ProofTier) {
		errs = append(errs, fmt.Errorf("task requirements proof_tier %q is unknown", req.ProofTier))
	}
	if req.ExecutorProvider != "" && !contains(caps.ExecutorProviders, req.ExecutorProvider) {
		errs = append(errs, fmt.Errorf("worker does not support executor provider %q", req.ExecutorProvider))
	}
	if report, ok := providerCapabilityReportForProvider(caps.CapabilityReports, req.ExecutorProvider); ok && report.Status != ProviderCapabilitySupported {
		errs = append(errs, fmt.Errorf("worker executor provider %q is %s: %s", req.ExecutorProvider, report.Status, report.Reason))
	}
	if req.ExecutionSecurityTier != "" && !contains(caps.ExecutionTiers, req.ExecutionSecurityTier) {
		errs = append(errs, fmt.Errorf("worker does not support execution security tier %q", req.ExecutionSecurityTier))
	}
	if req.ProofTier != "" && !contains(caps.ProofTiers, req.ProofTier) {
		errs = append(errs, fmt.Errorf("worker does not support proof tier %q", req.ProofTier))
	}
	if len(caps.Executors) > 0 && !ExecutorCapabilitiesHaveSupportedMatch(req, caps) {
		errs = append(errs, errors.New("worker has no supported executor matching task placement requirements"))
	}
	return errors.Join(errs...)
}

func RequiredHardwareClass(req PlacementRequirements) string {
	if req.HardwareClass != "" {
		return req.HardwareClass
	}
	switch req.ExecutionSecurityTier {
	case ExecutionConfidentialCPU:
		return string(ExecutionConfidentialCPU)
	case ExecutionConfidentialGPU:
		return string(ExecutionConfidentialGPU)
	default:
		return ""
	}
}

func PlacementRequiresVerifiedHardwareAttestation(req PlacementRequirements) bool {
	return req.ExecutionSecurityTier == ExecutionConfidentialCPU || req.ExecutionSecurityTier == ExecutionConfidentialGPU
}

func HardwareCapabilitiesSatisfyPlacementRequirements(req PlacementRequirements, caps HardwarePlacementCapabilities) bool {
	class := RequiredHardwareClass(req)
	if class == "" {
		return true
	}
	if class == string(ExecutionConfidentialGPU) && caps.GPUCount == 0 {
		return false
	}
	requireVerified := PlacementRequiresVerifiedHardwareAttestation(req) ||
		class == string(ExecutionConfidentialCPU) ||
		class == string(ExecutionConfidentialGPU)
	if requireVerified {
		now := caps.Now
		if now.IsZero() {
			now = time.Now().UTC()
		}
		for _, attestation := range caps.Security.HardwareAttestations {
			if attestation.Class == class &&
				attestation.Provider != "" &&
				attestation.VerifierID != "" &&
				attestation.KeyID != "" &&
				attestation.Verified &&
				(attestation.ExpiresAt.IsZero() || attestation.ExpiresAt.After(now)) {
				return true
			}
		}
		return false
	}
	return contains(caps.Security.HardwareClasses, class) || contains(caps.Security.TEE, class)
}

func ExecutorCapabilitiesHaveSupportedMatch(req PlacementRequirements, caps PlacementRequirementCapabilities) bool {
	for _, executor := range caps.Executors {
		if ExecutorMatchesPlacementRequirements(executor, req) {
			report, ok := providerCapabilityReportForProvider(caps.CapabilityReports, executor.Provider)
			if !ok || report.Status == ProviderCapabilitySupported {
				return true
			}
		}
	}
	return false
}

func providerCapabilityReportForProvider(reports []ProviderCapabilityReport, provider string) (ProviderCapabilityReport, bool) {
	if provider == "" {
		return ProviderCapabilityReport{}, false
	}
	for _, report := range reports {
		if report.Provider == provider {
			return report, true
		}
	}
	return ProviderCapabilityReport{}, false
}

func ResourceLimitsRequireResourceConstrainedExecutor(limits ResourceLimits) bool {
	return limits.CPUPercent > 0 || limits.MemoryBytes > 0
}

func ExecutorCapabilitiesHaveResourceConstrainedMatch(req PlacementRequirements, caps ExecutorCapabilities) bool {
	if len(caps.Executors) == 0 {
		for _, tier := range caps.ExecutionTiers {
			if ExecutionTierSupportsResourceLimits(tier) {
				return true
			}
		}
		return false
	}
	for _, executor := range caps.Executors {
		if !ExecutorMatchesPlacementRequirements(executor, req) {
			continue
		}
		if ExecutionTierSupportsResourceLimits(executor.ExecutionSecurityTier) {
			return true
		}
	}
	return false
}

func ExecutionTierSupportsResourceLimits(tier ExecutionSecurityTier) bool {
	switch tier {
	case ExecutionHardenedContainer,
		ExecutionSandboxedContainer,
		ExecutionMicroVM,
		ExecutionConfidentialCPU,
		ExecutionConfidentialGPU,
		ExecutionWASMCapability:
		return true
	default:
		return false
	}
}

type ResourceUsage struct {
	CPUMillis      int64  `json:"cpu_millis,omitempty"`
	GPUMillis      int64  `json:"gpu_millis,omitempty"`
	MaxMemoryBytes int64  `json:"max_memory_bytes,omitempty"`
	NetworkRxBytes int64  `json:"network_rx_bytes,omitempty"`
	NetworkTxBytes int64  `json:"network_tx_bytes,omitempty"`
	WorkspaceBytes int64  `json:"workspace_bytes,omitempty"`
	OutputBytes    int64  `json:"output_bytes,omitempty"`
	LimitHit       string `json:"limit_hit,omitempty"`
}

const NetworkAuditMaxLabels = 32

const NetworkAuditRefKeyEpoch = "network-audit-ref-v1"

type NetworkAuditDestinationKind string

const (
	NetworkAuditDestinationEndpoint  NetworkAuditDestinationKind = "endpoint"
	NetworkAuditDestinationSHA256    NetworkAuditDestinationKind = "sha256"
	NetworkAuditDestinationArtifact  NetworkAuditDestinationKind = "artifact"
	NetworkAuditDestinationLifecycle NetworkAuditDestinationKind = "network-lifecycle"
)

type NetworkAuditValidationCode string

const (
	NetworkAuditValidationProtocolVersionInvalid NetworkAuditValidationCode = "protocol_version_invalid"
	NetworkAuditValidationRecordIDRequired       NetworkAuditValidationCode = "record_id_required"
	NetworkAuditValidationDestinationRequired    NetworkAuditValidationCode = "destination_required"
	NetworkAuditValidationDestinationInvalid     NetworkAuditValidationCode = "destination_invalid"
	NetworkAuditValidationResourceUsageInvalid   NetworkAuditValidationCode = "resource_usage_invalid"
	NetworkAuditValidationLabelInvalid           NetworkAuditValidationCode = "label_invalid"
	NetworkAuditValidationLabelCountExceeded     NetworkAuditValidationCode = "label_count_exceeded"
	NetworkAuditValidationTimeRangeInvalid       NetworkAuditValidationCode = "time_range_invalid"
	NetworkAuditValidationProviderInvalid        NetworkAuditValidationCode = "provider_invalid"
)

type NetworkAuditValidationIssue struct {
	Code    NetworkAuditValidationCode `json:"code"`
	Field   string                     `json:"field"`
	Message string                     `json:"message"`
}

type NetworkAuditValidationError struct {
	Issues []NetworkAuditValidationIssue
}

func (e NetworkAuditValidationError) Error() string {
	if len(e.Issues) == 0 {
		return "network audit validation failed"
	}
	return fmt.Sprintf("network audit validation failed with %d issue(s)", len(e.Issues))
}

type NetworkAuditDestination struct {
	Kind  NetworkAuditDestinationKind `json:"kind"`
	Value string                      `json:"value"`
}

type NetworkAuditProviderEvidence struct {
	ProviderID       string `json:"provider_id,omitempty"`
	PluginName       string `json:"plugin_name,omitempty"`
	PluginVersion    string `json:"plugin_version,omitempty"`
	ContractID       string `json:"contract_id,omitempty"`
	ContractVersion  string `json:"contract_version,omitempty"`
	DescriptorDigest string `json:"descriptor_digest,omitempty"`
}

type NetworkAuditRefStability string

const (
	NetworkAuditRefStable    NetworkAuditRefStability = "stable"
	NetworkAuditRefEphemeral NetworkAuditRefStability = "ephemeral"
)

type NetworkAuditRefOptions struct {
	Stability NetworkAuditRefStability
	Timestamp time.Time
}

type NetworkAuditRefProjection struct {
	Ref       string                   `json:"ref"`
	Epoch     string                   `json:"epoch"`
	Stability NetworkAuditRefStability `json:"stability"`
	Timestamp string                   `json:"timestamp"`
}

type NetworkAuditRefProjector struct {
	key []byte
}

type NetworkAuditRecord struct {
	ProtocolVersion string                       `json:"protocol_version"`
	RecordID        string                       `json:"record_id"`
	TaskID          string                       `json:"task_id,omitempty"`
	LeaseID         string                       `json:"lease_id,omitempty"`
	WorkerID        string                       `json:"worker_id,omitempty"`
	Provider        NetworkAuditProviderEvidence `json:"provider,omitempty"`
	Destination     NetworkAuditDestination      `json:"destination"`
	ResourceUsage   ResourceUsage                `json:"resource_usage,omitempty"`
	Labels          map[string]string            `json:"labels,omitempty"`
	StartedAt       time.Time                    `json:"started_at,omitempty"`
	FinishedAt      time.Time                    `json:"finished_at,omitempty"`
	ObservedAt      time.Time                    `json:"observed_at,omitempty"`
}

func ProjectNetworkAuditDestination(raw string) (NetworkAuditDestination, []NetworkAuditValidationIssue) {
	value := strings.TrimSpace(raw)
	var kind NetworkAuditDestinationKind
	switch {
	case strings.HasPrefix(value, "sha256:"):
		kind = NetworkAuditDestinationSHA256
	case strings.HasPrefix(value, "artifact://"):
		kind = NetworkAuditDestinationArtifact
	case strings.HasPrefix(value, "network-lifecycle://"):
		kind = NetworkAuditDestinationLifecycle
	default:
		kind = NetworkAuditDestinationEndpoint
	}
	destination := NetworkAuditDestination{Kind: kind, Value: value}
	return destination, destination.validateNetworkAudit()
}

func ProjectNetworkAuditLifecycle(leaseID, event string) (NetworkAuditDestination, []NetworkAuditValidationIssue) {
	destination, err := NewNetworkAuditLifecycleDestination(leaseID, event)
	if err != nil {
		return NetworkAuditDestination{}, []NetworkAuditValidationIssue{
			networkAuditIssue(NetworkAuditValidationDestinationInvalid, "destination", "lifecycle destination is invalid"),
		}
	}
	return destination, nil
}

func NewNetworkAuditLifecycleDestination(leaseID, event string) (NetworkAuditDestination, error) {
	if err := validateIdentifier("lease_id", leaseID); err != nil {
		return NetworkAuditDestination{}, err
	}
	if err := validateIdentifier("event", event); err != nil {
		return NetworkAuditDestination{}, err
	}
	destination := NetworkAuditDestination{
		Kind:  NetworkAuditDestinationLifecycle,
		Value: "network-lifecycle://" + leaseID + "/" + event,
	}
	if issues := destination.validateNetworkAudit(); len(issues) != 0 {
		return NetworkAuditDestination{}, NetworkAuditValidationError{Issues: issues}
	}
	return destination, nil
}

func ProjectNetworkAuditLabels(labels map[string]string) (map[string]string, []NetworkAuditValidationIssue) {
	projected := copyStringMap(labels)
	return projected, validateNetworkAuditLabels(projected)
}

func ProjectNetworkAuditProvider(providerID, pluginName, pluginVersion, contractID, contractVersion, descriptorDigest string) (NetworkAuditProviderEvidence, []NetworkAuditValidationIssue) {
	provider := NetworkAuditProviderEvidence{
		ProviderID:       strings.TrimSpace(providerID),
		PluginName:       strings.TrimSpace(pluginName),
		PluginVersion:    strings.TrimSpace(pluginVersion),
		ContractID:       strings.TrimSpace(contractID),
		ContractVersion:  strings.TrimSpace(contractVersion),
		DescriptorDigest: strings.TrimSpace(descriptorDigest),
	}
	return provider, provider.validateNetworkAudit()
}

func ProjectNetworkAuditID(components ...string) (string, error) {
	if len(components) == 0 {
		return "", errors.New("at least one network audit id component is required")
	}
	hash := sha256.New()
	for _, component := range components {
		if strings.TrimSpace(component) == "" || strings.ContainsAny(component, "\x00\r\n\t") {
			return "", errors.New("network audit id component is invalid")
		}
		fmt.Fprintf(hash, "%d:", len(component))
		_, _ = hash.Write([]byte(component))
		_, _ = hash.Write([]byte{0})
	}
	return "network-audit-sha256-" + hex.EncodeToString(hash.Sum(nil)), nil
}

func NewNetworkAuditRefProjector(key []byte) (NetworkAuditRefProjector, error) {
	if len(key) < 32 {
		return NetworkAuditRefProjector{}, errors.New("network audit ref key must be at least 32 bytes")
	}
	copied := make([]byte, len(key))
	copy(copied, key)
	return NetworkAuditRefProjector{key: copied}, nil
}

func (p NetworkAuditRefProjector) Project(record NetworkAuditRecord, options NetworkAuditRefOptions) (NetworkAuditRefProjection, error) {
	if len(p.key) < 32 {
		return NetworkAuditRefProjection{}, errors.New("network audit ref projector key is invalid")
	}
	if err := record.Validate(); err != nil {
		return NetworkAuditRefProjection{}, err
	}
	stability := options.Stability
	if stability == "" {
		stability = NetworkAuditRefStable
	}
	switch stability {
	case NetworkAuditRefStable, NetworkAuditRefEphemeral:
	default:
		return NetworkAuditRefProjection{}, errors.New("network audit ref stability is invalid")
	}
	timestamp := options.Timestamp
	if timestamp.IsZero() {
		timestamp = record.StartedAt
	}
	if timestamp.IsZero() {
		timestamp = record.ObservedAt
	}
	if timestamp.IsZero() {
		timestamp = record.FinishedAt
	}
	normalizedTimestamp := timestamp.UTC().Format(time.RFC3339Nano)
	normalizedRecord := record
	normalizedRecord.StartedAt = normalizedRecord.StartedAt.UTC()
	normalizedRecord.FinishedAt = normalizedRecord.FinishedAt.UTC()
	normalizedRecord.ObservedAt = normalizedRecord.ObservedAt.UTC()
	recordDigest := CanonicalHash(normalizedRecord)
	input := strings.Join([]string{
		NetworkAuditRefKeyEpoch,
		string(stability),
		recordDigest,
		normalizedTimestamp,
		"",
	}, "\n")
	mac := hmac.New(sha256.New, p.key)
	_, _ = mac.Write([]byte(input))
	ref := NetworkAuditRefKeyEpoch + ":" + string(stability) + ":" + hex.EncodeToString(mac.Sum(nil))
	return NetworkAuditRefProjection{
		Ref:       ref,
		Epoch:     NetworkAuditRefKeyEpoch,
		Stability: stability,
		Timestamp: normalizedTimestamp,
	}, nil
}

func ClassifyLegacyNetworkAuditRecord(record map[string]any) []NetworkAuditValidationIssue {
	var findings []NetworkAuditValidationIssue
	if rawDestination, ok := record["destination"].(string); ok {
		_, issues := ProjectNetworkAuditDestination(rawDestination)
		findings = append(findings, issues...)
	}
	if rawLabels, ok := record["labels"].(map[string]any); ok {
		labels := make(map[string]string, len(rawLabels))
		for key, value := range rawLabels {
			stringValue, ok := value.(string)
			if !ok {
				findings = append(findings, networkAuditIssue(NetworkAuditValidationLabelInvalid, "labels", "label value is invalid"))
				continue
			}
			labels[key] = stringValue
		}
		_, issues := ProjectNetworkAuditLabels(labels)
		findings = append(findings, issues...)
	}
	if rawUsage, ok := record["resource_usage"].(map[string]any); ok {
		usage := ResourceUsage{
			CPUMillis:      legacyInt64(rawUsage["cpu_millis"]),
			GPUMillis:      legacyInt64(rawUsage["gpu_millis"]),
			MaxMemoryBytes: legacyInt64(rawUsage["max_memory_bytes"]),
			NetworkRxBytes: legacyInt64(rawUsage["network_rx_bytes"]),
			NetworkTxBytes: legacyInt64(rawUsage["network_tx_bytes"]),
			WorkspaceBytes: legacyInt64(rawUsage["workspace_bytes"]),
			OutputBytes:    legacyInt64(rawUsage["output_bytes"]),
		}
		if err := validateNetworkAuditResourceUsage(usage); err != nil {
			findings = append(findings, networkAuditIssue(NetworkAuditValidationResourceUsageInvalid, "resource_usage", "resource usage contains invalid counters"))
		}
	}
	return findings
}

func legacyInt64(value any) int64 {
	switch typed := value.(type) {
	case int:
		return int64(typed)
	case int8:
		return int64(typed)
	case int16:
		return int64(typed)
	case int32:
		return int64(typed)
	case int64:
		return typed
	case float64:
		return int64(typed)
	case json.Number:
		converted, _ := typed.Int64()
		return converted
	default:
		return 0
	}
}

func (r NetworkAuditRecord) Validate() error {
	issues := r.ValidateNetworkAudit()
	if len(issues) == 0 {
		return nil
	}
	return NetworkAuditValidationError{Issues: issues}
}

func (r NetworkAuditRecord) ValidateNetworkAudit() []NetworkAuditValidationIssue {
	var issues []NetworkAuditValidationIssue
	if r.ProtocolVersion != NetworkAuditProtocolVersion {
		issues = append(issues, networkAuditIssue(NetworkAuditValidationProtocolVersionInvalid, "protocol_version", "protocol version is not supported"))
	}
	if err := validateIdentifier("record_id", r.RecordID); err != nil {
		issues = append(issues, networkAuditIssue(NetworkAuditValidationRecordIDRequired, "record_id", "record id is required"))
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{"task_id", r.TaskID},
		{"lease_id", r.LeaseID},
		{"worker_id", r.WorkerID},
	} {
		if field.value != "" {
			if err := validateIdentifier(field.name, field.value); err != nil {
				issues = append(issues, networkAuditIssue(NetworkAuditValidationRecordIDRequired, field.name, "identifier is invalid"))
			}
		}
	}
	issues = append(issues, r.Provider.validateNetworkAudit()...)
	issues = append(issues, r.Destination.validateNetworkAudit()...)
	if err := validateNetworkAuditResourceUsage(r.ResourceUsage); err != nil {
		issues = append(issues, networkAuditIssue(NetworkAuditValidationResourceUsageInvalid, "resource_usage", "resource usage contains invalid counters"))
	}
	issues = append(issues, validateNetworkAuditLabels(r.Labels)...)
	if !r.StartedAt.IsZero() && !r.FinishedAt.IsZero() && r.FinishedAt.Before(r.StartedAt) {
		issues = append(issues, networkAuditIssue(NetworkAuditValidationTimeRangeInvalid, "finished_at", "finish time must not precede start time"))
	}
	if !r.FinishedAt.IsZero() && !r.ObservedAt.IsZero() && r.ObservedAt.Before(r.FinishedAt) {
		issues = append(issues, networkAuditIssue(NetworkAuditValidationTimeRangeInvalid, "observed_at", "observed time must not precede finish time"))
	}
	return issues
}

func (p NetworkAuditProviderEvidence) validateNetworkAudit() []NetworkAuditValidationIssue {
	var issues []NetworkAuditValidationIssue
	for _, field := range []struct {
		name  string
		value string
	}{
		{"provider_id", p.ProviderID},
		{"plugin_name", p.PluginName},
		{"plugin_version", p.PluginVersion},
		{"contract_id", p.ContractID},
		{"contract_version", p.ContractVersion},
	} {
		if field.value != "" {
			if err := validateIdentifier(field.name, field.value); err != nil {
				issues = append(issues, networkAuditIssue(NetworkAuditValidationProviderInvalid, field.name, "provider evidence identifier is invalid"))
			}
		}
	}
	if p.DescriptorDigest != "" && !validSHA256Digest(p.DescriptorDigest) {
		issues = append(issues, networkAuditIssue(NetworkAuditValidationProviderInvalid, "descriptor_digest", "descriptor digest is invalid"))
	}
	return issues
}

func (d NetworkAuditDestination) validateNetworkAudit() []NetworkAuditValidationIssue {
	if d.Kind == "" && strings.TrimSpace(d.Value) == "" {
		return []NetworkAuditValidationIssue{
			networkAuditIssue(NetworkAuditValidationDestinationRequired, "destination", "destination is required"),
		}
	}
	if !validNetworkAuditDestination(d) {
		return []NetworkAuditValidationIssue{
			networkAuditIssue(NetworkAuditValidationDestinationInvalid, "destination", "destination is invalid"),
		}
	}
	return nil
}

func validNetworkAuditDestination(d NetworkAuditDestination) bool {
	value := strings.TrimSpace(d.Value)
	if value == "" || value != d.Value || strings.ContainsAny(value, " \t\r\n\x00") {
		return false
	}
	switch d.Kind {
	case NetworkAuditDestinationEndpoint:
		return validNetworkAuditEndpoint(value)
	case NetworkAuditDestinationSHA256:
		return validSHA256Ref(value)
	case NetworkAuditDestinationArtifact:
		return validateScopedRef("destination", value, "artifact://") == nil && !strings.ContainsAny(value, "\t\r\n\x00")
	case NetworkAuditDestinationLifecycle:
		return validNetworkLifecycleRef(value)
	default:
		return false
	}
}

func validNetworkAuditEndpoint(value string) bool {
	parsed, err := url.Parse(value)
	if err != nil {
		return false
	}
	switch parsed.Scheme {
	case "http", "https", "tcp", "udp":
	default:
		return false
	}
	return parsed.Host != "" &&
		parsed.User == nil &&
		parsed.RawQuery == "" &&
		parsed.Fragment == "" &&
		!strings.Contains(parsed.Path, "..")
}

func validNetworkLifecycleRef(value string) bool {
	if !strings.HasPrefix(value, "network-lifecycle://") {
		return false
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return false
	}
	return parsed.Scheme == "network-lifecycle" &&
		parsed.Host != "" &&
		parsed.User == nil &&
		parsed.RawQuery == "" &&
		parsed.Fragment == "" &&
		parsed.Path != "" &&
		!strings.Contains(parsed.Path, "..") &&
		validateIdentifier("lease_id", parsed.Host) == nil &&
		validateIdentifier("event", strings.TrimPrefix(parsed.Path, "/")) == nil
}

func validateNetworkAuditResourceUsage(usage ResourceUsage) error {
	var errs []error
	for _, field := range []struct {
		name  string
		value int64
	}{
		{"cpu_millis", usage.CPUMillis},
		{"gpu_millis", usage.GPUMillis},
		{"max_memory_bytes", usage.MaxMemoryBytes},
		{"network_rx_bytes", usage.NetworkRxBytes},
		{"network_tx_bytes", usage.NetworkTxBytes},
		{"workspace_bytes", usage.WorkspaceBytes},
		{"output_bytes", usage.OutputBytes},
	} {
		if field.value < 0 {
			errs = append(errs, fmt.Errorf("%s cannot be negative", field.name))
		}
	}
	if usage.LimitHit != "" && (strings.TrimSpace(usage.LimitHit) != usage.LimitHit || strings.ContainsAny(usage.LimitHit, " \t\r\n/:?&#\x00")) {
		errs = append(errs, errors.New("limit_hit is invalid"))
	}
	return errors.Join(errs...)
}

func validateNetworkAuditLabels(labels map[string]string) []NetworkAuditValidationIssue {
	var issues []NetworkAuditValidationIssue
	if len(labels) > NetworkAuditMaxLabels {
		issues = append(issues, networkAuditIssue(NetworkAuditValidationLabelCountExceeded, "labels", "label count exceeds limit"))
	}
	for key, value := range labels {
		if err := validateIdentifier("label", key); err != nil {
			issues = append(issues, networkAuditIssue(NetworkAuditValidationLabelInvalid, "labels", "label key is invalid"))
		}
		if value == "" || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\t\r\n\x00") {
			issues = append(issues, networkAuditIssue(NetworkAuditValidationLabelInvalid, "labels", "label value is invalid"))
		}
	}
	return issues
}

func networkAuditIssue(code NetworkAuditValidationCode, field, message string) NetworkAuditValidationIssue {
	return NetworkAuditValidationIssue{
		Code:    code,
		Field:   field,
		Message: message,
	}
}

func (r NetworkAuditRecord) ToProto() *pb.NetworkAuditRecord {
	return &pb.NetworkAuditRecord{
		ProtocolVersion:    r.ProtocolVersion,
		RecordId:           r.RecordID,
		TaskId:             r.TaskID,
		LeaseId:            r.LeaseID,
		WorkerId:           r.WorkerID,
		Provider:           r.Provider.toProto(),
		Destination:        r.Destination.toProto(),
		ResourceUsage:      networkAuditResourceUsageToProto(r.ResourceUsage),
		Labels:             copyStringMap(r.Labels),
		StartedAtUnixNano:  unixNanoOrZero(r.StartedAt),
		FinishedAtUnixNano: unixNanoOrZero(r.FinishedAt),
		ObservedAtUnixNano: unixNanoOrZero(r.ObservedAt),
	}
}

func NetworkAuditRecordFromProto(message *pb.NetworkAuditRecord) (NetworkAuditRecord, error) {
	if message == nil {
		return NetworkAuditRecord{}, NetworkAuditValidationError{Issues: []NetworkAuditValidationIssue{
			networkAuditIssue(NetworkAuditValidationRecordIDRequired, "record", "record is required"),
		}}
	}
	if message.GetStartedAtUnixNano() < 0 || message.GetFinishedAtUnixNano() < 0 || message.GetObservedAtUnixNano() < 0 {
		return NetworkAuditRecord{}, NetworkAuditValidationError{Issues: []NetworkAuditValidationIssue{
			networkAuditIssue(NetworkAuditValidationTimeRangeInvalid, "timestamp", "timestamp must not be negative"),
		}}
	}
	record := NetworkAuditRecord{
		ProtocolVersion: message.GetProtocolVersion(),
		RecordID:        message.GetRecordId(),
		TaskID:          message.GetTaskId(),
		LeaseID:         message.GetLeaseId(),
		WorkerID:        message.GetWorkerId(),
		Provider:        networkAuditProviderFromProto(message.GetProvider()),
		Destination:     networkAuditDestinationFromProto(message.GetDestination()),
		ResourceUsage:   networkAuditResourceUsageFromProto(message.GetResourceUsage()),
		Labels:          copyStringMap(message.GetLabels()),
		StartedAt:       timeFromUnixNano(message.GetStartedAtUnixNano()),
		FinishedAt:      timeFromUnixNano(message.GetFinishedAtUnixNano()),
		ObservedAt:      timeFromUnixNano(message.GetObservedAtUnixNano()),
	}
	if err := record.Validate(); err != nil {
		return NetworkAuditRecord{}, err
	}
	return record, nil
}

func UnmarshalNetworkAuditRecordProtoStrict(data []byte) (*pb.NetworkAuditRecord, error) {
	var message pb.NetworkAuditRecord
	if err := (proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(data, &message); err != nil {
		return nil, err
	}
	if err := rejectUnknownProtoFields(&message); err != nil {
		return nil, err
	}
	return &message, nil
}

func rejectUnknownProtoFields(message proto.Message) error {
	if message == nil {
		return nil
	}
	reflected := message.ProtoReflect()
	if len(reflected.GetUnknown()) != 0 {
		return fmt.Errorf("proto message %s contains unknown fields", reflected.Descriptor().FullName())
	}
	var err error
	reflected.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		if field.IsMap() {
			if field.MapValue().Message() == nil {
				return true
			}
			value.Map().Range(func(_ protoreflect.MapKey, mapValue protoreflect.Value) bool {
				if nestedErr := rejectUnknownProtoFields(mapValue.Message().Interface()); nestedErr != nil {
					err = nestedErr
					return false
				}
				return true
			})
			return err == nil
		}
		if field.IsList() && field.Message() != nil {
			list := value.List()
			for i := range list.Len() {
				if nestedErr := rejectUnknownProtoFields(list.Get(i).Message().Interface()); nestedErr != nil {
					err = nestedErr
					return false
				}
			}
			return true
		}
		if field.Message() != nil {
			if nestedErr := rejectUnknownProtoFields(value.Message().Interface()); nestedErr != nil {
				err = nestedErr
				return false
			}
		}
		return true
	})
	return err
}

func (p NetworkAuditProviderEvidence) toProto() *pb.NetworkAuditProviderEvidence {
	return &pb.NetworkAuditProviderEvidence{
		ProviderId:       p.ProviderID,
		PluginName:       p.PluginName,
		PluginVersion:    p.PluginVersion,
		ContractId:       p.ContractID,
		ContractVersion:  p.ContractVersion,
		DescriptorDigest: p.DescriptorDigest,
	}
}

func networkAuditProviderFromProto(message *pb.NetworkAuditProviderEvidence) NetworkAuditProviderEvidence {
	if message == nil {
		return NetworkAuditProviderEvidence{}
	}
	return NetworkAuditProviderEvidence{
		ProviderID:       message.GetProviderId(),
		PluginName:       message.GetPluginName(),
		PluginVersion:    message.GetPluginVersion(),
		ContractID:       message.GetContractId(),
		ContractVersion:  message.GetContractVersion(),
		DescriptorDigest: message.GetDescriptorDigest(),
	}
}

func (d NetworkAuditDestination) toProto() *pb.NetworkAuditDestination {
	return &pb.NetworkAuditDestination{
		Kind:  string(d.Kind),
		Value: d.Value,
	}
}

func networkAuditDestinationFromProto(message *pb.NetworkAuditDestination) NetworkAuditDestination {
	if message == nil {
		return NetworkAuditDestination{}
	}
	return NetworkAuditDestination{
		Kind:  NetworkAuditDestinationKind(message.GetKind()),
		Value: message.GetValue(),
	}
}

func networkAuditResourceUsageToProto(usage ResourceUsage) *pb.NetworkAuditResourceUsage {
	return &pb.NetworkAuditResourceUsage{
		CpuMillis:      usage.CPUMillis,
		GpuMillis:      usage.GPUMillis,
		MaxMemoryBytes: usage.MaxMemoryBytes,
		NetworkRxBytes: usage.NetworkRxBytes,
		NetworkTxBytes: usage.NetworkTxBytes,
		WorkspaceBytes: usage.WorkspaceBytes,
		OutputBytes:    usage.OutputBytes,
		LimitHit:       usage.LimitHit,
	}
}

func networkAuditResourceUsageFromProto(message *pb.NetworkAuditResourceUsage) ResourceUsage {
	if message == nil {
		return ResourceUsage{}
	}
	return ResourceUsage{
		CPUMillis:      message.GetCpuMillis(),
		GPUMillis:      message.GetGpuMillis(),
		MaxMemoryBytes: message.GetMaxMemoryBytes(),
		NetworkRxBytes: message.GetNetworkRxBytes(),
		NetworkTxBytes: message.GetNetworkTxBytes(),
		WorkspaceBytes: message.GetWorkspaceBytes(),
		OutputBytes:    message.GetOutputBytes(),
		LimitHit:       message.GetLimitHit(),
	}
}

func unixNanoOrZero(value time.Time) int64 {
	if value.IsZero() {
		return 0
	}
	return value.UTC().UnixNano()
}

func timeFromUnixNano(value int64) time.Time {
	if value == 0 {
		return time.Time{}
	}
	return time.Unix(0, value).UTC()
}

func copyStringMap(input map[string]string) map[string]string {
	if len(input) == 0 {
		return nil
	}
	output := make(map[string]string, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}

func NetworkAuditDescriptorSet() *descriptorpb.FileDescriptorSet {
	return &descriptorpb.FileDescriptorSet{
		File: []*descriptorpb.FileDescriptorProto{
			protodesc.ToFileDescriptorProto(pb.File_workflow_plugin_compute_core_protocol_v1_network_audit_proto),
		},
	}
}

func NetworkAuditDescriptorDigest() string {
	data, err := (proto.MarshalOptions{Deterministic: true}).Marshal(NetworkAuditDescriptorSet())
	if err != nil {
		return CanonicalHash(pb.File_workflow_plugin_compute_core_protocol_v1_network_audit_proto.FullName())
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

type ResourceLimits struct {
	CPUPercent         int   `json:"cpu_percent,omitempty"`
	MemoryBytes        int64 `json:"memory_bytes,omitempty"`
	WorkspaceBytes     int64 `json:"workspace_bytes,omitempty"`
	RuntimeSeconds     int   `json:"runtime_seconds,omitempty"`
	NetworkEgressBytes int64 `json:"network_egress_bytes,omitempty"`
	OutputBytes        int64 `json:"output_bytes,omitempty"`
}

type ResourceCapacity struct {
	CPUCount    int   `json:"cpu_count,omitempty"`
	MemoryBytes int64 `json:"memory_bytes,omitempty"`
	DiskBytes   int64 `json:"disk_bytes,omitempty"`
}

func ValidateResourceLimitsAgainstCapacity(limits ResourceLimits, capacity ResourceCapacity) error {
	var errs []error
	if limits.CPUPercent > 0 && capacity.CPUCount > 0 {
		cpuCapacity := capacity.CPUCount * 100
		if limits.CPUPercent > cpuCapacity {
			errs = append(errs, fmt.Errorf("resource_limits.cpu_percent %d exceeds worker CPU capacity %d", limits.CPUPercent, cpuCapacity))
		}
	}
	if limits.MemoryBytes > 0 && capacity.MemoryBytes > 0 && limits.MemoryBytes > capacity.MemoryBytes {
		errs = append(errs, fmt.Errorf("resource_limits.memory_bytes %d exceeds worker memory_bytes %d", limits.MemoryBytes, capacity.MemoryBytes))
	}
	if limits.WorkspaceBytes > 0 && capacity.DiskBytes > 0 && limits.WorkspaceBytes > capacity.DiskBytes {
		errs = append(errs, fmt.Errorf("resource_limits.workspace_bytes %d exceeds worker disk_bytes %d", limits.WorkspaceBytes, capacity.DiskBytes))
	}
	return errors.Join(errs...)
}

func (l ResourceLimits) Validate() error {
	var errs []error
	if l.CPUPercent < 0 {
		errs = append(errs, errors.New("cpu_percent cannot be negative"))
	}
	if l.MemoryBytes < 0 {
		errs = append(errs, errors.New("memory_bytes cannot be negative"))
	}
	if l.WorkspaceBytes < 0 {
		errs = append(errs, errors.New("workspace_bytes cannot be negative"))
	}
	if l.RuntimeSeconds < 0 {
		errs = append(errs, errors.New("runtime_seconds cannot be negative"))
	}
	if l.NetworkEgressBytes < 0 {
		errs = append(errs, errors.New("network_egress_bytes cannot be negative"))
	}
	if l.OutputBytes < 0 {
		errs = append(errs, errors.New("output_bytes cannot be negative"))
	}
	return errors.Join(errs...)
}

type RuntimeExecutionRequest struct {
	ProtocolVersion string            `json:"protocol_version"`
	TaskID          string            `json:"task_id"`
	LeaseID         string            `json:"lease_id"`
	WorkloadKind    WorkloadKind      `json:"workload_kind"`
	ProviderConfig  ProviderConfig    `json:"provider_config,omitzero"`
	Operation       string            `json:"operation,omitempty"`
	Input           json.RawMessage   `json:"input,omitempty"`
	Env             map[string]string `json:"env,omitempty"`
	Limits          ResourceLimits    `json:"limits,omitzero"`
}

type EnvRef struct {
	Name      string `json:"name"`
	ValueRef  string `json:"value_ref,omitempty"`
	SecretRef string `json:"secret_ref,omitempty"`
}

func (r EnvRef) Validate() error {
	var errs []error
	if r.Name == "" {
		errs = append(errs, errors.New("name is required"))
	}
	if r.ValueRef == "" && r.SecretRef == "" {
		errs = append(errs, errors.New("requires value_ref or secret_ref"))
	}
	if r.ValueRef != "" && r.SecretRef != "" {
		errs = append(errs, errors.New("cannot set both value_ref and secret_ref"))
	}
	return errors.Join(errs...)
}

type ConfidentialPayloadRef struct {
	CiphertextRef  string `json:"ciphertext_ref"`
	CiphertextHash string `json:"ciphertext_hash"`
	KeyRefHash     string `json:"key_ref_hash"`
	Algorithm      string `json:"algorithm"`
	KBSPolicyID    string `json:"kbs_policy_id"`
}

func (r ConfidentialPayloadRef) Validate() error {
	var errs []error
	if err := validateScopedRef("ciphertext_ref", r.CiphertextRef, "artifact://"); err != nil {
		errs = append(errs, err)
	}
	if !validSHA256Digest(r.CiphertextHash) {
		errs = append(errs, errors.New("ciphertext_hash must be sha256:<64 hex chars>"))
	}
	if !validSHA256Digest(r.KeyRefHash) {
		errs = append(errs, errors.New("key_ref_hash must be sha256:<64 hex chars>"))
	}
	if r.Algorithm == "" {
		errs = append(errs, errors.New("algorithm is required"))
	}
	if r.KBSPolicyID == "" {
		errs = append(errs, errors.New("kbs_policy_id is required"))
	}
	return errors.Join(errs...)
}

type CommandWorkload struct {
	Args                []string                `json:"args"`
	WorkingDirectory    string                  `json:"working_directory,omitempty"`
	Env                 []EnvRef                `json:"env,omitempty"`
	ArtifactRefs        []string                `json:"artifact_refs,omitempty"`
	ArtifactAllowlist   []string                `json:"artifact_allowlist,omitempty"`
	ConfidentialPayload *ConfidentialPayloadRef `json:"confidential_payload,omitempty"`
}

func (w CommandWorkload) Validate() error {
	var errs []error
	if len(w.Args) == 0 {
		errs = append(errs, errors.New("command args are required"))
	}
	for i, ref := range w.Env {
		if err := ref.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("env[%d]: %w", i, err))
		}
	}
	for i, ref := range w.ArtifactRefs {
		if err := validateScopedRef(fmt.Sprintf("artifact_refs[%d]", i), ref, "artifact://"); err != nil {
			errs = append(errs, err)
		}
	}
	if w.ConfidentialPayload != nil {
		if err := w.ConfidentialPayload.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("confidential_payload: %w", err))
		}
	}
	return errors.Join(errs...)
}

type ContainerBuildWorkload struct {
	ContextDirectory string   `json:"context_directory"`
	Dockerfile       string   `json:"dockerfile,omitempty"`
	Tags             []string `json:"tags,omitempty"`
	PushTargetRef    string   `json:"push_target_ref,omitempty"`
	PullTargetRef    string   `json:"pull_target_ref,omitempty"`
	Env              []EnvRef `json:"env,omitempty"`
}

func (w ContainerBuildWorkload) Validate() error {
	var errs []error
	if w.ContextDirectory == "" {
		errs = append(errs, errors.New("context_directory is required"))
	}
	if len(w.Tags) == 0 {
		errs = append(errs, errors.New("tags is required"))
	}
	for i, ref := range w.Env {
		if err := ref.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("env[%d]: %w", i, err))
		}
	}
	return errors.Join(errs...)
}

func (r RuntimeExecutionRequest) Validate() error {
	var errs []error
	if r.ProtocolVersion != Version {
		errs = append(errs, fmt.Errorf("protocol_version must be %q", Version))
	}
	if strings.TrimSpace(r.TaskID) == "" {
		errs = append(errs, errors.New("task_id is required"))
	}
	if strings.TrimSpace(r.LeaseID) == "" {
		errs = append(errs, errors.New("lease_id is required"))
	}
	if !validWorkloadKind(r.WorkloadKind) {
		errs = append(errs, fmt.Errorf("workload_kind %q is unsupported", r.WorkloadKind))
	}
	if r.ProviderConfig != (ProviderConfig{}) {
		if err := r.ProviderConfig.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("provider_config: %w", err))
		}
	}
	if strings.ContainsAny(r.Operation, " \t\r\n\x00") {
		errs = append(errs, errors.New("operation must not contain whitespace"))
	}
	if len(r.Input) > 0 && !json.Valid(r.Input) {
		errs = append(errs, errors.New("input must be valid JSON"))
	}
	if err := r.Limits.Validate(); err != nil {
		errs = append(errs, fmt.Errorf("resource_limits: %w", err))
	}
	return errors.Join(errs...)
}

type RuntimeAdapterContract struct {
	ProtocolVersion     string                 `json:"protocol_version"`
	AdapterID           string                 `json:"adapter_id"`
	Descriptor          RuntimeDescriptor      `json:"descriptor,omitzero"`
	Kinds               []RuntimeAdapterKind   `json:"kinds"`
	WorkloadKinds       []WorkloadKind         `json:"workload_kinds"`
	RuntimeProfiles     []RuntimeProfile       `json:"runtime_profiles,omitempty"`
	WorkspacePolicy     RuntimeWorkspacePolicy `json:"workspace_policy"`
	ConformanceProfiles []string               `json:"conformance_profiles"`
	ResiduePolicy       ResiduePolicy          `json:"residue_policy,omitzero"`
	ProviderConfig      ProviderConfig         `json:"provider_config,omitzero"`
	Metadata            map[string]string      `json:"metadata,omitempty"`
}

func (c RuntimeAdapterContract) Validate() error {
	var errs []error
	if c.ProtocolVersion != Version {
		errs = append(errs, fmt.Errorf("protocol_version must be %q", Version))
	}
	if err := validateIdentifier("adapter_id", c.AdapterID); err != nil {
		errs = append(errs, err)
	}
	if err := c.Descriptor.Validate(); err != nil {
		errs = append(errs, fmt.Errorf("descriptor: %w", err))
	}
	if len(c.Kinds) == 0 {
		errs = append(errs, errors.New("kinds is required"))
	}
	seenKinds := map[RuntimeAdapterKind]struct{}{}
	for i, kind := range c.Kinds {
		if !validRuntimeAdapterKind(kind) {
			errs = append(errs, fmt.Errorf("kinds[%d] %q is unsupported", i, kind))
			continue
		}
		if _, exists := seenKinds[kind]; exists {
			errs = append(errs, fmt.Errorf("kinds[%d] %q is duplicated", i, kind))
		}
		seenKinds[kind] = struct{}{}
	}
	if len(c.WorkloadKinds) == 0 {
		errs = append(errs, errors.New("workload_kinds is required"))
	}
	seenWorkloads := map[WorkloadKind]struct{}{}
	for i, kind := range c.WorkloadKinds {
		if !validWorkloadKind(kind) {
			errs = append(errs, fmt.Errorf("workload_kinds[%d] %q is unsupported", i, kind))
			continue
		}
		if _, exists := seenWorkloads[kind]; exists {
			errs = append(errs, fmt.Errorf("workload_kinds[%d] %q is duplicated", i, kind))
		}
		seenWorkloads[kind] = struct{}{}
	}
	if c.SupportsAdapterKind(RuntimeAdapterServiceRun) || c.SupportsAdapterKind(RuntimeAdapterServiceSession) {
		if !c.Supports(WorkloadService) && !c.Supports(WorkloadNodeService) {
			errs = append(errs, errors.New("service adapter kinds require service workload kind"))
		}
	}
	for i, profile := range c.RuntimeProfiles {
		if !validRuntimeProfile(profile) {
			errs = append(errs, fmt.Errorf("runtime_profiles[%d] %q is unsupported", i, profile))
		}
	}
	if !validRuntimeWorkspacePolicy(c.WorkspacePolicy) {
		errs = append(errs, fmt.Errorf("workspace_policy %q is unsupported", c.WorkspacePolicy))
	}
	if len(c.ConformanceProfiles) == 0 {
		errs = append(errs, errors.New("conformance_profiles is required"))
	}
	seenProfiles := map[string]struct{}{}
	for i, profile := range c.ConformanceProfiles {
		if err := validateIdentifier(fmt.Sprintf("conformance_profiles[%d]", i), profile); err != nil {
			errs = append(errs, err)
			continue
		}
		if _, exists := seenProfiles[profile]; exists {
			errs = append(errs, fmt.Errorf("conformance_profiles[%d] %q is duplicated", i, profile))
		}
		seenProfiles[profile] = struct{}{}
	}
	if err := c.ResiduePolicy.Validate(ResiduePolicyValidation{RequirePolicyHash: true}); err != nil {
		errs = append(errs, fmt.Errorf("residue_policy: %w", err))
	}
	if err := c.ProviderConfig.Validate(); err != nil {
		errs = append(errs, fmt.Errorf("provider_config: %w", err))
	}
	for key := range c.Metadata {
		if err := validateIdentifier("metadata key", key); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (c RuntimeAdapterContract) Supports(kind WorkloadKind) bool {
	for _, supported := range c.WorkloadKinds {
		if supported == kind {
			return true
		}
	}
	return false
}

func (c RuntimeAdapterContract) SupportsAdapterKind(kind RuntimeAdapterKind) bool {
	for _, supported := range c.Kinds {
		if supported == kind {
			return true
		}
	}
	return false
}

const MaxRuntimeResultPreviewBytes = 16 * 1024

func ValidateRuntimeResultPreview(preview map[string]any) error {
	if len(preview) == 0 {
		return nil
	}
	data, err := json.Marshal(preview)
	if err != nil {
		return fmt.Errorf("result_preview must be JSON-serializable: %w", err)
	}
	if len(data) > MaxRuntimeResultPreviewBytes {
		return fmt.Errorf("result_preview must be at most %d bytes", MaxRuntimeResultPreviewBytes)
	}
	return nil
}

type RuntimeExecutionResult struct {
	StartedAt     time.Time      `json:"started_at,omitempty"`
	FinishedAt    time.Time      `json:"finished_at,omitempty"`
	ExitCode      int            `json:"exit_code,omitempty"`
	Stdout        []byte         `json:"stdout,omitempty"`
	Stderr        []byte         `json:"stderr,omitempty"`
	ArtifactHash  string         `json:"artifact_hash,omitempty"`
	Artifacts     []string       `json:"artifacts,omitempty"`
	ResultPreview map[string]any `json:"result_preview,omitempty"`
	ResourceUsage ResourceUsage  `json:"resource_usage,omitzero"`
}

func (r RuntimeExecutionResult) Validate() error {
	var errs []error
	if !r.StartedAt.IsZero() && !r.FinishedAt.IsZero() && r.FinishedAt.Before(r.StartedAt) {
		errs = append(errs, errors.New("finished_at must be after started_at"))
	}
	if r.ArtifactHash != "" && !validSHA256Ref(r.ArtifactHash) {
		errs = append(errs, errors.New("artifact_hash must be sha256:<64 hex chars>"))
	}
	if err := ValidateRuntimeResultPreview(r.ResultPreview); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

type SLOEvidence struct {
	LatencyMillis int64 `json:"latency_millis,omitempty"`
	StatusCode    int   `json:"status_code,omitempty"`
	DeadlineMS    int64 `json:"deadline_ms,omitempty"`
	Healthy       bool  `json:"healthy,omitempty"`
}

func (e SLOEvidence) Validate() error {
	var errs []error
	if e.StatusCode <= 0 {
		errs = append(errs, errors.New("status_code is required"))
	}
	if e.LatencyMillis <= 0 {
		errs = append(errs, errors.New("latency_millis is required"))
	}
	if e.DeadlineMS < 0 {
		errs = append(errs, errors.New("deadline_ms must not be negative"))
	}
	return errors.Join(errs...)
}

type ServiceStatusEvidence struct {
	CommandHash string `json:"command_hash,omitempty"`
	OutputHash  string `json:"output_hash,omitempty"`
	Preview     string `json:"preview,omitempty"`
	Truncated   bool   `json:"truncated,omitempty"`
}

func (e ServiceStatusEvidence) Validate() error {
	var errs []error
	for _, field := range []struct {
		name  string
		value string
	}{
		{"command_hash", e.CommandHash},
		{"output_hash", e.OutputHash},
	} {
		if field.value != "" && !validSHA256Ref(field.value) {
			errs = append(errs, fmt.Errorf("%s must be sha256:<64 hex chars>", field.name))
		}
	}
	return errors.Join(errs...)
}

type RuntimeServiceResult struct {
	StartedAt      time.Time             `json:"started_at,omitempty"`
	FinishedAt     time.Time             `json:"finished_at,omitempty"`
	RequestHash    string                `json:"request_hash,omitempty"`
	ResponseHash   string                `json:"response_hash,omitempty"`
	ResourceUsage  ResourceUsage         `json:"resource_usage,omitzero"`
	SLOEvidence    SLOEvidence           `json:"slo_evidence,omitzero"`
	StatusEvidence ServiceStatusEvidence `json:"status_evidence,omitzero"`
}

func (r RuntimeServiceResult) Validate() error {
	var errs []error
	if !r.StartedAt.IsZero() && !r.FinishedAt.IsZero() && r.FinishedAt.Before(r.StartedAt) {
		errs = append(errs, errors.New("finished_at must be after started_at"))
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{"request_hash", r.RequestHash},
		{"response_hash", r.ResponseHash},
	} {
		if field.value != "" && !validSHA256Ref(field.value) {
			errs = append(errs, fmt.Errorf("%s must be sha256:<64 hex chars>", field.name))
		}
	}
	if err := r.SLOEvidence.Validate(); err != nil {
		errs = append(errs, fmt.Errorf("slo_evidence: %w", err))
	}
	if err := r.StatusEvidence.Validate(); err != nil {
		errs = append(errs, fmt.Errorf("status_evidence: %w", err))
	}
	return errors.Join(errs...)
}

type ServiceIngressTerminalStatus string

const (
	ServiceIngressTerminalCompleted ServiceIngressTerminalStatus = "completed"
	ServiceIngressTerminalFailed    ServiceIngressTerminalStatus = "failed"
)

type ServiceIngressEvidence struct {
	ID                         string                       `json:"id"`
	OrgID                      string                       `json:"org_id"`
	PoolID                     string                       `json:"pool_id"`
	ProductID                  string                       `json:"product_id"`
	Hostname                   string                       `json:"hostname"`
	RouteTarget                string                       `json:"route_target"`
	ServiceLeaseID             string                       `json:"service_lease_id"`
	TaskID                     string                       `json:"task_id"`
	WorkerID                   string                       `json:"worker_id"`
	LeaseLeasedAt              time.Time                    `json:"lease_leased_at"`
	LeaseRenewBy               time.Time                    `json:"lease_renew_by"`
	SelectedAt                 time.Time                    `json:"selected_at"`
	LastHealthAt               time.Time                    `json:"last_health_at"`
	HealthValidUntil           time.Time                    `json:"health_valid_until"`
	LastHealthResponseHash     string                       `json:"last_health_response_hash"`
	LastHealthSLOEvidenceHash  string                       `json:"last_health_slo_evidence_hash"`
	AuthDecisionHash           string                       `json:"auth_decision_hash"`
	IdempotencyKey             string                       `json:"idempotency_key"`
	RequestMethod              string                       `json:"request_method"`
	RequestPath                string                       `json:"request_path"`
	RequestBodyHash            string                       `json:"request_body_hash"`
	RequestHeaderNames         []string                     `json:"request_header_names,omitempty"`
	HelperImage                string                       `json:"helper_image"`
	HelperScheme               string                       `json:"helper_scheme"`
	HelperHost                 string                       `json:"helper_host"`
	HelperPort                 int                          `json:"helper_port"`
	HelperPortName             string                       `json:"helper_port_name,omitempty"`
	HelperTimeoutMS            int                          `json:"helper_timeout_ms"`
	HelperContainerNetNSTarget string                       `json:"helper_container_netns_target"`
	HelperOutputHash           string                       `json:"helper_output_hash,omitempty"`
	HelperErrorHash            string                       `json:"helper_error_hash,omitempty"`
	FailureClass               string                       `json:"failure_class,omitempty"`
	FailureMessage             string                       `json:"failure_message,omitempty"`
	ResponseStatus             int                          `json:"response_status,omitempty"`
	ResponseHeaderNames        []string                     `json:"response_header_names,omitempty"`
	ResponseHash               string                       `json:"response_hash,omitempty"`
	ResponseBytes              int64                        `json:"response_bytes,omitempty"`
	TerminalStatus             ServiceIngressTerminalStatus `json:"terminal_status"`
	StartedAt                  time.Time                    `json:"started_at"`
	FinishedAt                 time.Time                    `json:"finished_at"`
}

func (e ServiceIngressEvidence) Validate() error {
	var errs []error
	require := func(name, value string) {
		if strings.TrimSpace(value) == "" {
			errs = append(errs, fmt.Errorf("%s is required", name))
		}
	}
	require("id", e.ID)
	require("org_id", e.OrgID)
	require("pool_id", e.PoolID)
	require("product_id", e.ProductID)
	require("hostname", e.Hostname)
	require("route_target", e.RouteTarget)
	require("service_lease_id", e.ServiceLeaseID)
	require("task_id", e.TaskID)
	require("worker_id", e.WorkerID)
	require("last_health_response_hash", e.LastHealthResponseHash)
	require("last_health_slo_evidence_hash", e.LastHealthSLOEvidenceHash)
	require("auth_decision_hash", e.AuthDecisionHash)
	require("idempotency_key", e.IdempotencyKey)
	require("request_method", e.RequestMethod)
	require("request_path", e.RequestPath)
	require("helper_image", e.HelperImage)
	require("helper_scheme", e.HelperScheme)
	require("helper_host", e.HelperHost)
	require("helper_container_netns_target", e.HelperContainerNetNSTarget)
	for _, field := range []struct {
		name  string
		value string
	}{
		{name: "id", value: e.ID},
		{name: "org_id", value: e.OrgID},
		{name: "pool_id", value: e.PoolID},
		{name: "product_id", value: e.ProductID},
		{name: "service_lease_id", value: e.ServiceLeaseID},
		{name: "task_id", value: e.TaskID},
		{name: "worker_id", value: e.WorkerID},
		{name: "idempotency_key", value: e.IdempotencyKey},
	} {
		if field.value != "" {
			if err := validateIdentifier(field.name, field.value); err != nil {
				errs = append(errs, err)
			}
		}
	}
	if e.Hostname != "" {
		if err := validateNetworkHostname(e.Hostname); err != nil {
			errs = append(errs, fmt.Errorf("hostname: %w", err))
		}
	}
	if e.RouteTarget != "" && !strings.HasPrefix(e.RouteTarget, "service-route:") {
		errs = append(errs, errors.New("route_target must be opaque service-route target"))
	}
	switch e.RequestMethod {
	case "GET", "POST":
	case "":
	default:
		errs = append(errs, fmt.Errorf("request_method %q is unsupported", e.RequestMethod))
	}
	if e.RequestPath != "" {
		if !strings.HasPrefix(e.RequestPath, "/") || strings.Contains(e.RequestPath, "://") {
			errs = append(errs, errors.New("request_path must be queryless origin-form path"))
		}
		if strings.ContainsAny(e.RequestPath, "?#") {
			errs = append(errs, errors.New("request_path must not contain query or fragment"))
		}
	}
	if e.HelperScheme != "" && e.HelperScheme != "http" {
		errs = append(errs, errors.New("helper_scheme must be http"))
	}
	if e.HelperHost != "" && e.HelperHost != "127.0.0.1" {
		errs = append(errs, errors.New("helper_host must be 127.0.0.1"))
	}
	if e.HelperPort <= 0 || e.HelperPort > 65535 {
		errs = append(errs, errors.New("helper_port must be between 1 and 65535"))
	}
	if e.HelperTimeoutMS <= 0 {
		errs = append(errs, errors.New("helper_timeout_ms is required"))
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{name: "last_health_response_hash", value: e.LastHealthResponseHash},
		{name: "last_health_slo_evidence_hash", value: e.LastHealthSLOEvidenceHash},
		{name: "auth_decision_hash", value: e.AuthDecisionHash},
		{name: "request_body_hash", value: e.RequestBodyHash},
		{name: "helper_output_hash", value: e.HelperOutputHash},
		{name: "helper_error_hash", value: e.HelperErrorHash},
		{name: "response_hash", value: e.ResponseHash},
	} {
		if field.value != "" && !validSHA256Digest(field.value) {
			errs = append(errs, fmt.Errorf("%s must use sha256 digest", field.name))
		}
	}
	switch e.TerminalStatus {
	case ServiceIngressTerminalCompleted:
		if e.ResponseStatus <= 0 {
			errs = append(errs, errors.New("response_status is required for completed ingress"))
		}
		if e.ResponseHash == "" {
			errs = append(errs, errors.New("response_hash is required for completed ingress"))
		}
	case ServiceIngressTerminalFailed:
		if strings.TrimSpace(e.FailureClass) == "" {
			errs = append(errs, errors.New("failure_class is required for failed ingress"))
		}
	case "":
		errs = append(errs, errors.New("terminal_status is required"))
	default:
		errs = append(errs, fmt.Errorf("terminal_status %q is unsupported", e.TerminalStatus))
	}
	if e.ResponseBytes < 0 {
		errs = append(errs, errors.New("response_bytes must be non-negative"))
	}
	for i, name := range e.RequestHeaderNames {
		if err := validateIngressHeaderName(name); err != nil {
			errs = append(errs, fmt.Errorf("request_header_names[%d]: %w", i, err))
		}
	}
	for i, name := range e.ResponseHeaderNames {
		if err := validateIngressHeaderName(name); err != nil {
			errs = append(errs, fmt.Errorf("response_header_names[%d]: %w", i, err))
		}
	}
	for _, field := range []struct {
		name string
		ts   time.Time
	}{
		{name: "lease_leased_at", ts: e.LeaseLeasedAt},
		{name: "lease_renew_by", ts: e.LeaseRenewBy},
		{name: "selected_at", ts: e.SelectedAt},
		{name: "last_health_at", ts: e.LastHealthAt},
		{name: "health_valid_until", ts: e.HealthValidUntil},
		{name: "started_at", ts: e.StartedAt},
		{name: "finished_at", ts: e.FinishedAt},
	} {
		if field.ts.IsZero() {
			errs = append(errs, fmt.Errorf("%s is required", field.name))
		}
	}
	if !e.StartedAt.IsZero() && !e.FinishedAt.IsZero() && e.FinishedAt.Before(e.StartedAt) {
		errs = append(errs, errors.New("finished_at must be after started_at"))
	}
	return errors.Join(errs...)
}

type NetworkMode string

const (
	NetworkModeDirect  NetworkMode = "direct"
	NetworkModeRelay   NetworkMode = "relay"
	NetworkModeTailnet NetworkMode = "tailnet"
	NetworkModeTor     NetworkMode = "tor"
	NetworkModeP2P     NetworkMode = "p2p"
	NetworkModeOffline NetworkMode = "offline"
)

type PlacementRequirements struct {
	ExecutorProvider      string                `json:"executor_provider,omitempty"`
	ExecutionSecurityTier ExecutionSecurityTier `json:"execution_security_tier,omitempty"`
	ProofTier             ProofTier             `json:"proof_tier,omitempty"`
	HardwareClass         string                `json:"hardware_class,omitempty"`
	RequiredCapabilities  []string              `json:"required_capabilities,omitempty"`
}

type ProofPolicy struct {
	Quorum      int `json:"quorum,omitempty"`
	MaxAttempts int `json:"max_attempts,omitempty"`
}

type SessionPolicy struct {
	WarmSeconds      int `json:"warm_seconds,omitempty"`
	MinRenewals      int `json:"min_renewals,omitempty"`
	MaxBatchRequests int `json:"max_batch_requests,omitempty"`
}

type ProviderConfig struct {
	PluginID     string `json:"plugin_id,omitempty"`
	ProviderID   string `json:"provider_id,omitempty"`
	ContractID   string `json:"contract_id,omitempty"`
	Version      string `json:"version,omitempty"`
	ConfigRef    string `json:"config_ref,omitempty"`
	ConfigDigest string `json:"config_digest,omitempty"`
}

func (p ProviderConfig) Validate() error {
	if p == (ProviderConfig{}) {
		return nil
	}
	var errs []error
	if err := validateIdentifier("plugin_id", p.PluginID); err != nil {
		errs = append(errs, err)
	}
	if err := validateIdentifier("provider_id", p.ProviderID); err != nil {
		errs = append(errs, err)
	}
	if err := validateIdentifier("contract_id", p.ContractID); err != nil {
		errs = append(errs, err)
	}
	if strings.TrimSpace(p.Version) == "" {
		errs = append(errs, errors.New("version is required"))
	} else if strings.ContainsAny(p.Version, " \t\r\n\x00") {
		errs = append(errs, errors.New("version must not contain whitespace"))
	}
	if strings.TrimSpace(p.ConfigRef) == "" {
		errs = append(errs, errors.New("config_ref is required"))
	} else if err := validateScopedRef("config_ref", p.ConfigRef, "config://"); err != nil {
		errs = append(errs, err)
	}
	if p.ConfigDigest != "" && !validSHA256Ref(p.ConfigDigest) {
		errs = append(errs, errors.New("config_digest must be sha256:<64 hex chars>"))
	}
	return errors.Join(errs...)
}

func (p SessionPolicy) ValidateForOperatingMode(mode NetworkOperatingMode) error {
	var errs []error
	if p.WarmSeconds < 0 {
		errs = append(errs, errors.New("warm_seconds must be non-negative"))
	}
	if p.MinRenewals < 0 {
		errs = append(errs, errors.New("min_renewals must be non-negative"))
	}
	if p.MaxBatchRequests < 0 {
		errs = append(errs, errors.New("max_batch_requests must be non-negative"))
	}
	switch mode {
	case NetworkModeWarmService, NetworkModeNodeService, NetworkModeInferenceAPI:
		if p.WarmSeconds <= 0 {
			errs = append(errs, errors.New("warm_seconds is required for warm operating modes"))
		}
	case NetworkModeBatch:
		if p.MinRenewals > 0 {
			errs = append(errs, errors.New("min_renewals requires warm operating mode"))
		}
	}
	return errors.Join(errs...)
}

func ValidateProofPolicy(proofTier ProofTier, policy ProofPolicy) error {
	switch proofTier {
	case ProofReplicatedQuorum, ProofAttestedQuorum:
		if policy.Quorum < 2 {
			return errors.New("proof_policy.quorum must be >= 2")
		}
		if policy.MaxAttempts != 0 && policy.MaxAttempts < policy.Quorum {
			return errors.New("proof_policy.max_attempts must be >= quorum")
		}
	default:
		if policy.Quorum > 1 || policy.MaxAttempts > 0 {
			return errors.New("proof_policy.quorum requires replicated or attested quorum proof tier")
		}
	}
	return nil
}

type AccessVisibility string

const (
	AccessVisibilityPrivate AccessVisibility = "private"
	AccessVisibilityNetwork AccessVisibility = "network"
	AccessVisibilityPublic  AccessVisibility = "public"
)

type AccessPolicy struct {
	ProviderUsageVisibility AccessVisibility `json:"provider_usage_visibility,omitempty"`
	WorkloadVisibility      AccessVisibility `json:"workload_visibility,omitempty"`
	ArtifactVisibility      AccessVisibility `json:"artifact_visibility,omitempty"`
}

func (p AccessPolicy) Validate() error {
	var errs []error
	if !validAccessVisibility(p.ProviderUsageVisibility) {
		errs = append(errs, fmt.Errorf("provider_usage_visibility %q is unsupported", p.ProviderUsageVisibility))
	}
	if !validAccessVisibility(p.WorkloadVisibility) {
		errs = append(errs, fmt.Errorf("workload_visibility %q is unsupported", p.WorkloadVisibility))
	}
	if !validAccessVisibility(p.ArtifactVisibility) {
		errs = append(errs, fmt.Errorf("artifact_visibility %q is unsupported", p.ArtifactVisibility))
	}
	return errors.Join(errs...)
}

type ProviderContract struct {
	ProtocolVersion        string                  `json:"protocol_version"`
	ID                     string                  `json:"id"`
	PluginID               string                  `json:"plugin_id"`
	ProviderID             string                  `json:"provider_id"`
	ContractID             string                  `json:"contract_id"`
	Version                string                  `json:"version"`
	DisplayName            string                  `json:"display_name,omitempty"`
	OrgID                  string                  `json:"org_id,omitempty"`
	PoolID                 string                  `json:"pool_id,omitempty"`
	AccessPolicy           AccessPolicy            `json:"access_policy,omitzero"`
	ConfigSchemaRef        string                  `json:"config_schema_ref"`
	ConfigSchemaDigest     string                  `json:"config_schema_digest"`
	OperatingModes         []NetworkOperatingMode  `json:"operating_modes"`
	WorkloadKinds          []string                `json:"workload_kinds"`
	ExecutorProviders      []string                `json:"executor_providers"`
	ExecutionSecurityTiers []ExecutionSecurityTier `json:"execution_security_tiers"`
	ProofTiers             []ProofTier             `json:"proof_tiers"`
	NetworkModes           []NetworkMode           `json:"network_modes"`
	Operations             []ProviderOperation     `json:"operations,omitempty"`
	RuntimeContract        ProviderRuntimeContract `json:"runtime_contract"`
	CreatedAt              time.Time               `json:"created_at,omitempty"`
}

func (c ProviderContract) Validate() error {
	var errs []error
	if c.ProtocolVersion != Version {
		errs = append(errs, fmt.Errorf("protocol_version must be %q", Version))
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{"id", c.ID},
		{"plugin_id", c.PluginID},
		{"provider_id", c.ProviderID},
		{"contract_id", c.ContractID},
	} {
		if err := validateIdentifier(field.name, field.value); err != nil {
			errs = append(errs, err)
		}
	}
	if c.OrgID != "" {
		if err := validateIdentifier("org_id", c.OrgID); err != nil {
			errs = append(errs, err)
		}
	}
	if c.PoolID != "" {
		if c.OrgID == "" {
			errs = append(errs, errors.New("org_id is required when pool_id is set"))
		}
		if err := validateIdentifier("pool_id", c.PoolID); err != nil {
			errs = append(errs, err)
		}
	}
	if err := c.AccessPolicy.Validate(); err != nil {
		errs = append(errs, fmt.Errorf("access_policy: %w", err))
	}
	if strings.TrimSpace(c.Version) == "" {
		errs = append(errs, errors.New("version is required"))
	} else if strings.ContainsAny(c.Version, " \t\r\n\x00") {
		errs = append(errs, errors.New("version must not contain whitespace"))
	}
	if strings.TrimSpace(c.ConfigSchemaRef) == "" {
		errs = append(errs, errors.New("config_schema_ref is required"))
	} else if err := validateScopedRef("config_schema_ref", c.ConfigSchemaRef, "schema://"); err != nil {
		errs = append(errs, err)
	}
	if c.ConfigSchemaDigest == "" {
		errs = append(errs, errors.New("config_schema_digest is required"))
	} else if !validSHA256Ref(c.ConfigSchemaDigest) {
		errs = append(errs, errors.New("config_schema_digest must be sha256:<64 hex chars>"))
	}
	if len(c.OperatingModes) == 0 {
		errs = append(errs, errors.New("operating_modes is required"))
	}
	for i, mode := range c.OperatingModes {
		if !validNetworkOperatingMode(mode) {
			errs = append(errs, fmt.Errorf("operating_modes[%d] %q is unsupported", i, mode))
		}
	}
	if len(c.WorkloadKinds) == 0 {
		errs = append(errs, errors.New("workload_kinds is required"))
	}
	for i, kind := range c.WorkloadKinds {
		if !validWorkloadKind(WorkloadKind(strings.TrimSpace(kind))) {
			errs = append(errs, fmt.Errorf("workload_kinds[%d] %q is unknown", i, kind))
		}
	}
	if len(c.ExecutorProviders) == 0 {
		errs = append(errs, errors.New("executor_providers is required"))
	}
	for i, provider := range c.ExecutorProviders {
		if err := validateIdentifier(fmt.Sprintf("executor_providers[%d]", i), provider); err != nil {
			errs = append(errs, err)
		}
	}
	if len(c.ExecutionSecurityTiers) == 0 {
		errs = append(errs, errors.New("execution_security_tiers is required"))
	}
	for i, tier := range c.ExecutionSecurityTiers {
		if !validExecutionSecurityTier(tier) || tier == ExecutionTrustedNative {
			errs = append(errs, fmt.Errorf("execution_security_tiers[%d] %q is unsupported", i, tier))
		}
	}
	if len(c.ProofTiers) == 0 {
		errs = append(errs, errors.New("proof_tiers is required"))
	}
	for i, tier := range c.ProofTiers {
		if !validProofTier(tier) || tier == ProofReceiptOnly {
			errs = append(errs, fmt.Errorf("proof_tiers[%d] %q is unsupported", i, tier))
		}
	}
	if len(c.NetworkModes) == 0 {
		errs = append(errs, errors.New("network_modes is required"))
	}
	for i, mode := range c.NetworkModes {
		if !validNetworkMode(normalizeNetworkMode(mode)) {
			errs = append(errs, fmt.Errorf("network_modes[%d] %q is unsupported", i, mode))
		}
	}
	if contains(c.WorkloadKinds, string(WorkloadProvider)) && len(c.Operations) == 0 {
		errs = append(errs, errors.New("operations is required for provider workload contracts"))
	}
	seenOperations := map[string]struct{}{}
	for i, operation := range c.Operations {
		if err := operation.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("operations[%d]: %w", i, err))
		}
		if operation.ID != "" {
			if _, exists := seenOperations[operation.ID]; exists {
				errs = append(errs, fmt.Errorf("operations[%d].id %q is duplicated", i, operation.ID))
			}
			seenOperations[operation.ID] = struct{}{}
		}
	}
	if err := c.RuntimeContract.Validate(); err != nil {
		errs = append(errs, err)
	}
	if ProviderPluginRequiresUpstreamClientConformance(c.PluginID) {
		for i, profile := range c.RuntimeContract.Profiles {
			if profile.UpstreamClientConformance == "" {
				errs = append(errs, fmt.Errorf("runtime_contract.profiles[%d].upstream_client_conformance is required for plugin %q", i, c.PluginID))
			}
		}
	}
	return errors.Join(errs...)
}

func (c ProviderContract) SupportsProduct(product NetworkProduct) error {
	if c.PluginID != product.ProviderConfig.PluginID ||
		c.ProviderID != product.ProviderConfig.ProviderID ||
		c.ContractID != product.ProviderConfig.ContractID {
		return errors.New("product provider config does not match contract")
	}
	if product.ProviderConfig.Version != "" && c.Version != product.ProviderConfig.Version {
		return fmt.Errorf("product provider config version %q does not match contract version %q", product.ProviderConfig.Version, c.Version)
	}
	if !contains(c.OperatingModes, product.OperatingMode) {
		return fmt.Errorf("operating mode %q is unsupported", product.OperatingMode)
	}
	for _, kind := range product.WorkloadKinds {
		if !contains(c.WorkloadKinds, kind) {
			return fmt.Errorf("workload kind %q is unsupported", kind)
		}
	}
	if !contains(c.ExecutorProviders, product.SecurityFloor.ExecutorProvider) {
		return fmt.Errorf("executor provider %q is unsupported", product.SecurityFloor.ExecutorProvider)
	}
	if !contains(c.ExecutionSecurityTiers, product.SecurityFloor.ExecutionSecurityTier) {
		return fmt.Errorf("execution security tier %q is unsupported", product.SecurityFloor.ExecutionSecurityTier)
	}
	if !contains(c.ProofTiers, product.SecurityFloor.ProofTier) {
		return fmt.Errorf("proof tier %q is unsupported", product.SecurityFloor.ProofTier)
	}
	for _, mode := range product.NetworkModes {
		if !contains(c.NetworkModes, normalizeNetworkMode(mode)) {
			return fmt.Errorf("network mode %q is unsupported", mode)
		}
	}
	if !c.RuntimeContract.SupportsProduct(product) {
		return fmt.Errorf("runtime profile for executor provider %q is unsupported", product.SecurityFloor.ExecutorProvider)
	}
	return nil
}

func (c ProviderContract) Matches(config ProviderConfig) bool {
	return c.PluginID == config.PluginID &&
		c.ProviderID == config.ProviderID &&
		c.ContractID == config.ContractID &&
		c.Version == config.Version
}

func (c ProviderContract) SupportsOperation(operation string) bool {
	operation = strings.TrimSpace(operation)
	for _, candidate := range c.Operations {
		if candidate.ID == operation {
			return true
		}
	}
	return false
}

type ProviderOperation struct {
	ID                 string                 `json:"id"`
	InputSchemaRef     string                 `json:"input_schema_ref"`
	InputSchemaDigest  string                 `json:"input_schema_digest"`
	OutputSchemaRef    string                 `json:"output_schema_ref"`
	OutputSchemaDigest string                 `json:"output_schema_digest"`
	Artifacts          []string               `json:"artifacts,omitempty"`
	ArtifactSpecs      []ProviderArtifactSpec `json:"artifact_specs,omitempty"`
}

func (o ProviderOperation) Validate() error {
	var errs []error
	if err := validateIdentifier("id", o.ID); err != nil {
		errs = append(errs, err)
	}
	if strings.TrimSpace(o.InputSchemaRef) == "" {
		errs = append(errs, errors.New("input_schema_ref is required"))
	} else if err := validateScopedRef("input_schema_ref", o.InputSchemaRef, "schema://"); err != nil {
		errs = append(errs, err)
	}
	if strings.TrimSpace(o.OutputSchemaRef) == "" {
		errs = append(errs, errors.New("output_schema_ref is required"))
	} else if err := validateScopedRef("output_schema_ref", o.OutputSchemaRef, "schema://"); err != nil {
		errs = append(errs, err)
	}
	if !validSHA256Ref(o.InputSchemaDigest) {
		errs = append(errs, errors.New("input_schema_digest must be sha256:<64 hex chars>"))
	}
	if !validSHA256Ref(o.OutputSchemaDigest) {
		errs = append(errs, errors.New("output_schema_digest must be sha256:<64 hex chars>"))
	}
	legacyArtifacts := map[string]struct{}{}
	for i, artifact := range o.Artifacts {
		if !validProviderArtifactName(artifact) {
			errs = append(errs, fmt.Errorf("artifacts[%d] %q is invalid", i, artifact))
		}
		legacyArtifacts[artifact] = struct{}{}
	}
	seenArtifactSpecs := map[string]struct{}{}
	for i, spec := range o.ArtifactSpecs {
		if !validProviderArtifactName(spec.Name) {
			errs = append(errs, fmt.Errorf("artifact_specs[%d].name %q is invalid", i, spec.Name))
		}
		if spec.Name != "" {
			if _, exists := seenArtifactSpecs[spec.Name]; exists {
				errs = append(errs, fmt.Errorf("artifact_specs[%d].name %q is duplicated", i, spec.Name))
			}
			seenArtifactSpecs[spec.Name] = struct{}{}
			if len(legacyArtifacts) > 0 {
				if _, exists := legacyArtifacts[spec.Name]; !exists {
					errs = append(errs, fmt.Errorf("artifact_specs[%d].name %q must also appear in artifacts", i, spec.Name))
				}
			}
		}
		if spec.ContentType != "" {
			if strings.TrimSpace(spec.ContentType) != spec.ContentType || strings.ContainsAny(spec.ContentType, "\x00\r\n\t") {
				errs = append(errs, fmt.Errorf("artifact_specs[%d].content_type is invalid", i))
			} else if _, _, err := mime.ParseMediaType(spec.ContentType); err != nil {
				errs = append(errs, fmt.Errorf("artifact_specs[%d].content_type is invalid", i))
			}
		}
		if spec.MaxBytes < 0 {
			errs = append(errs, fmt.Errorf("artifact_specs[%d].max_bytes must not be negative", i))
		}
		if spec.RetentionSeconds < 0 {
			errs = append(errs, fmt.Errorf("artifact_specs[%d].retention_seconds must not be negative", i))
		}
		if spec.ProviderReturn != nil {
			if err := spec.ProviderReturn.Validate(); err != nil {
				errs = append(errs, fmt.Errorf("artifact_specs[%d].provider_return: %w", i, err))
			}
		}
	}
	return errors.Join(errs...)
}

func (o ProviderOperation) NormalizedArtifactSpecs() []ProviderArtifactSpec {
	if len(o.ArtifactSpecs) > 0 {
		specs := make([]ProviderArtifactSpec, len(o.ArtifactSpecs))
		copy(specs, o.ArtifactSpecs)
		return specs
	}
	if len(o.Artifacts) == 0 {
		return nil
	}
	specs := make([]ProviderArtifactSpec, 0, len(o.Artifacts))
	for _, artifact := range o.Artifacts {
		specs = append(specs, ProviderArtifactSpec{Name: artifact})
	}
	return specs
}

type ProviderArtifactSpec struct {
	Name             string                      `json:"name"`
	Required         bool                        `json:"required,omitempty"`
	ContentType      string                      `json:"content_type,omitempty"`
	MaxBytes         int64                       `json:"max_bytes,omitempty"`
	RetentionSeconds int                         `json:"retention_seconds,omitempty"`
	Forwardable      bool                        `json:"forwardable,omitempty"`
	ProviderReturn   *ProviderArtifactReturnSpec `json:"provider_return,omitempty"`
}

type ProviderArtifactReturnSpec struct {
	StepType        string   `json:"step_type"`
	Contract        string   `json:"contract"`
	ContractVersion string   `json:"contract_version,omitempty"`
	SubmitEndpoint  string   `json:"submit_endpoint,omitempty"`
	RequiredConfig  []string `json:"required_config,omitempty"`
	OutputHandling  []string `json:"output_handling,omitempty"`
}

func (s ProviderArtifactReturnSpec) Enabled() bool {
	return s.StepType != "" || s.Contract != "" || s.ContractVersion != "" || s.SubmitEndpoint != "" || len(s.RequiredConfig) > 0 || len(s.OutputHandling) > 0
}

func (s ProviderArtifactReturnSpec) Validate() error {
	var errs []error
	if err := validateIdentifier("step_type", s.StepType); err != nil {
		errs = append(errs, err)
	}
	if strings.TrimSpace(s.Contract) == "" {
		errs = append(errs, errors.New("contract is required"))
	} else if strings.TrimSpace(s.Contract) != s.Contract || strings.ContainsAny(s.Contract, " \t\r\n\x00") || strings.Contains(s.Contract, "://") {
		errs = append(errs, errors.New("contract must be a typed plugin contract without whitespace or URL scheme"))
	} else if !strings.Contains(s.Contract, ":") {
		errs = append(errs, errors.New("contract must include plugin and step type"))
	}
	if s.ContractVersion != "" && strings.ContainsAny(s.ContractVersion, " \t\r\n\x00") {
		errs = append(errs, errors.New("contract_version must not contain whitespace"))
	}
	if s.SubmitEndpoint != "" && !validProviderReturnSubmitEndpoint(s.SubmitEndpoint) {
		errs = append(errs, errors.New("submit_endpoint must be a server-relative path"))
	}
	for i, value := range s.RequiredConfig {
		if err := validateIdentifier(fmt.Sprintf("required_config[%d]", i), value); err != nil {
			errs = append(errs, err)
		}
	}
	for i, value := range s.OutputHandling {
		if err := validateIdentifier(fmt.Sprintf("output_handling[%d]", i), value); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

type ProviderArtifactDeliveryStatus string

const (
	ProviderArtifactDeliveryPending    ProviderArtifactDeliveryStatus = "pending"
	ProviderArtifactDeliveryDelivered  ProviderArtifactDeliveryStatus = "delivered"
	ProviderArtifactDeliveryFailed     ProviderArtifactDeliveryStatus = "failed"
	ProviderArtifactDeliveryDeadLetter ProviderArtifactDeliveryStatus = "dead_letter"
)

type ProviderArtifactDeliveryArtifact struct {
	Name        string    `json:"name"`
	Ref         string    `json:"ref"`
	ContentType string    `json:"content_type,omitempty"`
	SHA256      string    `json:"sha256"`
	SizeBytes   int64     `json:"size_bytes"`
	ExpiresAt   time.Time `json:"expires_at,omitempty"`
}

func (a ProviderArtifactDeliveryArtifact) Validate() error {
	var errs []error
	if !validProviderArtifactName(a.Name) {
		errs = append(errs, errors.New("artifact.name is invalid"))
	}
	if strings.TrimSpace(a.Ref) == "" {
		errs = append(errs, errors.New("artifact.ref is required"))
	} else if err := validateScopedRef("artifact.ref", a.Ref, "artifact://"); err != nil {
		errs = append(errs, err)
	}
	if a.ContentType != "" {
		if strings.TrimSpace(a.ContentType) != a.ContentType || strings.ContainsAny(a.ContentType, "\x00\r\n\t") {
			errs = append(errs, errors.New("artifact.content_type is invalid"))
		} else if _, _, err := mime.ParseMediaType(a.ContentType); err != nil {
			errs = append(errs, errors.New("artifact.content_type is invalid"))
		}
	}
	if !validSHA256Ref(a.SHA256) {
		errs = append(errs, errors.New("artifact.sha256 must be sha256:<64 hex chars>"))
	}
	if a.SizeBytes < 0 {
		errs = append(errs, errors.New("artifact.size_bytes must not be negative"))
	}
	return errors.Join(errs...)
}

type ProviderArtifactDelivery struct {
	ProtocolVersion string                           `json:"protocol_version,omitempty"`
	ID              string                           `json:"id"`
	OrgID           string                           `json:"org_id"`
	PoolID          string                           `json:"pool_id"`
	ProductID       string                           `json:"product_id,omitempty"`
	TaskID          string                           `json:"task_id"`
	ProofID         string                           `json:"proof_id"`
	WorkerID        string                           `json:"worker_id"`
	ProviderConfig  ProviderConfig                   `json:"provider_config"`
	Operation       string                           `json:"operation"`
	ReturnSpec      ProviderArtifactReturnSpec       `json:"provider_return"`
	Artifact        ProviderArtifactDeliveryArtifact `json:"artifact"`
	Status          ProviderArtifactDeliveryStatus   `json:"status"`
	Attempts        int                              `json:"attempts,omitempty"`
	LastErrorHash   string                           `json:"last_error_hash,omitempty"`
	CreatedAt       time.Time                        `json:"created_at"`
	UpdatedAt       time.Time                        `json:"updated_at"`
}

func (d ProviderArtifactDelivery) Validate() error {
	var errs []error
	if d.ProtocolVersion != "" && d.ProtocolVersion != Version {
		errs = append(errs, fmt.Errorf("protocol_version must be %q", Version))
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{name: "id", value: d.ID},
		{name: "org_id", value: d.OrgID},
		{name: "pool_id", value: d.PoolID},
		{name: "task_id", value: d.TaskID},
		{name: "proof_id", value: d.ProofID},
		{name: "worker_id", value: d.WorkerID},
		{name: "operation", value: d.Operation},
	} {
		if err := validateIdentifier(field.name, field.value); err != nil {
			errs = append(errs, err)
		}
	}
	if d.ProductID != "" {
		if err := validateIdentifier("product_id", d.ProductID); err != nil {
			errs = append(errs, err)
		}
	}
	if err := d.ProviderConfig.Validate(); err != nil {
		errs = append(errs, fmt.Errorf("provider_config: %w", err))
	}
	if err := d.ReturnSpec.Validate(); err != nil {
		errs = append(errs, fmt.Errorf("provider_return: %w", err))
	}
	if err := d.Artifact.Validate(); err != nil {
		errs = append(errs, err)
	}
	if !validProviderArtifactDeliveryStatus(d.Status) {
		errs = append(errs, fmt.Errorf("status %q is unsupported", d.Status))
	}
	if d.Attempts < 0 {
		errs = append(errs, errors.New("attempts must not be negative"))
	}
	if d.LastErrorHash != "" && !validSHA256Ref(d.LastErrorHash) {
		errs = append(errs, errors.New("last_error_hash must be sha256:<64 hex chars>"))
	}
	if d.CreatedAt.IsZero() {
		errs = append(errs, errors.New("created_at is required"))
	}
	if d.UpdatedAt.IsZero() {
		errs = append(errs, errors.New("updated_at is required"))
	}
	return errors.Join(errs...)
}

type ProviderArtifactDeliveryStatusUpdate struct {
	ProtocolVersion string                         `json:"protocol_version,omitempty"`
	DeliveryID      string                         `json:"delivery_id"`
	Status          ProviderArtifactDeliveryStatus `json:"status"`
	ProviderRef     string                         `json:"provider_ref,omitempty"`
	ErrorHash       string                         `json:"error_hash,omitempty"`
	ObservedAt      time.Time                      `json:"observed_at,omitempty"`
}

type ProviderArtifactDeliveryAction struct {
	ProtocolVersion string                           `json:"protocol_version,omitempty"`
	DeliveryID      string                           `json:"delivery_id"`
	PluginID        string                           `json:"plugin_id"`
	ProviderID      string                           `json:"provider_id"`
	ContractID      string                           `json:"contract_id"`
	ContractVersion string                           `json:"contract_version,omitempty"`
	StepType        string                           `json:"step_type"`
	Operation       string                           `json:"operation"`
	SubmitEndpoint  string                           `json:"submit_endpoint,omitempty"`
	Artifact        ProviderArtifactDeliveryArtifact `json:"artifact"`
	TaskID          string                           `json:"task_id"`
	ProofID         string                           `json:"proof_id"`
}

func validProviderArtifactDeliveryStatus(status ProviderArtifactDeliveryStatus) bool {
	switch status {
	case ProviderArtifactDeliveryPending, ProviderArtifactDeliveryDelivered, ProviderArtifactDeliveryFailed, ProviderArtifactDeliveryDeadLetter:
		return true
	default:
		return false
	}
}

type ProviderRuntimeContract struct {
	Profiles []ProviderRuntimeProfile `json:"profiles"`
}

func (c ProviderRuntimeContract) Validate() error {
	var errs []error
	if len(c.Profiles) == 0 {
		errs = append(errs, errors.New("runtime_contract.profiles is required"))
	}
	seen := map[string]struct{}{}
	for i, profile := range c.Profiles {
		if err := profile.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("runtime_contract.profiles[%d]: %w", i, err))
		}
		if profile.ID != "" {
			if _, exists := seen[profile.ID]; exists {
				errs = append(errs, fmt.Errorf("runtime_contract.profiles[%d].id %q is duplicated", i, profile.ID))
			}
			seen[profile.ID] = struct{}{}
		}
	}
	return errors.Join(errs...)
}

func (c ProviderRuntimeContract) SupportsProduct(product NetworkProduct) bool {
	_, ok := c.RuntimeProfileForRequirements(product.SecurityFloor)
	return ok
}

func (c ProviderRuntimeContract) RuntimeProfileForRequirements(req PlacementRequirements) (ProviderRuntimeProfile, bool) {
	for _, profile := range c.Profiles {
		if profile.ExecutorProvider == req.ExecutorProvider &&
			profile.ExecutionSecurityTier == req.ExecutionSecurityTier &&
			profile.ProofTier == req.ProofTier {
			return profile, true
		}
	}
	return ProviderRuntimeProfile{}, false
}

type ProviderRuntimeProfile struct {
	ID                           string                    `json:"id"`
	RuntimeProfile               RuntimeProfile            `json:"runtime_profile"`
	ExecutorProvider             string                    `json:"executor_provider"`
	ExecutionSecurityTier        ExecutionSecurityTier     `json:"execution_security_tier"`
	ProofTier                    ProofTier                 `json:"proof_tier"`
	AllowedRuntimeTools          []ContainerRuntimeTool    `json:"allowed_runtime_tools,omitempty"`
	ImageDigestRequired          bool                      `json:"image_digest_required"`
	RootFSDigestRequired         bool                      `json:"rootfs_digest_required"`
	AllowedMountRefs             []string                  `json:"allowed_mount_refs,omitempty"`
	WritablePaths                []string                  `json:"writable_paths,omitempty"`
	WritableRootFS               RuntimePermission         `json:"writable_rootfs"`
	Privileged                   RuntimePermission         `json:"privileged"`
	HostNamespaces               RuntimePermission         `json:"host_namespaces"`
	HostSocket                   RuntimePermission         `json:"host_socket"`
	SeccompDisable               RuntimePermission         `json:"seccomp_disable"`
	NoNewPrivilegesDisable       RuntimePermission         `json:"no_new_privileges_disable"`
	AllowedCapabilities          []string                  `json:"allowed_capabilities,omitempty"`
	ConformanceProfiles          []string                  `json:"conformance_profiles,omitempty"`
	UpstreamClientConformance    UpstreamClientConformance `json:"upstream_client_conformance,omitempty"`
	UpstreamClientEvidenceRef    string                    `json:"upstream_client_evidence_ref,omitempty"`
	UpstreamClientEvidenceDigest string                    `json:"upstream_client_evidence_digest,omitempty"`
	HostWorkspaceSupported       bool                      `json:"host_workspace_supported,omitempty"`
	ResiduePolicy                ResiduePolicy             `json:"residue_policy,omitzero"`
	WASM                         WASMRuntimeContract       `json:"wasm,omitzero"`
}

type WASMRuntimeContract struct {
	ABI               string            `json:"abi"`
	ComponentRef      string            `json:"component_ref"`
	ComponentDigest   string            `json:"component_digest"`
	Features          []string          `json:"features,omitempty"`
	MaxMemoryBytes    int64             `json:"max_memory_bytes,omitempty"`
	MaxRuntimeSeconds int               `json:"max_runtime_seconds,omitempty"`
	Filesystem        RuntimePermission `json:"filesystem"`
	Network           RuntimePermission `json:"network"`
	NativeHostUpdates RuntimePermission `json:"native_host_updates,omitempty"`
	BrowserWorker     bool              `json:"browser_worker,omitempty"`
}

func (p ProviderRuntimeProfile) Validate() error {
	var errs []error
	if err := validateIdentifier("id", p.ID); err != nil {
		errs = append(errs, err)
	}
	if !validRuntimeProfile(p.RuntimeProfile) {
		errs = append(errs, fmt.Errorf("runtime_profile %q is unsupported", p.RuntimeProfile))
	}
	if err := validateIdentifier("executor_provider", p.ExecutorProvider); err != nil {
		errs = append(errs, err)
	}
	if !validExecutionSecurityTier(p.ExecutionSecurityTier) || p.ExecutionSecurityTier == ExecutionTrustedNative {
		errs = append(errs, fmt.Errorf("execution_security_tier %q is unsupported", p.ExecutionSecurityTier))
	}
	if !validProofTier(p.ProofTier) || p.ProofTier == ProofReceiptOnly {
		errs = append(errs, fmt.Errorf("proof_tier %q is unsupported", p.ProofTier))
	}
	if err := p.ResiduePolicy.Validate(ResiduePolicyValidation{
		NoWorkspaceAllowed: !p.HostWorkspaceSupported,
	}); err != nil {
		errs = append(errs, fmt.Errorf("residue_policy: %w", err))
	}
	if p.RuntimeProfile == RuntimeProfileWASMComponent || p.RuntimeProfile == RuntimeProfileBrowserWorker {
		if p.HostWorkspaceSupported {
			errs = append(errs, errors.New("host workspace must be unsupported for wasm runtime profiles"))
		}
		if p.ExecutionSecurityTier != ExecutionWASMCapability {
			errs = append(errs, errors.New("wasm runtime_profile requires execution_security_tier wasm-capability"))
		}
		if p.ImageDigestRequired || p.RootFSDigestRequired {
			errs = append(errs, errors.New("image and rootfs digests must be disabled for wasm runtime profiles"))
		}
		if len(p.AllowedRuntimeTools) != 0 || len(p.AllowedMountRefs) != 0 || len(p.WritablePaths) != 0 {
			errs = append(errs, errors.New("container runtime tools, mounts, and writable paths must be empty for wasm runtime profiles"))
		}
		if err := p.WASM.Validate(p.RuntimeProfile); err != nil {
			errs = append(errs, fmt.Errorf("wasm: %w", err))
		}
	} else {
		if p.ExecutionSecurityTier == ExecutionWASMCapability {
			errs = append(errs, errors.New("execution_security_tier wasm-capability requires wasm runtime_profile"))
		}
		if len(p.AllowedRuntimeTools) == 0 {
			errs = append(errs, errors.New("allowed_runtime_tools is required"))
		}
		for i, tool := range p.AllowedRuntimeTools {
			if !validContainerRuntimeTool(tool) {
				errs = append(errs, fmt.Errorf("allowed_runtime_tools[%d] %q is unsupported", i, tool))
			}
		}
		if !p.ImageDigestRequired || !p.RootFSDigestRequired {
			errs = append(errs, errors.New("image and rootfs digests are required"))
		}
		if len(p.AllowedMountRefs) == 0 {
			errs = append(errs, errors.New("allowed_mount_refs is required"))
		}
		for i, ref := range p.AllowedMountRefs {
			if err := validateIdentifier(fmt.Sprintf("allowed_mount_refs[%d]", i), ref); err != nil {
				errs = append(errs, err)
			}
		}
	}
	for i, path := range p.WritablePaths {
		if !validContainerAbsolutePath(path) {
			errs = append(errs, fmt.Errorf("writable_paths[%d] %q is invalid", i, path))
		}
	}
	for _, permission := range []struct {
		name  string
		value RuntimePermission
	}{
		{"writable_rootfs", p.WritableRootFS},
		{"privileged", p.Privileged},
		{"host_namespaces", p.HostNamespaces},
		{"host_socket", p.HostSocket},
		{"seccomp_disable", p.SeccompDisable},
		{"no_new_privileges_disable", p.NoNewPrivilegesDisable},
	} {
		if !validRuntimePermission(permission.value) {
			errs = append(errs, fmt.Errorf("%s %q is unsupported", permission.name, permission.value))
			continue
		}
		if permission.name != "writable_rootfs" && permission.value != RuntimePermissionForbidden {
			errs = append(errs, fmt.Errorf("%s must be forbidden", permission.name))
		}
	}
	for i, capability := range p.AllowedCapabilities {
		if capability == "" || strings.ToUpper(capability) != capability || strings.ContainsAny(capability, " \t\r\n\x00") {
			errs = append(errs, fmt.Errorf("allowed_capabilities[%d] %q is invalid", i, capability))
		}
	}
	if len(p.ConformanceProfiles) == 0 {
		errs = append(errs, errors.New("conformance_profiles is required"))
	}
	for i, profile := range p.ConformanceProfiles {
		if err := validateIdentifier(fmt.Sprintf("conformance_profiles[%d]", i), profile); err != nil {
			errs = append(errs, err)
		}
	}
	if p.UpstreamClientConformance != "" {
		if !validUpstreamClientConformance(p.UpstreamClientConformance) {
			errs = append(errs, fmt.Errorf("upstream_client_conformance %q is unsupported", p.UpstreamClientConformance))
		}
		if p.UpstreamClientConformance == UpstreamClientConformanceRealClient && !contains(p.ConformanceProfiles, "upstream-client-v1") {
			errs = append(errs, errors.New("upstream_client_conformance real-client requires upstream-client-v1 conformance profile"))
		}
		if p.UpstreamClientConformance == UpstreamClientConformanceRealClient {
			if p.UpstreamClientEvidenceRef == "" {
				errs = append(errs, errors.New("upstream_client_evidence_ref is required for real-client upstream conformance"))
			} else if err := validateScopedRef("upstream_client_evidence_ref", p.UpstreamClientEvidenceRef, "artifact://"); err != nil {
				errs = append(errs, err)
			}
			if p.UpstreamClientEvidenceDigest == "" {
				errs = append(errs, errors.New("upstream_client_evidence_digest is required for real-client upstream conformance"))
			} else if !validSHA256Ref(p.UpstreamClientEvidenceDigest) {
				errs = append(errs, errors.New("upstream_client_evidence_digest must be sha256:<64 hex chars>"))
			}
		}
	}
	return errors.Join(errs...)
}

func (w WASMRuntimeContract) Validate(profile RuntimeProfile) error {
	var errs []error
	if strings.TrimSpace(w.ABI) == "" {
		errs = append(errs, errors.New("abi is required"))
	}
	if err := validateComponentRef("component_ref", w.ComponentRef); err != nil {
		errs = append(errs, err)
	}
	if !validSHA256Ref(w.ComponentDigest) {
		errs = append(errs, errors.New("component_digest must be sha256:<64 hex chars>"))
	}
	if w.MaxMemoryBytes <= 0 {
		errs = append(errs, errors.New("max_memory_bytes must be positive"))
	}
	if w.MaxRuntimeSeconds <= 0 {
		errs = append(errs, errors.New("max_runtime_seconds must be positive"))
	}
	if !validRuntimePermission(w.Filesystem) {
		errs = append(errs, fmt.Errorf("filesystem %q is unsupported", w.Filesystem))
	}
	if !validRuntimePermission(w.Network) {
		errs = append(errs, fmt.Errorf("network %q is unsupported", w.Network))
	}
	if w.NativeHostUpdates != "" && !validRuntimePermission(w.NativeHostUpdates) {
		errs = append(errs, fmt.Errorf("native_host_updates %q is unsupported", w.NativeHostUpdates))
	}
	if profile == RuntimeProfileBrowserWorker {
		if !w.BrowserWorker {
			errs = append(errs, errors.New("browser_worker must be true for browser worker runtime profile"))
		}
		if w.Filesystem != RuntimePermissionForbidden {
			errs = append(errs, errors.New("filesystem must be forbidden for browser worker runtime profile"))
		}
		if w.NativeHostUpdates != "" && w.NativeHostUpdates != RuntimePermissionForbidden {
			errs = append(errs, errors.New("native_host_updates must be forbidden for browser worker runtime profile"))
		}
	}
	return errors.Join(errs...)
}

func (p ResiduePolicy) Validate(v ResiduePolicyValidation) error {
	var errs []error
	if !validResidueMode(p.Mode, true) {
		errs = append(errs, fmt.Errorf("mode %q is unsupported", p.Mode))
	}
	seen := map[ResidueMode]struct{}{}
	for i, mode := range p.AllowedModes {
		if !validResidueMode(mode, false) {
			errs = append(errs, fmt.Errorf("allowed_modes[%d] %q is unsupported", i, mode))
			continue
		}
		if _, exists := seen[mode]; exists {
			errs = append(errs, fmt.Errorf("allowed_modes[%d] %q is duplicated", i, mode))
		}
		seen[mode] = struct{}{}
	}
	if p.Mode != "" && len(p.AllowedModes) > 0 {
		if _, exists := seen[p.Mode]; !exists {
			errs = append(errs, fmt.Errorf("mode %q is not in allowed_modes", p.Mode))
		}
	}
	if v.NoWorkspaceAllowed && p.UsesReusableWorkspace() {
		errs = append(errs, errors.New("reusable residue requires host workspace support"))
	}
	if p.Mode == ResidueModeSessionBound || (v.RequireSessionKey && p.Mode == ResidueModeSessionBound) {
		if strings.TrimSpace(p.SessionKey) == "" {
			errs = append(errs, errors.New("session_key is required for session-bound residue"))
		} else if strings.TrimSpace(p.SessionKey) != p.SessionKey || strings.ContainsAny(p.SessionKey, "\x00\r\n\t") {
			errs = append(errs, errors.New("session_key must not contain control whitespace or surrounding whitespace"))
		}
	}
	if p.Mode != ResidueModeSessionBound && p.SessionKey != "" {
		errs = append(errs, errors.New("session_key requires session-bound residue mode"))
	}
	if p.Mode == ResidueModeWorkerBound && v.RequireExplicitWorkerBound && !p.ExplicitWorkerBound {
		errs = append(errs, errors.New("explicit_worker_bound is required for worker-bound residue"))
	}
	if p.PolicyHash != "" && !validSHA256Ref(p.PolicyHash) {
		errs = append(errs, errors.New("policy_hash must be sha256:<64 hex chars>"))
	}
	if v.RequirePolicyHash && p.UsesReusableWorkspace() && p.PolicyHash == "" {
		errs = append(errs, errors.New("policy_hash is required for reusable residue"))
	}
	if p.MaxAgeSeconds < 0 {
		errs = append(errs, errors.New("max_age_seconds must not be negative"))
	}
	if p.MaxReuseCount < 0 {
		errs = append(errs, errors.New("max_reuse_count must not be negative"))
	}
	return errors.Join(errs...)
}

func (p ResiduePolicy) IsZero() bool {
	return p.Mode == "" &&
		len(p.AllowedModes) == 0 &&
		p.SessionKey == "" &&
		p.PolicyHash == "" &&
		p.MaxAgeSeconds == 0 &&
		p.MaxReuseCount == 0 &&
		!p.WipeOnFailure &&
		!p.ExplicitWorkerBound
}

func (p ResiduePolicy) UsesReusableWorkspace() bool {
	switch p.Mode {
	case ResidueModeProviderBound, ResidueModeWorkerBound, ResidueModeSessionBound:
		return true
	default:
		return false
	}
}

func DefaultProviderRuntimeProfile(executorProvider string, tier ExecutionSecurityTier, proof ProofTier) ProviderRuntimeProfile {
	runtimeProfile := RuntimeProfileSandboxedOCI
	writableRootFS := RuntimePermissionForbidden
	capabilities := []string{}
	conformance := []string{"sandboxed-oci-v1"}
	mountRefs := []string{"workspace"}
	writablePaths := []string{"/tmp"}
	runtimeTools := []ContainerRuntimeTool{ContainerRuntimePodman, ContainerRuntimeDocker, ContainerRuntimeNerdctl}
	imageDigestRequired := true
	rootFSDigestRequired := true
	switch executorProvider {
	case "sandboxed-container-build":
		runtimeProfile = RuntimeProfileContainerBuild
		writableRootFS = RuntimePermissionExplicit
		capabilities = []string{"CHOWN", "FOWNER"}
		conformance = []string{"container-build-v1"}
		writablePaths = []string{"/tmp", "/wfcompute-build"}
	case "service-sandboxed-container", "node-service-sandboxed-container":
		runtimeProfile = RuntimeProfileServiceOCI
		conformance = []string{"service-oci-v1"}
		if executorProvider == "node-service-sandboxed-container" {
			mountRefs = []string{"workspace", "node-data"}
		}
	case "wasm-component":
		runtimeProfile = RuntimeProfileWASMComponent
		conformance = []string{"wasm-component-v1"}
		mountRefs = nil
		writablePaths = nil
		runtimeTools = nil
		imageDigestRequired = false
		rootFSDigestRequired = false
	}
	hostWorkspaceSupported := runtimeProfile != RuntimeProfileWASMComponent && runtimeProfile != RuntimeProfileBrowserWorker
	return ProviderRuntimeProfile{
		ID:                     executorProvider + "-" + string(tier) + "-" + string(proof) + "-runtime",
		RuntimeProfile:         runtimeProfile,
		ExecutorProvider:       executorProvider,
		ExecutionSecurityTier:  tier,
		ProofTier:              proof,
		AllowedRuntimeTools:    runtimeTools,
		ImageDigestRequired:    imageDigestRequired,
		RootFSDigestRequired:   rootFSDigestRequired,
		AllowedMountRefs:       mountRefs,
		WritablePaths:          writablePaths,
		WritableRootFS:         writableRootFS,
		Privileged:             RuntimePermissionForbidden,
		HostNamespaces:         RuntimePermissionForbidden,
		HostSocket:             RuntimePermissionForbidden,
		SeccompDisable:         RuntimePermissionForbidden,
		NoNewPrivilegesDisable: RuntimePermissionForbidden,
		AllowedCapabilities:    capabilities,
		ConformanceProfiles:    conformance,
		HostWorkspaceSupported: hostWorkspaceSupported,
	}
}

type ProviderRuntimeContractOptions struct {
	ConformanceProfiles          []string
	UpstreamClientConformance    UpstreamClientConformance
	UpstreamClientEvidenceRef    string
	UpstreamClientEvidenceDigest string
}

func DefaultProviderRuntimeContract(executors []string, tiers []ExecutionSecurityTier, proofs []ProofTier, options ProviderRuntimeContractOptions) ProviderRuntimeContract {
	profiles := make([]ProviderRuntimeProfile, 0, len(executors)*len(tiers)*len(proofs))
	for _, executorProvider := range executors {
		for _, tier := range tiers {
			for _, proof := range proofs {
				profile := DefaultProviderRuntimeProfile(executorProvider, tier, proof)
				profile.ConformanceProfiles = append(profile.ConformanceProfiles, options.ConformanceProfiles...)
				if options.UpstreamClientConformance != "" {
					profile.UpstreamClientConformance = options.UpstreamClientConformance
				}
				profile.UpstreamClientEvidenceRef = options.UpstreamClientEvidenceRef
				profile.UpstreamClientEvidenceDigest = options.UpstreamClientEvidenceDigest
				profiles = append(profiles, profile)
			}
		}
	}
	return ProviderRuntimeContract{Profiles: profiles}
}

type NetworkProduct struct {
	ProtocolVersion      string                    `json:"protocol_version"`
	ID                   string                    `json:"id"`
	DisplayName          string                    `json:"display_name,omitempty"`
	Purpose              string                    `json:"purpose,omitempty"`
	OperatingMode        NetworkOperatingMode      `json:"operating_mode"`
	OrgID                string                    `json:"org_id"`
	PoolID               string                    `json:"pool_id"`
	WorkloadKinds        []string                  `json:"workload_kinds"`
	SecurityFloor        PlacementRequirements     `json:"security_floor"`
	ProofPolicy          ProofPolicy               `json:"proof_policy,omitzero"`
	SessionPolicy        SessionPolicy             `json:"session_policy,omitzero"`
	ProviderConfig       ProviderConfig            `json:"provider_config,omitzero"`
	NetworkModes         []NetworkMode             `json:"network_modes"`
	PlacementConstraints PlacementConstraints      `json:"placement_constraints,omitzero"`
	RewardPolicy         string                    `json:"reward_policy"`
	AbusePolicy          string                    `json:"abuse_policy"`
	SettlementAccountID  string                    `json:"settlement_account_id,omitempty"`
	SettlementTarget     SettlementTarget          `json:"settlement_target,omitzero"`
	CryptoRewardRouting  CryptoRewardRoutingPolicy `json:"crypto_reward_routing,omitzero"`
	ContributionPolicy   ContributionPolicy        `json:"contribution_policy,omitzero"`
	AccessPolicy         AccessPolicy              `json:"access_policy,omitzero"`
	ResiduePolicy        ResiduePolicy             `json:"residue_policy,omitzero"`
	AdmissionMode        string                    `json:"admission_mode,omitempty"`
	AllowPublic          bool                      `json:"allow_public,omitempty"`
	CreatedAt            time.Time                 `json:"created_at,omitempty"`
}

func (p NetworkProduct) Validate() error {
	var errs []error
	if p.ProtocolVersion != Version {
		errs = append(errs, fmt.Errorf("protocol_version must be %q", Version))
	}
	if err := validateNetworkProductID(p.ID); err != nil {
		errs = append(errs, fmt.Errorf("id: %w", err))
	}
	if p.OrgID == "" {
		errs = append(errs, errors.New("org_id is required"))
	}
	if p.PoolID == "" {
		errs = append(errs, errors.New("pool_id is required"))
	}
	if p.OperatingMode == "" {
		errs = append(errs, errors.New("operating_mode is required"))
	} else if !validNetworkOperatingMode(p.OperatingMode) {
		errs = append(errs, fmt.Errorf("operating_mode %q is unsupported", p.OperatingMode))
	}
	if len(p.WorkloadKinds) == 0 {
		errs = append(errs, errors.New("workload_kinds is required"))
	}
	for i, kind := range p.WorkloadKinds {
		if !validWorkloadKind(WorkloadKind(strings.TrimSpace(kind))) {
			errs = append(errs, fmt.Errorf("workload_kinds[%d] %q is unknown", i, kind))
		}
	}
	switch p.OperatingMode {
	case NetworkModeBatch:
	case NetworkModeWarmService, NetworkModeInferenceAPI:
		if !contains(p.WorkloadKinds, string(WorkloadService)) {
			errs = append(errs, fmt.Errorf("operating_mode %q requires service workload kind", p.OperatingMode))
		}
	case NetworkModeNodeService:
		if !contains(p.WorkloadKinds, string(WorkloadNodeService)) {
			errs = append(errs, fmt.Errorf("operating_mode %q requires node-service workload kind", p.OperatingMode))
		}
	}
	if p.SecurityFloor.ExecutorProvider == "" {
		errs = append(errs, errors.New("security_floor.executor_provider is required"))
	}
	if p.SecurityFloor.ExecutionSecurityTier == "" {
		errs = append(errs, errors.New("security_floor.execution_security_tier is required"))
	} else if !validExecutionSecurityTier(p.SecurityFloor.ExecutionSecurityTier) {
		errs = append(errs, fmt.Errorf("security_floor.execution_security_tier %q is unknown", p.SecurityFloor.ExecutionSecurityTier))
	} else if p.SecurityFloor.ExecutionSecurityTier == ExecutionTrustedNative {
		errs = append(errs, errors.New("security_floor.execution_security_tier trusted-native is not allowed for network products"))
	}
	if p.SecurityFloor.ProofTier == "" {
		errs = append(errs, errors.New("security_floor.proof_tier is required"))
	} else if !validProofTier(p.SecurityFloor.ProofTier) {
		errs = append(errs, fmt.Errorf("security_floor.proof_tier %q is unknown", p.SecurityFloor.ProofTier))
	} else if p.SecurityFloor.ProofTier == ProofReceiptOnly {
		errs = append(errs, errors.New("security_floor.proof_tier receipt-only is not allowed for network products"))
	} else if err := ValidateProofPolicy(p.SecurityFloor.ProofTier, p.ProofPolicy); err != nil {
		errs = append(errs, fmt.Errorf("proof_policy: %w", err))
	}
	if len(p.NetworkModes) == 0 {
		errs = append(errs, errors.New("network_modes is required"))
	}
	for i, mode := range p.NetworkModes {
		if !validNetworkMode(normalizeNetworkMode(mode)) {
			errs = append(errs, fmt.Errorf("network_modes[%d] %q is unsupported", i, mode))
		}
	}
	if strings.TrimSpace(p.RewardPolicy) == "" {
		errs = append(errs, errors.New("reward_policy is required"))
	}
	if strings.TrimSpace(p.AbusePolicy) == "" {
		errs = append(errs, errors.New("abuse_policy is required"))
	}
	if p.SettlementAccountID != "" {
		if err := validateIdentifier("settlement_account_id", p.SettlementAccountID); err != nil {
			errs = append(errs, err)
		}
	}
	if err := p.SettlementTarget.Validate(p.SettlementAccountID); err != nil {
		errs = append(errs, fmt.Errorf("settlement_target: %w", err))
	}
	if err := p.CryptoRewardRouting.Validate(p.SettlementTarget); err != nil {
		errs = append(errs, fmt.Errorf("crypto_reward_routing: %w", err))
	}
	if err := p.PlacementConstraints.Validate(p.SettlementTarget.Kind == SettlementTargetTreasuryWallet, p.SettlementTarget); err != nil {
		errs = append(errs, fmt.Errorf("placement_constraints: %w", err))
	}
	if err := p.ContributionPolicy.ValidateForRewardPolicy(p.RewardPolicy, p.SettlementTarget); err != nil {
		errs = append(errs, fmt.Errorf("contribution_policy: %w", err))
	}
	if err := p.AccessPolicy.Validate(); err != nil {
		errs = append(errs, fmt.Errorf("access_policy: %w", err))
	}
	if err := p.ResiduePolicy.Validate(ResiduePolicyValidation{}); err != nil {
		errs = append(errs, fmt.Errorf("residue_policy: %w", err))
	}
	if !p.ResiduePolicy.IsZero() && !networkProductAdmitsShortLivedResidue(p) {
		errs = append(errs, errors.New("residue_policy is only for short-lived workload products; service products use session_policy and durable service storage"))
	}
	if strings.EqualFold(strings.TrimSpace(p.RewardPolicy), "upstream-credit") {
		if p.OperatingMode != NetworkModeWarmService && p.OperatingMode != NetworkModeNodeService {
			errs = append(errs, errors.New("upstream-credit products require headless warm-service or node-service operating mode"))
		}
		if !contains(p.WorkloadKinds, string(WorkloadService)) && !contains(p.WorkloadKinds, string(WorkloadNodeService)) {
			errs = append(errs, errors.New("upstream-credit products require service or node-service workload kind"))
		}
	}
	if p.OperatingMode == NetworkModeNodeService && strings.EqualFold(strings.TrimSpace(p.RewardPolicy), "profit-share") {
		if p.SettlementTarget.Kind != SettlementTargetTreasuryWallet {
			errs = append(errs, errors.New("node-service profit-share products require settlement_target.kind treasury_wallet"))
		}
		if strings.TrimSpace(p.SettlementTarget.Network) == "" {
			errs = append(errs, errors.New("node-service profit-share products require settlement_target.network"))
		}
		if strings.TrimSpace(p.SettlementTarget.WalletRef) == "" {
			errs = append(errs, errors.New("node-service profit-share products require settlement_target.wallet_ref"))
		}
	}
	if err := p.SessionPolicy.ValidateForOperatingMode(p.OperatingMode); err != nil {
		errs = append(errs, fmt.Errorf("session_policy: %w", err))
	}
	if err := p.ProviderConfig.Validate(); err != nil {
		errs = append(errs, fmt.Errorf("provider_config: %w", err))
	}
	return errors.Join(errs...)
}

func networkProductAdmitsShortLivedResidue(p NetworkProduct) bool {
	for _, kind := range p.WorkloadKinds {
		switch WorkloadKind(strings.TrimSpace(kind)) {
		case WorkloadService, WorkloadNodeService:
			continue
		default:
			return true
		}
	}
	return false
}

type PlacementConstraints struct {
	Chain                string          `json:"chain,omitempty"`
	Role                 string          `json:"role,omitempty"`
	MinDiskBytes         int64           `json:"min_disk_bytes,omitempty"`
	MinMemoryBytes       int64           `json:"min_memory_bytes,omitempty"`
	MinBandwidthMbps     int64           `json:"min_bandwidth_mbps,omitempty"`
	RequiresIngress      bool            `json:"requires_ingress,omitempty"`
	RequiredCapabilities []string        `json:"required_capabilities,omitempty"`
	WalletRef            string          `json:"wallet_ref,omitempty"`
	StorageGuidance      StorageGuidance `json:"storage_guidance,omitzero"`
}

type PlacementCapabilities struct {
	DiskBytes      int64    `json:"disk_bytes,omitempty"`
	MemoryBytes    int64    `json:"memory_bytes,omitempty"`
	BandwidthMbps  int64    `json:"bandwidth_mbps,omitempty"`
	IngressCapable bool     `json:"ingress_capable,omitempty"`
	CapabilityTags []string `json:"capability_tags,omitempty"`
}

type PlacementNetworkPolicy struct {
	AllowIngress bool `json:"allow_ingress,omitempty"`
}

func PlacementConstraintsSatisfiedBy(c PlacementConstraints, caps PlacementCapabilities, task PlacementNetworkPolicy) error {
	if c.IsZero() {
		return nil
	}
	var errs []error
	if c.MinDiskBytes > 0 && caps.DiskBytes < c.MinDiskBytes {
		errs = append(errs, fmt.Errorf("worker disk_bytes %d below placement min_disk_bytes %d", caps.DiskBytes, c.MinDiskBytes))
	}
	if c.MinMemoryBytes > 0 && caps.MemoryBytes < c.MinMemoryBytes {
		errs = append(errs, fmt.Errorf("worker memory_bytes %d below placement min_memory_bytes %d", caps.MemoryBytes, c.MinMemoryBytes))
	}
	if c.MinBandwidthMbps > 0 && caps.BandwidthMbps < c.MinBandwidthMbps {
		errs = append(errs, fmt.Errorf("worker bandwidth_mbps %d below placement min_bandwidth_mbps %d", caps.BandwidthMbps, c.MinBandwidthMbps))
	}
	if c.RequiresIngress && (!caps.IngressCapable || !task.AllowIngress) {
		errs = append(errs, errors.New("worker/task does not satisfy placement ingress requirement"))
	}
	capabilityTags := map[string]struct{}{}
	for _, tag := range caps.CapabilityTags {
		capabilityTags[tag] = struct{}{}
	}
	for _, tag := range c.RequiredCapabilities {
		if _, ok := capabilityTags[tag]; !ok {
			errs = append(errs, fmt.Errorf("worker missing placement required capability %q", tag))
		}
	}
	return errors.Join(errs...)
}

func (c PlacementConstraints) Validate(required bool, target SettlementTarget) error {
	if c.IsZero() {
		if required {
			return errors.New("placement constraints are required")
		}
		return nil
	}
	var errs []error
	if c.Chain == "" {
		if required {
			errs = append(errs, errors.New("chain is required"))
		}
	} else if err := validateIdentifier("chain", c.Chain); err != nil {
		errs = append(errs, err)
	}
	if c.Role == "" {
		if required {
			errs = append(errs, errors.New("role is required"))
		}
	} else if err := validateIdentifier("role", c.Role); err != nil {
		errs = append(errs, err)
	}
	if c.MinDiskBytes <= 0 {
		if required {
			errs = append(errs, errors.New("min_disk_bytes must be positive"))
		} else if c.MinDiskBytes < 0 {
			errs = append(errs, errors.New("min_disk_bytes must not be negative"))
		}
	}
	if c.MinMemoryBytes <= 0 {
		if required {
			errs = append(errs, errors.New("min_memory_bytes must be positive"))
		} else if c.MinMemoryBytes < 0 {
			errs = append(errs, errors.New("min_memory_bytes must not be negative"))
		}
	}
	if c.MinBandwidthMbps <= 0 {
		if required {
			errs = append(errs, errors.New("min_bandwidth_mbps must be positive"))
		} else if c.MinBandwidthMbps < 0 {
			errs = append(errs, errors.New("min_bandwidth_mbps must not be negative"))
		}
	}
	seen := map[string]struct{}{}
	for i, tag := range c.RequiredCapabilities {
		if err := validateIdentifier(fmt.Sprintf("required_capabilities[%d]", i), tag); err != nil {
			errs = append(errs, err)
			continue
		}
		if _, ok := seen[tag]; ok {
			errs = append(errs, fmt.Errorf("required_capabilities[%d] %q is duplicated", i, tag))
		}
		seen[tag] = struct{}{}
	}
	if c.WalletRef == "" {
		if required {
			errs = append(errs, errors.New("wallet_ref is required"))
		}
	} else {
		if !strings.HasPrefix(c.WalletRef, "wallet://") {
			errs = append(errs, errors.New("wallet_ref must use wallet:// scope"))
		}
		if strings.ContainsAny(c.WalletRef, " \t\r\n?&#") {
			errs = append(errs, errors.New("wallet_ref must not contain whitespace, query, fragment, or parameter delimiters"))
		}
		if target.WalletRef != "" && c.WalletRef != target.WalletRef {
			errs = append(errs, errors.New("wallet_ref must match settlement_target.wallet_ref"))
		}
	}
	if err := c.StorageGuidance.Validate(); err != nil {
		errs = append(errs, fmt.Errorf("storage_guidance: %w", err))
	}
	return errors.Join(errs...)
}

func (c PlacementConstraints) IsZero() bool {
	return c.Chain == "" &&
		c.Role == "" &&
		c.MinDiskBytes == 0 &&
		c.MinMemoryBytes == 0 &&
		c.MinBandwidthMbps == 0 &&
		!c.RequiresIngress &&
		len(c.RequiredCapabilities) == 0 &&
		c.WalletRef == "" &&
		c.StorageGuidance == (StorageGuidance{})
}

type StorageGuidance struct {
	Mode                         string `json:"mode,omitempty"`
	MinDiskBytes                 int64  `json:"min_disk_bytes,omitempty"`
	MinDiskDisplay               string `json:"min_disk_display,omitempty"`
	RecommendedDiskBytes         int64  `json:"recommended_disk_bytes,omitempty"`
	RecommendedDiskDisplay       string `json:"recommended_disk_display,omitempty"`
	GrowthMarginBytes            int64  `json:"growth_margin_bytes,omitempty"`
	GrowthMarginDisplay          string `json:"growth_margin_display,omitempty"`
	DurableVolumeRequired        bool   `json:"durable_volume_required,omitempty"`
	PreserveOnUpdate             bool   `json:"preserve_on_update,omitempty"`
	PreserveOnUninstall          bool   `json:"preserve_on_uninstall,omitempty"`
	PruningSupported             bool   `json:"pruning_supported,omitempty"`
	SnapshotVerificationRequired bool   `json:"snapshot_verification_required,omitempty"`
}

func (g StorageGuidance) Validate() error {
	if g == (StorageGuidance{}) {
		return nil
	}
	var errs []error
	if g.Mode != "" {
		if err := validateIdentifier("mode", g.Mode); err != nil {
			errs = append(errs, err)
		}
	}
	if g.MinDiskBytes < 0 {
		errs = append(errs, errors.New("min_disk_bytes must not be negative"))
	}
	if g.RecommendedDiskBytes < 0 {
		errs = append(errs, errors.New("recommended_disk_bytes must not be negative"))
	}
	if g.GrowthMarginBytes < 0 {
		errs = append(errs, errors.New("growth_margin_bytes must not be negative"))
	}
	if g.MinDiskBytes > 0 && g.MinDiskDisplay == "" {
		errs = append(errs, errors.New("min_disk_display is required when min_disk_bytes is set"))
	}
	if g.RecommendedDiskBytes > 0 && g.RecommendedDiskDisplay == "" {
		errs = append(errs, errors.New("recommended_disk_display is required when recommended_disk_bytes is set"))
	}
	if g.GrowthMarginBytes > 0 && g.GrowthMarginDisplay == "" {
		errs = append(errs, errors.New("growth_margin_display is required when growth_margin_bytes is set"))
	}
	if g.MinDiskBytes > 0 && g.RecommendedDiskBytes > 0 && g.RecommendedDiskBytes < g.MinDiskBytes {
		errs = append(errs, errors.New("recommended_disk_bytes must be at least min_disk_bytes"))
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{"min_disk_display", g.MinDiskDisplay},
		{"recommended_disk_display", g.RecommendedDiskDisplay},
		{"growth_margin_display", g.GrowthMarginDisplay},
	} {
		if strings.TrimSpace(field.value) != field.value || strings.ContainsAny(field.value, "\t\r\n") {
			errs = append(errs, fmt.Errorf("%s must not contain surrounding whitespace or control whitespace", field.name))
		}
	}
	return errors.Join(errs...)
}

type ContributionAuthority string

const (
	ContributionAuthorityWFCompute ContributionAuthority = "wfcompute"
	ContributionAuthorityUpstream  ContributionAuthority = "upstream"
)

type ContributionPolicy struct {
	ValidationAuthority ContributionAuthority `json:"validation_authority,omitempty"`
	CreditAuthority     ContributionAuthority `json:"credit_authority,omitempty"`
	MonetaryPayouts     bool                  `json:"monetary_payouts,omitempty"`
}

func (p ContributionPolicy) ValidateForRewardPolicy(rewardPolicy string, target SettlementTarget) error {
	if p == (ContributionPolicy{}) && !strings.EqualFold(strings.TrimSpace(rewardPolicy), "upstream-credit") {
		return nil
	}
	var errs []error
	if p.ValidationAuthority == "" {
		errs = append(errs, errors.New("validation_authority is required"))
	} else if !validContributionAuthority(p.ValidationAuthority) {
		errs = append(errs, fmt.Errorf("validation_authority %q is unsupported", p.ValidationAuthority))
	}
	if p.CreditAuthority == "" {
		errs = append(errs, errors.New("credit_authority is required"))
	} else if !validContributionAuthority(p.CreditAuthority) {
		errs = append(errs, fmt.Errorf("credit_authority %q is unsupported", p.CreditAuthority))
	}
	if strings.EqualFold(strings.TrimSpace(rewardPolicy), "upstream-credit") {
		if p.ValidationAuthority != ContributionAuthorityUpstream {
			errs = append(errs, errors.New("validation_authority must be upstream for upstream-credit"))
		}
		if p.CreditAuthority != ContributionAuthorityUpstream {
			errs = append(errs, errors.New("credit_authority must be upstream for upstream-credit"))
		}
		if p.MonetaryPayouts {
			errs = append(errs, errors.New("monetary_payouts must be false for upstream-credit"))
		}
		switch target.Kind {
		case "", SettlementTargetBadgeLedger:
		default:
			errs = append(errs, fmt.Errorf("settlement_target.kind %q is not allowed for upstream-credit", target.Kind))
		}
	}
	return errors.Join(errs...)
}

func validContributionAuthority(authority ContributionAuthority) bool {
	switch authority {
	case ContributionAuthorityWFCompute, ContributionAuthorityUpstream:
		return true
	default:
		return false
	}
}

type SettlementTargetKind string

const (
	SettlementTargetPointsLedger        SettlementTargetKind = "points_ledger"
	SettlementTargetPayrollAccount      SettlementTargetKind = "payroll_account"
	SettlementTargetBadgeLedger         SettlementTargetKind = "badge_ledger"
	SettlementTargetFiatTokenTreasury   SettlementTargetKind = "fiat_token_treasury"
	SettlementTargetTreasuryWallet      SettlementTargetKind = "treasury_wallet"
	SettlementTargetParticipantWallet   SettlementTargetKind = "participant_wallet"
	SettlementTargetExternalDestination SettlementTargetKind = "external_destination"
)

type SettlementTarget struct {
	Kind      SettlementTargetKind `json:"kind,omitempty"`
	AccountID string               `json:"account_id,omitempty"`
	Network   string               `json:"network,omitempty"`
	WalletRef string               `json:"wallet_ref,omitempty"`
}

func (t SettlementTarget) Validate(settlementAccountID string) error {
	if t == (SettlementTarget{}) {
		return nil
	}
	var errs []error
	switch t.Kind {
	case SettlementTargetPointsLedger, SettlementTargetPayrollAccount, SettlementTargetBadgeLedger, SettlementTargetFiatTokenTreasury, SettlementTargetTreasuryWallet, SettlementTargetParticipantWallet, SettlementTargetExternalDestination:
	case "":
		errs = append(errs, errors.New("kind is required"))
	default:
		errs = append(errs, fmt.Errorf("kind %q is unsupported", t.Kind))
	}
	if t.AccountID != "" {
		if err := validateIdentifier("account_id", t.AccountID); err != nil {
			errs = append(errs, err)
		}
	}
	if settlementAccountID != "" && t.AccountID != "" && t.AccountID != settlementAccountID {
		errs = append(errs, fmt.Errorf("account_id %q must match settlement_account_id %q", t.AccountID, settlementAccountID))
	}
	if t.Network != "" {
		if err := validateIdentifier("network", t.Network); err != nil {
			errs = append(errs, err)
		}
	}
	if t.WalletRef != "" {
		if strings.ContainsAny(t.WalletRef, " \t\r\n") {
			errs = append(errs, errors.New("wallet_ref must not contain whitespace"))
		}
		if strings.ContainsAny(t.WalletRef, "?&#") {
			errs = append(errs, errors.New("wallet_ref must not contain query, fragment, or parameter delimiters"))
		}
	}
	if t.Kind == SettlementTargetTreasuryWallet {
		if strings.TrimSpace(t.AccountID) == "" {
			errs = append(errs, errors.New("account_id is required for treasury_wallet"))
		}
		if strings.TrimSpace(t.Network) == "" {
			errs = append(errs, errors.New("network is required for treasury_wallet"))
		}
		if strings.TrimSpace(t.WalletRef) == "" {
			errs = append(errs, errors.New("wallet_ref is required for treasury_wallet"))
		}
	}
	if t.Kind == SettlementTargetExternalDestination {
		if strings.TrimSpace(t.AccountID) == "" {
			errs = append(errs, errors.New("account_id is required for external_destination"))
		}
	}
	return errors.Join(errs...)
}

type CryptoRewardCustodyMode string

const CryptoRewardCustodyTreasuryThenDistribute CryptoRewardCustodyMode = "treasury_then_distribute"

type CryptoRewardDistributionMode string

const CryptoRewardDistributionContributionShare CryptoRewardDistributionMode = "contribution_share"

type CryptoRewardParticipantWalletSource string

const CryptoRewardParticipantAccountWallet CryptoRewardParticipantWalletSource = "account_wallet"

type CryptoRewardRoutingPolicy struct {
	Network                 string                              `json:"network,omitempty"`
	TreasuryAccountID       string                              `json:"treasury_account_id,omitempty"`
	TreasuryWalletRef       string                              `json:"treasury_wallet_ref,omitempty"`
	CustodyMode             CryptoRewardCustodyMode             `json:"custody_mode,omitempty"`
	DistributionMode        CryptoRewardDistributionMode        `json:"distribution_mode,omitempty"`
	ParticipantWalletSource CryptoRewardParticipantWalletSource `json:"participant_wallet_source,omitempty"`
	ManagementFeeBps        int                                 `json:"management_fee_bps,omitempty"`
}

func (p CryptoRewardRoutingPolicy) Validate(target SettlementTarget) error {
	if p == (CryptoRewardRoutingPolicy{}) {
		return nil
	}
	var errs []error
	if strings.TrimSpace(p.Network) == "" {
		errs = append(errs, errors.New("network is required"))
	} else if err := validateIdentifier("network", p.Network); err != nil {
		errs = append(errs, err)
	}
	if strings.TrimSpace(p.TreasuryAccountID) == "" {
		errs = append(errs, errors.New("treasury_account_id is required"))
	} else if err := validateIdentifier("treasury_account_id", p.TreasuryAccountID); err != nil {
		errs = append(errs, err)
	}
	if strings.TrimSpace(p.TreasuryWalletRef) == "" {
		errs = append(errs, errors.New("treasury_wallet_ref is required"))
	} else if err := validateScopedRef("treasury_wallet_ref", p.TreasuryWalletRef, "wallet://"); err != nil {
		errs = append(errs, err)
	} else if strings.ContainsAny(p.TreasuryWalletRef, " \t\r\n?&#") {
		errs = append(errs, errors.New("treasury_wallet_ref must not contain whitespace, query, fragment, or ampersand"))
	}
	switch p.CustodyMode {
	case CryptoRewardCustodyTreasuryThenDistribute:
	case "":
		errs = append(errs, errors.New("custody_mode is required"))
	default:
		errs = append(errs, fmt.Errorf("custody_mode %q is unsupported", p.CustodyMode))
	}
	switch p.DistributionMode {
	case CryptoRewardDistributionContributionShare:
	case "":
		errs = append(errs, errors.New("distribution_mode is required"))
	default:
		errs = append(errs, fmt.Errorf("distribution_mode %q is unsupported", p.DistributionMode))
	}
	switch p.ParticipantWalletSource {
	case CryptoRewardParticipantAccountWallet:
	case "":
		errs = append(errs, errors.New("participant_wallet_source is required"))
	default:
		errs = append(errs, fmt.Errorf("participant_wallet_source %q is unsupported", p.ParticipantWalletSource))
	}
	if p.ManagementFeeBps < 0 || p.ManagementFeeBps > 10_000 {
		errs = append(errs, errors.New("management_fee_bps must be between 0 and 10000"))
	}
	if target.Kind != SettlementTargetTreasuryWallet {
		errs = append(errs, errors.New("settlement_target.kind must be treasury_wallet"))
	}
	if target.Network != "" && p.Network != target.Network {
		errs = append(errs, fmt.Errorf("network %q must match settlement_target.network %q", p.Network, target.Network))
	}
	if target.AccountID != "" && p.TreasuryAccountID != target.AccountID {
		errs = append(errs, fmt.Errorf("treasury_account_id %q must match settlement_target.account_id %q", p.TreasuryAccountID, target.AccountID))
	}
	if target.WalletRef != "" && p.TreasuryWalletRef != target.WalletRef {
		errs = append(errs, errors.New("treasury_wallet_ref must match settlement_target.wallet_ref"))
	}
	return errors.Join(errs...)
}

type ProviderConformanceEvidence struct {
	ProtocolVersion       string    `json:"protocol_version"`
	ID                    string    `json:"id"`
	PluginID              string    `json:"plugin_id"`
	ProviderID            string    `json:"provider_id"`
	ContractID            string    `json:"contract_id"`
	Version               string    `json:"version"`
	RuntimeProfileID      string    `json:"runtime_profile_id"`
	ConformanceProfile    string    `json:"conformance_profile"`
	UpstreamClientName    string    `json:"upstream_client_name"`
	UpstreamClientVersion string    `json:"upstream_client_version"`
	EvidenceRef           string    `json:"evidence_ref"`
	EvidenceDigest        string    `json:"evidence_digest"`
	ObservedAt            time.Time `json:"observed_at"`
	CreatedAt             time.Time `json:"created_at,omitempty"`
}

func (e ProviderConformanceEvidence) Validate() error {
	var errs []error
	if e.ProtocolVersion != Version {
		errs = append(errs, fmt.Errorf("protocol_version must be %q", Version))
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{"id", e.ID},
		{"plugin_id", e.PluginID},
		{"provider_id", e.ProviderID},
		{"contract_id", e.ContractID},
		{"runtime_profile_id", e.RuntimeProfileID},
		{"conformance_profile", e.ConformanceProfile},
	} {
		if err := validateIdentifier(field.name, field.value); err != nil {
			errs = append(errs, err)
		}
	}
	if strings.TrimSpace(e.Version) == "" || strings.ContainsAny(e.Version, "\t\r\n\x00") {
		errs = append(errs, errors.New("version is required"))
	}
	if strings.TrimSpace(e.UpstreamClientName) == "" {
		errs = append(errs, errors.New("upstream_client_name is required"))
	}
	if strings.TrimSpace(e.UpstreamClientVersion) == "" {
		errs = append(errs, errors.New("upstream_client_version is required"))
	}
	if err := validateScopedRef("evidence_ref", e.EvidenceRef, "artifact://"); err != nil {
		errs = append(errs, err)
	}
	if !validSHA256Ref(e.EvidenceDigest) {
		errs = append(errs, errors.New("evidence_digest must be sha256:<64 hex chars>"))
	}
	if e.ObservedAt.IsZero() {
		errs = append(errs, errors.New("observed_at is required"))
	}
	return errors.Join(errs...)
}

func (c *ProviderContract) ApplyProviderConformanceEvidence(evidence ProviderConformanceEvidence) error {
	if c == nil {
		return errors.New("provider contract is nil")
	}
	if err := evidence.Validate(); err != nil {
		return err
	}
	if evidence.PluginID != c.PluginID ||
		evidence.ProviderID != c.ProviderID ||
		evidence.ContractID != c.ContractID ||
		evidence.Version != c.Version {
		return fmt.Errorf("provider conformance evidence %q does not match provider contract tuple", evidence.ID)
	}
	for i := range c.RuntimeContract.Profiles {
		if c.RuntimeContract.Profiles[i].ID != evidence.RuntimeProfileID {
			continue
		}
		c.RuntimeContract.Profiles[i].UpstreamClientConformance = UpstreamClientConformanceRealClient
		c.RuntimeContract.Profiles[i].UpstreamClientEvidenceRef = evidence.EvidenceRef
		c.RuntimeContract.Profiles[i].UpstreamClientEvidenceDigest = evidence.EvidenceDigest
		if !containsString(c.RuntimeContract.Profiles[i].ConformanceProfiles, evidence.ConformanceProfile) {
			c.RuntimeContract.Profiles[i].ConformanceProfiles = append(c.RuntimeContract.Profiles[i].ConformanceProfiles, evidence.ConformanceProfile)
		}
		return nil
	}
	return fmt.Errorf("provider conformance evidence %q runtime profile %q does not match provider contract", evidence.ID, evidence.RuntimeProfileID)
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

type ProviderUpstreamClientRequirement struct {
	ProtocolVersion       string                      `json:"protocol_version"`
	PluginID              string                      `json:"plugin_id"`
	ProviderID            string                      `json:"provider_id"`
	ContractID            string                      `json:"contract_id"`
	Version               string                      `json:"version"`
	RuntimeProfileID      string                      `json:"runtime_profile_id"`
	ConformanceProfile    string                      `json:"conformance_profile"`
	DefaultConformance    UpstreamClientConformance   `json:"default_conformance"`
	RealClientConformance UpstreamClientConformance   `json:"real_client_conformance"`
	UpstreamClientName    string                      `json:"upstream_client_name"`
	VersionProbeCommand   []string                    `json:"version_probe_command,omitempty"`
	ImagePolicy           ProviderUpstreamImagePolicy `json:"image_policy"`
	RequiredEvidence      []string                    `json:"required_evidence,omitempty"`
	Notes                 []string                    `json:"notes,omitempty"`
}

func (r ProviderUpstreamClientRequirement) Validate() error {
	var errs []error
	for _, field := range []struct {
		name  string
		value string
	}{
		{"protocol_version", r.ProtocolVersion},
		{"plugin_id", r.PluginID},
		{"provider_id", r.ProviderID},
		{"contract_id", r.ContractID},
		{"version", r.Version},
		{"runtime_profile_id", r.RuntimeProfileID},
		{"conformance_profile", r.ConformanceProfile},
		{"upstream_client_name", r.UpstreamClientName},
	} {
		if strings.TrimSpace(field.value) == "" {
			errs = append(errs, fmt.Errorf("%s is required", field.name))
		}
	}
	if strings.TrimSpace(r.Version) != r.Version || strings.ContainsAny(r.Version, "\t\r\n\x00") {
		errs = append(errs, errors.New("version is required"))
	}
	if strings.TrimSpace(r.UpstreamClientName) != r.UpstreamClientName || strings.ContainsAny(r.UpstreamClientName, "\t\r\n\x00") {
		errs = append(errs, errors.New("upstream_client_name is required"))
	}
	if r.ProtocolVersion != Version {
		errs = append(errs, fmt.Errorf("protocol_version must be %q", Version))
	}
	if r.DefaultConformance != UpstreamClientConformanceShapeOnly {
		errs = append(errs, errors.New("default_conformance must be shape-only"))
	}
	if r.RealClientConformance != UpstreamClientConformanceRealClient {
		errs = append(errs, errors.New("real_client_conformance must be real-client"))
	}
	if r.ConformanceProfile != "upstream-client-v1" {
		errs = append(errs, errors.New("conformance_profile must be upstream-client-v1"))
	}
	if err := r.ImagePolicy.Validate(); err != nil {
		errs = append(errs, err)
	}
	for i, value := range r.VersionProbeCommand {
		if strings.TrimSpace(value) == "" || strings.ContainsAny(value, "\t\r\n\x00") {
			errs = append(errs, fmt.Errorf("version_probe_command[%d] is required", i))
		}
	}
	for i, value := range r.RequiredEvidence {
		if strings.TrimSpace(value) == "" || strings.ContainsAny(value, "\t\r\n\x00") {
			errs = append(errs, fmt.Errorf("required_evidence[%d] is required", i))
		}
	}
	for i, value := range r.Notes {
		if strings.TrimSpace(value) == "" || strings.ContainsAny(value, "\t\r\n\x00") {
			errs = append(errs, fmt.Errorf("notes[%d] is required", i))
		}
	}
	return errors.Join(errs...)
}

type ProviderUpstreamImagePolicy struct {
	DigestPinnedImageRequired     bool     `json:"digest_pinned_image_required"`
	OperatorSuppliedImageRequired bool     `json:"operator_supplied_image_required,omitempty"`
	RecommendedImageRef           string   `json:"recommended_image_ref,omitempty"`
	KnownImageRefs                []string `json:"known_image_refs,omitempty"`
}

func (p ProviderUpstreamImagePolicy) Validate() error {
	var errs []error
	if !p.DigestPinnedImageRequired {
		errs = append(errs, errors.New("digest_pinned_image_required must be true"))
	}
	if !p.OperatorSuppliedImageRequired && strings.TrimSpace(p.RecommendedImageRef) == "" {
		errs = append(errs, errors.New("recommended_image_ref is required unless operator_supplied_image_required is true"))
	}
	if p.RecommendedImageRef != "" && (strings.TrimSpace(p.RecommendedImageRef) == "" || strings.ContainsAny(p.RecommendedImageRef, "\t\r\n\x00")) {
		errs = append(errs, errors.New("recommended_image_ref is invalid"))
	}
	for i, ref := range p.KnownImageRefs {
		if strings.TrimSpace(ref) == "" || strings.ContainsAny(ref, "\t\r\n\x00") {
			errs = append(errs, fmt.Errorf("known_image_refs[%d] is required", i))
		}
	}
	return errors.Join(errs...)
}

func CanonicalHash(value any) string {
	data, err := json.Marshal(value)
	if err != nil {
		data = []byte(fmt.Sprintf("%v", value))
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func validNetworkOperatingMode(mode NetworkOperatingMode) bool {
	switch mode {
	case NetworkModeBatch, NetworkModeWarmService, NetworkModeNodeService, NetworkModeInferenceAPI:
		return true
	default:
		return false
	}
}

func validWorkloadKind(kind WorkloadKind) bool {
	switch kind {
	case WorkloadCommand,
		WorkloadContainerBuild,
		WorkloadDockerComposeBuild,
		WorkloadBenchmark,
		WorkloadTraining,
		WorkloadService,
		WorkloadNodeService,
		WorkloadContentCache,
		WorkloadSupervisor,
		WorkloadProductCapture,
		WorkloadProvider,
		WorkloadWASMComponent:
		return true
	default:
		return false
	}
}

func validRuntimeProfile(profile RuntimeProfile) bool {
	switch profile {
	case RuntimeProfileSandboxedOCI, RuntimeProfileContainerBuild, RuntimeProfileServiceOCI, RuntimeProfileWASMComponent, RuntimeProfileBrowserWorker:
		return true
	default:
		return false
	}
}

func validExecutionSecurityTier(tier ExecutionSecurityTier) bool {
	switch tier {
	case ExecutionTrustedNative,
		ExecutionHardenedContainer,
		ExecutionSandboxedContainer,
		ExecutionMicroVM,
		ExecutionConfidentialCPU,
		ExecutionConfidentialGPU,
		ExecutionWASMCapability:
		return true
	default:
		return false
	}
}

func validProofTier(tier ProofTier) bool {
	switch tier {
	case ProofReceiptOnly,
		ProofArtifactHash,
		ProofReplicatedQuorum,
		ProofAttestedReceipt,
		ProofAttestedQuorum,
		ProofZKReplay:
		return true
	default:
		return false
	}
}

func validRuntimeAdapterKind(kind RuntimeAdapterKind) bool {
	switch kind {
	case RuntimeAdapterExecution, RuntimeAdapterServiceRun, RuntimeAdapterServiceSession:
		return true
	default:
		return false
	}
}

func validRuntimeWorkspacePolicy(policy RuntimeWorkspacePolicy) bool {
	switch policy {
	case RuntimeWorkspaceUnavailable, RuntimeWorkspaceOptional, RuntimeWorkspaceRequired:
		return true
	default:
		return false
	}
}

func normalizeNetworkMode(mode NetworkMode) NetworkMode {
	mode = NetworkMode(strings.TrimSpace(string(mode)))
	if mode == "" {
		return NetworkModeDirect
	}
	return mode
}

func validNetworkMode(mode NetworkMode) bool {
	switch mode {
	case NetworkModeDirect, NetworkModeRelay, NetworkModeTailnet, NetworkModeTor, NetworkModeP2P, NetworkModeOffline:
		return true
	default:
		return false
	}
}

func validateNetworkProductID(id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return errors.New("product_id is required")
	}
	if strings.ContainsAny(id, " \t\r\n/:?&#") {
		return errors.New("product_id must not contain whitespace, scheme, path, query, or fragment")
	}
	return nil
}

func validContainerRuntimeTool(tool ContainerRuntimeTool) bool {
	switch tool {
	case ContainerRuntimePodman, ContainerRuntimeDocker, ContainerRuntimeNerdctl, ContainerRuntimeAppleContainer:
		return true
	default:
		return false
	}
}

func validRuntimePermission(permission RuntimePermission) bool {
	switch permission {
	case RuntimePermissionForbidden, RuntimePermissionExplicit, RuntimePermissionAllowed:
		return true
	default:
		return false
	}
}

func validAccessVisibility(visibility AccessVisibility) bool {
	switch visibility {
	case "", AccessVisibilityPrivate, AccessVisibilityNetwork, AccessVisibilityPublic:
		return true
	default:
		return false
	}
}

func validUpstreamClientConformance(conformance UpstreamClientConformance) bool {
	switch conformance {
	case UpstreamClientConformanceShapeOnly, UpstreamClientConformanceRealClient:
		return true
	default:
		return false
	}
}

func validResidueMode(mode ResidueMode, allowEmpty bool) bool {
	switch mode {
	case "":
		return allowEmpty
	case ResidueModeIsolated, ResidueModeNone, ResidueModeProviderBound, ResidueModeWorkerBound, ResidueModeSessionBound:
		return true
	default:
		return false
	}
}

func validSHA256Ref(value string) bool {
	if !strings.HasPrefix(value, "sha256:") {
		return false
	}
	hexPart := strings.TrimPrefix(value, "sha256:")
	if len(hexPart) != 64 {
		return false
	}
	_, err := hex.DecodeString(hexPart)
	return err == nil
}

func validSHA256Digest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") {
		return false
	}
	hexPart := strings.TrimPrefix(value, "sha256:")
	if len(hexPart) != 64 {
		return false
	}
	_, err := hex.DecodeString(hexPart)
	return err == nil && strings.ToLower(hexPart) == hexPart
}

func validateNetworkHostname(hostname string) error {
	hostname = strings.TrimSpace(hostname)
	if hostname == "" {
		return errors.New("hostname is required")
	}
	if strings.ContainsAny(hostname, " \t\r\n/:?&#") {
		return errors.New("hostname must not contain whitespace, scheme, path, query, or fragment")
	}
	if _, err := netip.ParseAddr(hostname); err == nil {
		return errors.New("hostname must not be an IP address")
	}
	return nil
}

func validateIngressHeaderName(name string) error {
	name = strings.TrimSpace(strings.ToLower(name))
	if name == "" {
		return errors.New("header name is required")
	}
	if strings.ContainsAny(name, " \t\r\n:") {
		return fmt.Errorf("header %q is invalid", name)
	}
	switch name {
	case "authorization", "cookie", "proxy-authorization", "x-api-key", "x-auth-token", "x-forwarded-authorization":
		return fmt.Errorf("header %q is not allowed", name)
	default:
		return nil
	}
}

func validateIdentifier(name, id string) error {
	trimmed := strings.TrimSpace(id)
	if trimmed == "" {
		return fmt.Errorf("%s is required", name)
	}
	if trimmed != id {
		return fmt.Errorf("%s must not contain leading or trailing whitespace", name)
	}
	if strings.ContainsAny(id, " \t\r\n/:?&#") {
		return fmt.Errorf("%s must not contain whitespace, scheme, path, query, or fragment", name)
	}
	return nil
}

func validateScopedRef(name, value, scheme string) error {
	if !strings.HasPrefix(value, scheme) {
		return fmt.Errorf("%s must use %s scoped ref", name, scheme)
	}
	if strings.Contains(value, "..") {
		return fmt.Errorf("%s must not contain parent traversal", name)
	}
	if strings.TrimPrefix(value, scheme) == "" {
		return fmt.Errorf("%s must include scoped path", name)
	}
	return nil
}

func validateComponentRef(name, value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("%s is required", name)
	}
	for _, prefix := range []string{"artifact://", "content://", "provider://"} {
		if strings.HasPrefix(value, prefix) && !strings.ContainsAny(value, " \t\r\n\x00") {
			return nil
		}
	}
	return fmt.Errorf("%s must use artifact://, content://, or provider:// ref", name)
}

func validContainerAbsolutePath(value string) bool {
	return strings.HasPrefix(value, "/") && !strings.Contains(value, "\x00") && path.Clean(value) == value && !strings.Contains(value, "..")
}

func validProviderArtifactName(name string) bool {
	return strings.TrimSpace(name) != "" &&
		!strings.ContainsAny(name, "\\/\x00\r\n\t") &&
		name != "." &&
		name != ".."
}

func validProviderReturnSubmitEndpoint(value string) bool {
	return strings.HasPrefix(value, "/") &&
		!strings.Contains(value, "://") &&
		!strings.ContainsAny(value, " \t\r\n\x00?#") &&
		path.Clean(value) == value &&
		!strings.Contains(value, "..")
}

func ProviderPluginRequiresUpstreamClientConformance(pluginID string) bool {
	switch pluginID {
	case "workflow-plugin-volunteer-science", "workflow-plugin-crypto":
		return true
	default:
		return false
	}
}

func contains[T comparable](values []T, want T) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
