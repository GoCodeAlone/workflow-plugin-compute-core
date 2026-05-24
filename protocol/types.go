package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"path"
	"strings"
	"time"
)

const Version = "compute.v1alpha1"

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
	Name             string `json:"name"`
	Required         bool   `json:"required,omitempty"`
	ContentType      string `json:"content_type,omitempty"`
	MaxBytes         int64  `json:"max_bytes,omitempty"`
	RetentionSeconds int    `json:"retention_seconds,omitempty"`
	Forwardable      bool   `json:"forwardable,omitempty"`
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
	for _, profile := range c.Profiles {
		if profile.ExecutorProvider == product.SecurityFloor.ExecutorProvider &&
			profile.ExecutionSecurityTier == product.SecurityFloor.ExecutionSecurityTier &&
			profile.ProofTier == product.SecurityFloor.ProofTier {
			return true
		}
	}
	return false
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
	return ProviderRuntimeProfile{
		ID:                        executorProvider + "-" + string(tier) + "-" + string(proof) + "-runtime",
		RuntimeProfile:            RuntimeProfileServiceOCI,
		ExecutorProvider:          executorProvider,
		ExecutionSecurityTier:     tier,
		ProofTier:                 proof,
		AllowedRuntimeTools:       []ContainerRuntimeTool{ContainerRuntimePodman, ContainerRuntimeDocker, ContainerRuntimeNerdctl},
		ImageDigestRequired:       true,
		RootFSDigestRequired:      true,
		AllowedMountRefs:          []string{"workspace", "node-data"},
		WritablePaths:             []string{"/tmp"},
		WritableRootFS:            RuntimePermissionForbidden,
		Privileged:                RuntimePermissionForbidden,
		HostNamespaces:            RuntimePermissionForbidden,
		HostSocket:                RuntimePermissionForbidden,
		SeccompDisable:            RuntimePermissionForbidden,
		NoNewPrivilegesDisable:    RuntimePermissionForbidden,
		ConformanceProfiles:       []string{"service-oci-v1"},
		HostWorkspaceSupported:    true,
		UpstreamClientConformance: UpstreamClientConformanceShapeOnly,
	}
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
	SessionPolicy        SessionPolicy             `json:"session_policy,omitzero"`
	ProviderConfig       ProviderConfig            `json:"provider_config,omitzero"`
	NetworkModes         []NetworkMode             `json:"network_modes"`
	PlacementConstraints PlacementConstraints      `json:"placement_constraints,omitzero"`
	RewardPolicy         string                    `json:"reward_policy"`
	AbusePolicy          string                    `json:"abuse_policy"`
	SettlementAccountID  string                    `json:"settlement_account_id,omitempty"`
	SettlementTarget     SettlementTarget          `json:"settlement_target,omitzero"`
	CryptoRewardRouting  CryptoRewardRoutingPolicy `json:"crypto_reward_routing,omitzero"`
}

func (p NetworkProduct) Validate() error {
	var errs []error
	for _, field := range []struct {
		name  string
		value string
	}{
		{"protocol_version", p.ProtocolVersion},
		{"id", p.ID},
		{"org_id", p.OrgID},
		{"pool_id", p.PoolID},
		{"reward_policy", p.RewardPolicy},
		{"abuse_policy", p.AbusePolicy},
	} {
		if strings.TrimSpace(field.value) == "" {
			errs = append(errs, fmt.Errorf("%s is required", field.name))
		}
	}
	if p.ProtocolVersion != Version {
		errs = append(errs, fmt.Errorf("protocol_version must be %q", Version))
	}
	if p.OperatingMode != NetworkModeNodeService {
		errs = append(errs, fmt.Errorf("operating_mode %q is unsupported", p.OperatingMode))
	}
	if len(p.WorkloadKinds) == 0 || len(p.NetworkModes) == 0 {
		errs = append(errs, errors.New("workload_kinds and network_modes are required"))
	}
	if p.SecurityFloor.ExecutorProvider == "" || p.SecurityFloor.ExecutionSecurityTier == "" || p.SecurityFloor.ProofTier == "" {
		errs = append(errs, errors.New("security_floor is required"))
	}
	if p.ProviderConfig.PluginID == "" || p.ProviderConfig.ProviderID == "" || p.ProviderConfig.ContractID == "" {
		errs = append(errs, errors.New("provider_config identity is required"))
	}
	if p.PlacementConstraints.Chain == "" || p.PlacementConstraints.Role == "" || p.PlacementConstraints.MinDiskBytes <= 0 {
		errs = append(errs, errors.New("placement_constraints chain, role, and min_disk_bytes are required"))
	}
	if p.SettlementTarget.Kind == "" || p.SettlementTarget.Network == "" || p.SettlementTarget.WalletRef == "" {
		errs = append(errs, errors.New("settlement_target is required"))
	}
	return errors.Join(errs...)
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

type SettlementTargetKind string

const SettlementTargetTreasuryWallet SettlementTargetKind = "treasury_wallet"

type SettlementTarget struct {
	Kind      SettlementTargetKind `json:"kind,omitempty"`
	AccountID string               `json:"account_id,omitempty"`
	Network   string               `json:"network,omitempty"`
	WalletRef string               `json:"wallet_ref,omitempty"`
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
