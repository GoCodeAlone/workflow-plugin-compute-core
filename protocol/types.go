package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
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
	ExecutionSandboxedContainer ExecutionSecurityTier = "sandboxed-container"
	ExecutionWASMCapability     ExecutionSecurityTier = "wasm-capability"
)

type ProofTier string

const ProofArtifactHash ProofTier = "artifact-hash"

type NetworkMode string

const (
	NetworkModeDirect NetworkMode = "direct"
	NetworkModeRelay  NetworkMode = "relay"
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

type ProviderContract struct {
	ProtocolVersion        string                  `json:"protocol_version"`
	ID                     string                  `json:"id"`
	PluginID               string                  `json:"plugin_id"`
	ProviderID             string                  `json:"provider_id"`
	ContractID             string                  `json:"contract_id"`
	Version                string                  `json:"version"`
	DisplayName            string                  `json:"display_name,omitempty"`
	ConfigSchemaRef        string                  `json:"config_schema_ref"`
	ConfigSchemaDigest     string                  `json:"config_schema_digest"`
	OperatingModes         []NetworkOperatingMode  `json:"operating_modes"`
	WorkloadKinds          []string                `json:"workload_kinds"`
	ExecutorProviders      []string                `json:"executor_providers"`
	ExecutionSecurityTiers []ExecutionSecurityTier `json:"execution_security_tiers"`
	ProofTiers             []ProofTier             `json:"proof_tiers"`
	NetworkModes           []NetworkMode           `json:"network_modes"`
	RuntimeContract        ProviderRuntimeContract `json:"runtime_contract"`
}

func (c ProviderContract) Validate() error {
	var errs []error
	for _, field := range []struct {
		name  string
		value string
	}{
		{"protocol_version", c.ProtocolVersion},
		{"id", c.ID},
		{"plugin_id", c.PluginID},
		{"provider_id", c.ProviderID},
		{"contract_id", c.ContractID},
		{"version", c.Version},
		{"config_schema_ref", c.ConfigSchemaRef},
		{"config_schema_digest", c.ConfigSchemaDigest},
	} {
		if strings.TrimSpace(field.value) == "" {
			errs = append(errs, fmt.Errorf("%s is required", field.name))
		}
	}
	if c.ProtocolVersion != Version {
		errs = append(errs, fmt.Errorf("protocol_version must be %q", Version))
	}
	if c.ConfigSchemaDigest != "" && !validSHA256Ref(c.ConfigSchemaDigest) {
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
	if len(c.ExecutionSecurityTiers) == 0 {
		errs = append(errs, errors.New("execution_security_tiers is required"))
	}
	if len(c.ProofTiers) == 0 {
		errs = append(errs, errors.New("proof_tiers is required"))
	}
	if len(c.NetworkModes) == 0 {
		errs = append(errs, errors.New("network_modes is required"))
	}
	if len(c.RuntimeContract.Profiles) == 0 {
		errs = append(errs, errors.New("runtime_contract.profiles is required"))
	}
	for i, profile := range c.RuntimeContract.Profiles {
		if err := profile.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("runtime_contract.profiles[%d]: %w", i, err))
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
	if !contains(c.OperatingModes, product.OperatingMode) {
		return fmt.Errorf("operating mode %q is unsupported", product.OperatingMode)
	}
	for _, kind := range product.WorkloadKinds {
		if !contains(c.WorkloadKinds, kind) {
			return fmt.Errorf("workload kind %q is unsupported", kind)
		}
	}
	for _, mode := range product.NetworkModes {
		if !contains(c.NetworkModes, mode) {
			return fmt.Errorf("network mode %q is unsupported", mode)
		}
	}
	return nil
}

type ProviderRuntimeContract struct {
	Profiles []ProviderRuntimeProfile `json:"profiles"`
}

type ProviderRuntimeProfile struct {
	ID                        string                    `json:"id"`
	RuntimeProfile            RuntimeProfile            `json:"runtime_profile"`
	ExecutorProvider          string                    `json:"executor_provider"`
	ExecutionSecurityTier     ExecutionSecurityTier     `json:"execution_security_tier"`
	ProofTier                 ProofTier                 `json:"proof_tier"`
	AllowedRuntimeTools       []ContainerRuntimeTool    `json:"allowed_runtime_tools,omitempty"`
	ImageDigestRequired       bool                      `json:"image_digest_required"`
	RootFSDigestRequired      bool                      `json:"rootfs_digest_required"`
	AllowedMountRefs          []string                  `json:"allowed_mount_refs,omitempty"`
	WritablePaths             []string                  `json:"writable_paths,omitempty"`
	WritableRootFS            RuntimePermission         `json:"writable_rootfs"`
	Privileged                RuntimePermission         `json:"privileged"`
	HostNamespaces            RuntimePermission         `json:"host_namespaces"`
	HostSocket                RuntimePermission         `json:"host_socket"`
	SeccompDisable            RuntimePermission         `json:"seccomp_disable"`
	NoNewPrivilegesDisable    RuntimePermission         `json:"no_new_privileges_disable"`
	ConformanceProfiles       []string                  `json:"conformance_profiles,omitempty"`
	UpstreamClientConformance UpstreamClientConformance `json:"upstream_client_conformance,omitempty"`
	HostWorkspaceSupported    bool                      `json:"host_workspace_supported,omitempty"`
	ResiduePolicy             ResiduePolicy             `json:"residue_policy,omitzero"`
	WASM                      WASMRuntimeContract       `json:"wasm,omitzero"`
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
	if p.ID == "" {
		errs = append(errs, errors.New("id is required"))
	}
	if !validRuntimeProfile(p.RuntimeProfile) {
		errs = append(errs, fmt.Errorf("runtime_profile %q is unsupported", p.RuntimeProfile))
	}
	if p.ExecutorProvider == "" {
		errs = append(errs, errors.New("executor_provider is required"))
	}
	if !validExecutionSecurityTier(p.ExecutionSecurityTier) {
		errs = append(errs, fmt.Errorf("execution_security_tier %q is unsupported", p.ExecutionSecurityTier))
	}
	if p.ProofTier != ProofArtifactHash {
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
		if !p.ImageDigestRequired || !p.RootFSDigestRequired {
			errs = append(errs, errors.New("image and rootfs digests are required"))
		}
		if len(p.AllowedMountRefs) == 0 {
			errs = append(errs, errors.New("allowed_mount_refs is required"))
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
	if !p.DigestPinnedImageRequired {
		return errors.New("digest_pinned_image_required must be true")
	}
	return nil
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
	case ExecutionSandboxedContainer, ExecutionWASMCapability:
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

func contains[T comparable](values []T, want T) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
