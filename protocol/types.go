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

const NetworkModeNodeService NetworkOperatingMode = "node-service"

type RuntimeProfile string

const RuntimeProfileServiceOCI RuntimeProfile = "service-oci-v1"

type ContainerRuntimeTool string

const (
	ContainerRuntimePodman  ContainerRuntimeTool = "podman"
	ContainerRuntimeDocker  ContainerRuntimeTool = "docker"
	ContainerRuntimeNerdctl ContainerRuntimeTool = "nerdctl"
)

type RuntimePermission string

const RuntimePermissionForbidden RuntimePermission = "forbidden"

type UpstreamClientConformance string

const (
	UpstreamClientConformanceShapeOnly  UpstreamClientConformance = "shape-only"
	UpstreamClientConformanceRealClient UpstreamClientConformance = "real-client"
)

type ExecutionSecurityTier string

const ExecutionSandboxedContainer ExecutionSecurityTier = "sandboxed-container"

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
	PluginID   string `json:"plugin_id,omitempty"`
	ProviderID string `json:"provider_id,omitempty"`
	ContractID string `json:"contract_id,omitempty"`
	Version    string `json:"version,omitempty"`
	ConfigRef  string `json:"config_ref,omitempty"`
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
	if len(c.OperatingModes) == 0 || len(c.WorkloadKinds) == 0 || len(c.ExecutorProviders) == 0 || len(c.ExecutionSecurityTiers) == 0 || len(c.ProofTiers) == 0 || len(c.NetworkModes) == 0 {
		errs = append(errs, errors.New("provider contract capability lists are required"))
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
}

func (p ProviderRuntimeProfile) Validate() error {
	var errs []error
	if p.ID == "" {
		errs = append(errs, errors.New("id is required"))
	}
	if p.RuntimeProfile != RuntimeProfileServiceOCI {
		errs = append(errs, fmt.Errorf("runtime_profile %q is unsupported", p.RuntimeProfile))
	}
	if p.ExecutorProvider == "" {
		errs = append(errs, errors.New("executor_provider is required"))
	}
	if p.ExecutionSecurityTier != ExecutionSandboxedContainer {
		errs = append(errs, fmt.Errorf("execution_security_tier %q is unsupported", p.ExecutionSecurityTier))
	}
	if p.ProofTier != ProofArtifactHash {
		errs = append(errs, fmt.Errorf("proof_tier %q is unsupported", p.ProofTier))
	}
	if !p.ImageDigestRequired || !p.RootFSDigestRequired {
		errs = append(errs, errors.New("image and rootfs digests are required"))
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
		if permission.value != RuntimePermissionForbidden {
			errs = append(errs, fmt.Errorf("%s must be forbidden", permission.name))
		}
	}
	return errors.Join(errs...)
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

func contains[T comparable](values []T, want T) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
