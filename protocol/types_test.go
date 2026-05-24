package protocol_test

import (
	"strings"
	"testing"
	"time"

	"github.com/GoCodeAlone/workflow-plugin-compute-core/protocol"
)

func TestProviderContractAcceptsBatchSandboxedOCI(t *testing.T) {
	contract := validBatchProviderContract()
	if err := contract.Validate(); err != nil {
		t.Fatalf("contract invalid: %v", err)
	}
}

func TestRuntimeDescriptorProducesExecutorRef(t *testing.T) {
	descriptor := protocol.RuntimeDescriptor{
		Name:                  "sandboxed-command",
		Version:               "v1.2.3",
		ExecutionSecurityTier: protocol.ExecutionSandboxedContainer,
		ProofTier:             protocol.ProofArtifactHash,
		ImageDigest:           "sha256:image",
		RootFSDigest:          "sha256:rootfs",
	}

	ref := descriptor.ExecutorRef("fallback")

	if ref.Provider != "sandboxed-command" || ref.Version != "v1.2.3" {
		t.Fatalf("executor identity = %+v", ref)
	}
	if ref.ExecutionSecurityTier != protocol.ExecutionSandboxedContainer || ref.ProofTier != protocol.ProofArtifactHash {
		t.Fatalf("executor proof metadata = %+v", ref)
	}
	if ref.ImageDigest != "sha256:image" || ref.RootFSDigest != "sha256:rootfs" {
		t.Fatalf("executor digests = %+v", ref)
	}
}

func TestRuntimeDescriptorFallsBackToProviderNameAndDevVersion(t *testing.T) {
	ref := (protocol.RuntimeDescriptor{}).ExecutorRef("command")

	if ref.Provider != "command" || ref.Version != "dev" {
		t.Fatalf("fallback executor ref = %+v", ref)
	}
}

func TestExecutorRefValidateForProofRequiresDigestsForNonNativeExecutors(t *testing.T) {
	ref := protocol.ExecutorRef{
		Provider:              "sandboxed-command",
		Version:               "dev",
		ExecutionSecurityTier: protocol.ExecutionSandboxedContainer,
		ProofTier:             protocol.ProofArtifactHash,
	}

	err := ref.ValidateForProof()
	if err == nil {
		t.Fatal("expected non-native executor without image digests to fail")
	}
	if !strings.Contains(err.Error(), "image_digest") || !strings.Contains(err.Error(), "rootfs_digest") {
		t.Fatalf("expected digest errors, got %v", err)
	}

	ref.ImageDigest = "sha256:image"
	ref.RootFSDigest = "sha256:rootfs"
	if err := ref.ValidateForProof(); err != nil {
		t.Fatalf("executor ref invalid with digests: %v", err)
	}
}

func TestResourceLimitsRejectNegativeValues(t *testing.T) {
	limits := protocol.ResourceLimits{
		CPUPercent:     -1,
		RuntimeSeconds: -1,
		OutputBytes:    -1,
	}

	err := limits.Validate()
	if err == nil {
		t.Fatal("expected negative resource limits to fail")
	}
	if !strings.Contains(err.Error(), "cpu_percent") ||
		!strings.Contains(err.Error(), "runtime_seconds") ||
		!strings.Contains(err.Error(), "output_bytes") {
		t.Fatalf("expected resource limit errors, got %v", err)
	}
}

func TestProviderContractRejectsMalformedConfigSchemaDigest(t *testing.T) {
	contract := validBatchProviderContract()
	contract.ConfigSchemaDigest = "sha256:not-hex"

	err := contract.Validate()
	if err == nil {
		t.Fatal("expected malformed digest to fail")
	}
	if !strings.Contains(err.Error(), "config_schema_digest") {
		t.Fatalf("expected config_schema_digest error, got %v", err)
	}
}

func TestProviderUpstreamImagePolicyRequiresRecommendedImageUnlessOperatorSupplied(t *testing.T) {
	policy := protocol.ProviderUpstreamImagePolicy{
		DigestPinnedImageRequired: true,
	}

	err := policy.Validate()
	if err == nil {
		t.Fatal("expected missing recommended image to fail")
	}
	if !strings.Contains(err.Error(), "recommended_image_ref") {
		t.Fatalf("expected recommended_image_ref error, got %v", err)
	}

	policy.OperatorSuppliedImageRequired = true
	if err := policy.Validate(); err != nil {
		t.Fatalf("operator-supplied image should not require recommended image: %v", err)
	}
}

func TestProviderUpstreamClientRequirementRejectsControlWhitespaceLists(t *testing.T) {
	req := protocol.ProviderUpstreamClientRequirement{
		ProtocolVersion:       protocol.Version,
		PluginID:              "workflow-plugin-crypto",
		ProviderID:            "ethereum-full-node",
		ContractID:            "ethereum-full-node.v1",
		Version:               "v1.0.0",
		RuntimeProfileID:      "sandboxed-container-runtime",
		ConformanceProfile:    "upstream-client-v1",
		DefaultConformance:    protocol.UpstreamClientConformanceShapeOnly,
		RealClientConformance: protocol.UpstreamClientConformanceRealClient,
		UpstreamClientName:    "geth",
		VersionProbeCommand:   []string{"geth version"},
		ImagePolicy: protocol.ProviderUpstreamImagePolicy{
			DigestPinnedImageRequired: true,
			RecommendedImageRef:       "ethereum/client-go@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
		RequiredEvidence: []string{"artifact://provider/evidence"},
		Notes:            []string{"operator may provide a digest-pinned image"},
	}
	if err := req.Validate(); err != nil {
		t.Fatalf("requirement invalid: %v", err)
	}

	req.VersionProbeCommand = []string{"geth\nversion"}
	if err := req.Validate(); err == nil || !strings.Contains(err.Error(), "version_probe_command") {
		t.Fatalf("expected version_probe_command error, got %v", err)
	}
	req.VersionProbeCommand = []string{"geth version"}

	req.RequiredEvidence = []string{""}
	if err := req.Validate(); err == nil || !strings.Contains(err.Error(), "required_evidence") {
		t.Fatalf("expected required_evidence error, got %v", err)
	}
	req.RequiredEvidence = []string{"artifact://provider/evidence"}

	req.Notes = []string{" "}
	if err := req.Validate(); err == nil || !strings.Contains(err.Error(), "notes") {
		t.Fatalf("expected notes error, got %v", err)
	}
}

func TestProviderRuntimeProfileRejectsReusableResidueWithoutWorkspace(t *testing.T) {
	contract := validBatchProviderContract()
	profile := &contract.RuntimeContract.Profiles[0]
	profile.HostWorkspaceSupported = false
	profile.ResiduePolicy = protocol.ResiduePolicy{
		Mode:         protocol.ResidueModeProviderBound,
		AllowedModes: []protocol.ResidueMode{protocol.ResidueModeProviderBound},
	}

	err := contract.Validate()
	if err == nil {
		t.Fatal("expected reusable residue without workspace to fail")
	}
	if !strings.Contains(err.Error(), "host workspace") {
		t.Fatalf("expected host workspace error, got %v", err)
	}
}

func TestProviderContractAcceptsWASMWithoutHostWorkspace(t *testing.T) {
	contract := validBatchProviderContract()
	contract.ID = "provider-example-wasm-v1"
	contract.ContractID = "example.wasm.v1"
	contract.WorkloadKinds = []string{string(protocol.WorkloadWASMComponent)}
	contract.ExecutionSecurityTiers = []protocol.ExecutionSecurityTier{protocol.ExecutionWASMCapability}
	contract.RuntimeContract.Profiles = []protocol.ProviderRuntimeProfile{{
		ID:                     "wasm-runtime",
		RuntimeProfile:         protocol.RuntimeProfileWASMComponent,
		ExecutorProvider:       "wasm-capability",
		ExecutionSecurityTier:  protocol.ExecutionWASMCapability,
		ProofTier:              protocol.ProofArtifactHash,
		WritableRootFS:         protocol.RuntimePermissionForbidden,
		Privileged:             protocol.RuntimePermissionForbidden,
		HostNamespaces:         protocol.RuntimePermissionForbidden,
		HostSocket:             protocol.RuntimePermissionForbidden,
		SeccompDisable:         protocol.RuntimePermissionForbidden,
		NoNewPrivilegesDisable: protocol.RuntimePermissionForbidden,
		ConformanceProfiles:    []string{"wasm-component-v1"},
		WASM: protocol.WASMRuntimeContract{
			ABI:               "wasi-preview2",
			ComponentRef:      "artifact://providers/example/wasm-client",
			ComponentDigest:   protocol.CanonicalHash([]byte("component")),
			MaxMemoryBytes:    128 * 1024 * 1024,
			MaxRuntimeSeconds: 30,
			Filesystem:        protocol.RuntimePermissionForbidden,
			Network:           protocol.RuntimePermissionExplicit,
		},
	}}

	if err := contract.Validate(); err != nil {
		t.Fatalf("contract invalid: %v", err)
	}
}

func TestProviderContractAcceptsAccessScopedProviderOperations(t *testing.T) {
	contract := validBatchProviderContract()
	contract.OrgID = "gocodealone"
	contract.PoolID = "ci-runners"
	contract.AccessPolicy = protocol.AccessPolicy{
		ProviderUsageVisibility: protocol.AccessVisibilityNetwork,
		WorkloadVisibility:      protocol.AccessVisibilityPrivate,
		ArtifactVisibility:      protocol.AccessVisibilityPrivate,
	}
	contract.WorkloadKinds = append(contract.WorkloadKinds, string(protocol.WorkloadProvider))
	contract.Operations = []protocol.ProviderOperation{{
		ID:                 "build",
		InputSchemaRef:     "schema://providers/example/operations/build/input/v1",
		InputSchemaDigest:  protocol.CanonicalHash(map[string]string{"input": "object"}),
		OutputSchemaRef:    "schema://providers/example/operations/build/output/v1",
		OutputSchemaDigest: protocol.CanonicalHash(map[string]string{"output": "object"}),
		Artifacts:          []string{"logs", "provenance"},
		ArtifactSpecs: []protocol.ProviderArtifactSpec{
			{Name: "logs", ContentType: "text/plain", MaxBytes: 1024, RetentionSeconds: 3600, Forwardable: true},
			{Name: "provenance", Required: true, ContentType: "application/json", MaxBytes: 4096},
		},
	}}

	if err := contract.Validate(); err != nil {
		t.Fatalf("contract invalid: %v", err)
	}
	if !contract.SupportsOperation("build") {
		t.Fatal("expected contract to support declared operation")
	}
	specs := contract.Operations[0].NormalizedArtifactSpecs()
	if len(specs) != 2 || specs[0].Name != "logs" || specs[1].Name != "provenance" {
		t.Fatalf("unexpected normalized artifact specs: %#v", specs)
	}
}

func TestProviderContractRejectsPoolWithoutOrg(t *testing.T) {
	contract := validBatchProviderContract()
	contract.PoolID = "ci-runners"

	err := contract.Validate()
	if err == nil {
		t.Fatal("expected pool without org to fail")
	}
	if !strings.Contains(err.Error(), "org_id") {
		t.Fatalf("expected org_id error, got %v", err)
	}
}

func TestProviderContractRejectsProviderWorkloadWithoutOperations(t *testing.T) {
	contract := validBatchProviderContract()
	contract.WorkloadKinds = append(contract.WorkloadKinds, string(protocol.WorkloadProvider))

	err := contract.Validate()
	if err == nil {
		t.Fatal("expected provider workload without operations to fail")
	}
	if !strings.Contains(err.Error(), "operations") {
		t.Fatalf("expected operations error, got %v", err)
	}
}

func TestProviderContractRejectsDuplicateArtifactSpecs(t *testing.T) {
	contract := validBatchProviderContract()
	contract.WorkloadKinds = append(contract.WorkloadKinds, string(protocol.WorkloadProvider))
	contract.Operations = []protocol.ProviderOperation{{
		ID:                 "build",
		InputSchemaRef:     "schema://providers/example/operations/build/input/v1",
		InputSchemaDigest:  protocol.CanonicalHash("input"),
		OutputSchemaRef:    "schema://providers/example/operations/build/output/v1",
		OutputSchemaDigest: protocol.CanonicalHash("output"),
		ArtifactSpecs: []protocol.ProviderArtifactSpec{
			{Name: "logs"},
			{Name: "logs"},
		},
	}}

	err := contract.Validate()
	if err == nil {
		t.Fatal("expected duplicate artifact specs to fail")
	}
	if !strings.Contains(err.Error(), "duplicated") {
		t.Fatalf("expected duplicate error, got %v", err)
	}
}

func TestProviderRuntimeProfileRequiresRealClientEvidence(t *testing.T) {
	contract := validBatchProviderContract()
	profile := &contract.RuntimeContract.Profiles[0]
	profile.ConformanceProfiles = append(profile.ConformanceProfiles, "upstream-client-v1")
	profile.UpstreamClientConformance = protocol.UpstreamClientConformanceRealClient

	err := contract.Validate()
	if err == nil {
		t.Fatal("expected real-client conformance without evidence to fail")
	}
	if !strings.Contains(err.Error(), "upstream_client_evidence") {
		t.Fatalf("expected evidence error, got %v", err)
	}

	profile.UpstreamClientEvidenceRef = "artifact://providers/example/evidence/upstream-client-v1"
	profile.UpstreamClientEvidenceDigest = protocol.CanonicalHash("evidence")
	if err := contract.Validate(); err != nil {
		t.Fatalf("contract invalid with real-client evidence: %v", err)
	}
}

func TestProviderContractRejectsDuplicateRuntimeProfiles(t *testing.T) {
	contract := validBatchProviderContract()
	contract.RuntimeContract.Profiles = append(contract.RuntimeContract.Profiles, contract.RuntimeContract.Profiles[0])

	err := contract.Validate()
	if err == nil {
		t.Fatal("expected duplicate runtime profiles to fail")
	}
	if !strings.Contains(err.Error(), "duplicated") {
		t.Fatalf("expected duplicate runtime profile error, got %v", err)
	}
}

func TestProviderContractRequiresUpstreamConformanceForKnownPlugins(t *testing.T) {
	contract := validBatchProviderContract()
	contract.PluginID = "workflow-plugin-crypto"
	contract.RuntimeContract.Profiles[0].UpstreamClientConformance = ""

	err := contract.Validate()
	if err == nil {
		t.Fatal("expected known upstream-client plugin without conformance to fail")
	}
	if !strings.Contains(err.Error(), "upstream_client_conformance") {
		t.Fatalf("expected upstream conformance error, got %v", err)
	}
}

func TestProviderContractRejectsRuntimeOnlySecurityAndProofTiers(t *testing.T) {
	contract := validBatchProviderContract()
	contract.ExecutionSecurityTiers = []protocol.ExecutionSecurityTier{protocol.ExecutionTrustedNative}
	contract.ProofTiers = []protocol.ProofTier{protocol.ProofReceiptOnly}
	contract.RuntimeContract.Profiles[0].ExecutionSecurityTier = protocol.ExecutionTrustedNative
	contract.RuntimeContract.Profiles[0].ProofTier = protocol.ProofReceiptOnly

	err := contract.Validate()
	if err == nil {
		t.Fatal("expected runtime-only tiers to fail")
	}
	if !strings.Contains(err.Error(), "trusted-native") || !strings.Contains(err.Error(), "receipt-only") {
		t.Fatalf("expected trusted-native and receipt-only errors, got %v", err)
	}
}

func TestProviderContractRejectsMismatchedProductVersionWhenPresent(t *testing.T) {
	contract := validBatchProviderContract()
	product := protocol.NetworkProduct{
		ProviderConfig: protocol.ProviderConfig{
			PluginID:   contract.PluginID,
			ProviderID: contract.ProviderID,
			ContractID: contract.ContractID,
			Version:    "v9.9.9",
		},
		OperatingMode: protocol.NetworkModeBatch,
		WorkloadKinds: []string{string(protocol.WorkloadCommand)},
		SecurityFloor: protocol.PlacementRequirements{
			ExecutorProvider:      "sandboxed-container",
			ExecutionSecurityTier: protocol.ExecutionSandboxedContainer,
			ProofTier:             protocol.ProofArtifactHash,
		},
		NetworkModes: []protocol.NetworkMode{protocol.NetworkModeRelay},
	}

	err := contract.SupportsProduct(product)
	if err == nil {
		t.Fatal("expected mismatched product version to fail")
	}
	if !strings.Contains(err.Error(), "version") {
		t.Fatalf("expected version mismatch error, got %v", err)
	}
}

func TestNetworkProductAcceptsWorkflowComputeProductCompatibilityShape(t *testing.T) {
	product := validBatchNetworkProduct()

	if err := product.Validate(); err != nil {
		t.Fatalf("product invalid: %v", err)
	}

	contract := validBatchProviderContract()
	if err := contract.SupportsProduct(product); err != nil {
		t.Fatalf("contract should support product: %v", err)
	}
}

func TestNetworkProductRejectsServiceResiduePolicy(t *testing.T) {
	product := validBatchNetworkProduct()
	product.OperatingMode = protocol.NetworkModeWarmService
	product.WorkloadKinds = []string{string(protocol.WorkloadService)}
	product.ResiduePolicy = protocol.ResiduePolicy{
		Mode:         protocol.ResidueModeProviderBound,
		AllowedModes: []protocol.ResidueMode{protocol.ResidueModeProviderBound},
	}

	err := product.Validate()
	if err == nil {
		t.Fatal("expected service product residue policy to fail")
	}
	if !strings.Contains(err.Error(), "residue_policy") {
		t.Fatalf("expected residue_policy error, got %v", err)
	}
}

func TestProviderConfigValidatesScopedConfigRef(t *testing.T) {
	config := protocol.ProviderConfig{
		PluginID:     "workflow-plugin-example",
		ProviderID:   "example",
		ContractID:   "example.batch.v1",
		Version:      "v1.0.0",
		ConfigRef:    "config://providers/example/batch",
		ConfigDigest: protocol.CanonicalHash("config"),
	}

	if err := config.Validate(); err != nil {
		t.Fatalf("config invalid: %v", err)
	}

	config.ConfigRef = "secret://wrong-scope"
	if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "config_ref") {
		t.Fatalf("expected config_ref error, got %v", err)
	}
}

func TestValidateProofPolicyRequiresQuorumOnlyForQuorumTiers(t *testing.T) {
	if err := protocol.ValidateProofPolicy(protocol.ProofReplicatedQuorum, protocol.ProofPolicy{Quorum: 2, MaxAttempts: 3}); err != nil {
		t.Fatalf("quorum proof policy invalid: %v", err)
	}
	if err := protocol.ValidateProofPolicy(protocol.ProofArtifactHash, protocol.ProofPolicy{Quorum: 2}); err == nil || !strings.Contains(err.Error(), "quorum") {
		t.Fatalf("expected non-quorum tier to reject quorum policy, got %v", err)
	}
}

func TestProviderContractAcceptsWorkflowComputeNetworkModes(t *testing.T) {
	for _, mode := range []protocol.NetworkMode{
		protocol.NetworkModeDirect,
		protocol.NetworkModeRelay,
		protocol.NetworkModeTailnet,
		protocol.NetworkModeTor,
		protocol.NetworkModeP2P,
		protocol.NetworkModeOffline,
	} {
		contract := validBatchProviderContract()
		contract.NetworkModes = []protocol.NetworkMode{mode}

		if err := contract.Validate(); err != nil {
			t.Fatalf("contract rejected network mode %q: %v", mode, err)
		}
	}
}

func validBatchNetworkProduct() protocol.NetworkProduct {
	return protocol.NetworkProduct{
		ProtocolVersion: protocol.Version,
		ID:              "example-batch",
		DisplayName:     "Example Batch",
		Purpose:         "ci",
		OperatingMode:   protocol.NetworkModeBatch,
		OrgID:           "public",
		PoolID:          "ci",
		WorkloadKinds:   []string{string(protocol.WorkloadCommand)},
		SecurityFloor: protocol.PlacementRequirements{
			ExecutorProvider:      "sandboxed-container",
			ExecutionSecurityTier: protocol.ExecutionSandboxedContainer,
			ProofTier:             protocol.ProofArtifactHash,
			RequiredCapabilities:  []string{"linux"},
		},
		ProviderConfig: protocol.ProviderConfig{
			PluginID:   "workflow-plugin-example",
			ProviderID: "example",
			ContractID: "example.batch.v1",
			Version:    "v1.0.0",
			ConfigRef:  "config://providers/example/batch",
		},
		NetworkModes: []protocol.NetworkMode{protocol.NetworkModeRelay},
		PlacementConstraints: protocol.PlacementConstraints{
			RequiredCapabilities: []string{"linux"},
		},
		RewardPolicy: "points",
		AbusePolicy:  "ban",
		AccessPolicy: protocol.AccessPolicy{
			ProviderUsageVisibility: protocol.AccessVisibilityPublic,
		},
		ResiduePolicy: protocol.ResiduePolicy{
			Mode:         protocol.ResidueModeProviderBound,
			AllowedModes: []protocol.ResidueMode{protocol.ResidueModeIsolated, protocol.ResidueModeProviderBound},
			PolicyHash:   protocol.CanonicalHash("residue-policy"),
		},
		AdmissionMode: "open",
		AllowPublic:   true,
		CreatedAt:     time.Now().UTC(),
	}
}

func TestProviderConformanceEvidenceRequiresArtifactDigestAndObservation(t *testing.T) {
	evidence := protocol.ProviderConformanceEvidence{
		ProtocolVersion:       protocol.Version,
		ID:                    "example-upstream-client-evidence",
		PluginID:              "workflow-plugin-example",
		ProviderID:            "example",
		ContractID:            "example.batch.v1",
		Version:               "v1.0.0",
		RuntimeProfileID:      "sandboxed-container-runtime",
		ConformanceProfile:    "upstream-client-v1",
		UpstreamClientName:    "example-client",
		UpstreamClientVersion: "1.2.3",
		EvidenceRef:           "artifact://providers/example/evidence/upstream-client-v1",
		EvidenceDigest:        protocol.CanonicalHash("evidence"),
		ObservedAt:            time.Now().UTC(),
	}

	if err := evidence.Validate(); err != nil {
		t.Fatalf("evidence invalid: %v", err)
	}

	evidence.EvidenceDigest = "sha256:not-hex"
	if err := evidence.Validate(); err == nil || !strings.Contains(err.Error(), "evidence_digest") {
		t.Fatalf("expected evidence_digest error, got %v", err)
	}
}

func validBatchProviderContract() protocol.ProviderContract {
	return protocol.ProviderContract{
		ProtocolVersion:        protocol.Version,
		ID:                     "provider-example-v1",
		PluginID:               "workflow-plugin-example",
		ProviderID:             "example",
		ContractID:             "example.batch.v1",
		Version:                "v1.0.0",
		ConfigSchemaRef:        "schema://providers/example/batch/v1",
		ConfigSchemaDigest:     protocol.CanonicalHash(map[string]string{"type": "object"}),
		OperatingModes:         []protocol.NetworkOperatingMode{protocol.NetworkModeBatch},
		WorkloadKinds:          []string{string(protocol.WorkloadCommand), string(protocol.WorkloadContainerBuild)},
		ExecutorProviders:      []string{"sandboxed-container"},
		ExecutionSecurityTiers: []protocol.ExecutionSecurityTier{protocol.ExecutionSandboxedContainer},
		ProofTiers:             []protocol.ProofTier{protocol.ProofArtifactHash},
		NetworkModes:           []protocol.NetworkMode{protocol.NetworkModeRelay},
		RuntimeContract: protocol.ProviderRuntimeContract{
			Profiles: []protocol.ProviderRuntimeProfile{{
				ID:                        "sandboxed-container-runtime",
				RuntimeProfile:            protocol.RuntimeProfileSandboxedOCI,
				ExecutorProvider:          "sandboxed-container",
				ExecutionSecurityTier:     protocol.ExecutionSandboxedContainer,
				ProofTier:                 protocol.ProofArtifactHash,
				AllowedRuntimeTools:       []protocol.ContainerRuntimeTool{protocol.ContainerRuntimePodman, protocol.ContainerRuntimeDocker, protocol.ContainerRuntimeNerdctl},
				ImageDigestRequired:       true,
				RootFSDigestRequired:      true,
				AllowedMountRefs:          []string{"workspace"},
				WritablePaths:             []string{"/tmp"},
				WritableRootFS:            protocol.RuntimePermissionForbidden,
				Privileged:                protocol.RuntimePermissionForbidden,
				HostNamespaces:            protocol.RuntimePermissionForbidden,
				HostSocket:                protocol.RuntimePermissionForbidden,
				SeccompDisable:            protocol.RuntimePermissionForbidden,
				NoNewPrivilegesDisable:    protocol.RuntimePermissionForbidden,
				ConformanceProfiles:       []string{"sandboxed-oci-v1"},
				HostWorkspaceSupported:    true,
				UpstreamClientConformance: protocol.UpstreamClientConformanceShapeOnly,
				ResiduePolicy: protocol.ResiduePolicy{
					Mode:          protocol.ResidueModeProviderBound,
					AllowedModes:  []protocol.ResidueMode{protocol.ResidueModeIsolated, protocol.ResidueModeProviderBound},
					MaxAgeSeconds: 600,
					WipeOnFailure: true,
				},
			}},
		},
	}
}
