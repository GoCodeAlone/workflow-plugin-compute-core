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
