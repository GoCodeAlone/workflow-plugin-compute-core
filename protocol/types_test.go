package protocol_test

import (
	"strings"
	"testing"

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
