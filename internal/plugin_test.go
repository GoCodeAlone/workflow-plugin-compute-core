package internal_test

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/GoCodeAlone/workflow-plugin-compute-core/internal"
	"github.com/GoCodeAlone/workflow-plugin-compute-core/protocol"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

func TestNewPlugin_ImplementsPluginProvider(t *testing.T) {
	var _ sdk.PluginProvider = internal.NewPlugin()
}

func TestManifest_HasRequiredFields(t *testing.T) {
	m := internal.NewPlugin().Manifest()
	if m.Name == "" {
		t.Error("manifest Name is empty")
	}
	if m.Version == "" {
		t.Error("manifest Version is empty — build-time ldflags injection missing")
	}
	if m.Description == "" {
		t.Error("manifest Description is empty")
	}
	if strings.Contains(m.Description, "TEMPLATE") || strings.Contains(strings.ToLower(m.Description), "scaffold") {
		t.Fatalf("manifest still carries scaffold placeholder text: %q", m.Description)
	}
}

func TestPluginJSON_AdvertisesProtocolCoreOnly(t *testing.T) {
	data, err := os.ReadFile("../plugin.json")
	if err != nil {
		t.Fatalf("read plugin.json: %v", err)
	}
	var manifest struct {
		Name         string   `json:"name"`
		Description  string   `json:"description"`
		Type         string   `json:"type"`
		Private      bool     `json:"private"`
		Keywords     []string `json:"keywords"`
		Capabilities struct {
			ConfigProvider bool     `json:"configProvider"`
			ModuleTypes    []string `json:"moduleTypes"`
			StepTypes      []string `json:"stepTypes"`
			TriggerTypes   []string `json:"triggerTypes"`
		} `json:"capabilities"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("parse plugin.json: %v", err)
	}
	if manifest.Name != "workflow-plugin-compute-core" || manifest.Type != "external" || manifest.Private {
		t.Fatalf("unexpected plugin identity: %+v", manifest)
	}
	joined := strings.Join(append(manifest.Keywords, manifest.Description), " ")
	if strings.Contains(joined, "TEMPLATE") || strings.Contains(strings.ToLower(joined), "scaffold") {
		t.Fatalf("plugin.json still carries scaffold placeholder text: %s", joined)
	}
	if manifest.Capabilities.ConfigProvider ||
		len(manifest.Capabilities.ModuleTypes) != 0 ||
		len(manifest.Capabilities.StepTypes) != 0 ||
		len(manifest.Capabilities.TriggerTypes) != 0 {
		t.Fatalf("compute-core should not advertise runtime capabilities: %+v", manifest.Capabilities)
	}
	if !slices.Contains(manifest.Keywords, "provider-catalog") || !slices.Contains(manifest.Keywords, "protocol") {
		t.Fatalf("protocol keywords missing: %+v", manifest.Keywords)
	}
}

func TestProtocolProviderContractSupportsProduct(t *testing.T) {
	runtime := protocol.DefaultProviderRuntimeProfile("node-service-sandboxed-container", protocol.ExecutionSandboxedContainer, protocol.ProofArtifactHash)
	contract := protocol.ProviderContract{
		ProtocolVersion:        protocol.Version,
		ID:                     "example-v1",
		PluginID:               "workflow-plugin-example",
		ProviderID:             "example",
		ContractID:             "example.client.v1",
		Version:                "v1.0.0",
		ConfigSchemaRef:        "schema://providers/example/client/v1",
		ConfigSchemaDigest:     protocol.CanonicalHash(map[string]string{"type": "object"}),
		OperatingModes:         []protocol.NetworkOperatingMode{protocol.NetworkModeNodeService},
		WorkloadKinds:          []string{"node-service"},
		ExecutorProviders:      []string{"node-service-sandboxed-container"},
		ExecutionSecurityTiers: []protocol.ExecutionSecurityTier{protocol.ExecutionSandboxedContainer},
		ProofTiers:             []protocol.ProofTier{protocol.ProofArtifactHash},
		NetworkModes:           []protocol.NetworkMode{protocol.NetworkModeDirect, protocol.NetworkModeRelay},
		RuntimeContract:        protocol.ProviderRuntimeContract{Profiles: []protocol.ProviderRuntimeProfile{runtime}},
	}
	if err := contract.Validate(); err != nil {
		t.Fatalf("contract invalid: %v", err)
	}
	product := protocol.NetworkProduct{
		ProtocolVersion: protocol.Version,
		ID:              "example-product",
		OperatingMode:   protocol.NetworkModeNodeService,
		OrgID:           "public",
		PoolID:          "example",
		WorkloadKinds:   []string{"node-service"},
		SecurityFloor: protocol.PlacementRequirements{
			ExecutorProvider:      "node-service-sandboxed-container",
			ExecutionSecurityTier: protocol.ExecutionSandboxedContainer,
			ProofTier:             protocol.ProofArtifactHash,
		},
		ProviderConfig: protocol.ProviderConfig{
			PluginID:   "workflow-plugin-example",
			ProviderID: "example",
			ContractID: "example.client.v1",
		},
		NetworkModes: []protocol.NetworkMode{protocol.NetworkModeDirect},
		PlacementConstraints: protocol.PlacementConstraints{
			Chain:        "example",
			Role:         "client",
			MinDiskBytes: 1,
		},
		RewardPolicy: "points",
		AbusePolicy:  "example",
		SettlementTarget: protocol.SettlementTarget{
			Kind:      protocol.SettlementTargetTreasuryWallet,
			Network:   "example",
			WalletRef: "wallet://example/primary",
		},
	}
	if err := product.Validate(); err != nil {
		t.Fatalf("product invalid: %v", err)
	}
	if err := contract.SupportsProduct(product); err != nil {
		t.Fatalf("contract should support product: %v", err)
	}
}
