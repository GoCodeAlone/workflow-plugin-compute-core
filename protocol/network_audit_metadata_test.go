package protocol_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/GoCodeAlone/workflow-plugin-compute-core/protocol"
)

func TestNetworkAuditStaticMessageContractMetadata(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "plugin.contracts.json"))
	if err != nil {
		t.Fatalf("read plugin.contracts.json: %v", err)
	}
	var contracts struct {
		DescriptorSetRef string `json:"descriptorSetRef"`
		Contracts        []struct {
			Kind            string   `json:"kind"`
			ContractType    string   `json:"contractType"`
			Mode            string   `json:"mode"`
			ProtoPackage    string   `json:"protoPackage"`
			MessageNames    []string `json:"messageNames"`
			GoImportPath    string   `json:"goImportPath"`
			SchemaDigest    string   `json:"schemaDigest"`
			ProtocolVersion string   `json:"protocolVersion"`
		} `json:"contracts"`
		ProtocolTypes []struct {
			Name            string   `json:"name"`
			Wire            string   `json:"wire"`
			GoType          string   `json:"goType"`
			ProtocolVersion string   `json:"protocolVersion"`
			StatusValues    []string `json:"statusValues"`
			Produces        []string `json:"produces"`
		} `json:"protocolTypes"`
	}
	if err := json.Unmarshal(data, &contracts); err != nil {
		t.Fatalf("parse plugin.contracts.json: %v", err)
	}
	if contracts.DescriptorSetRef != "descriptors/network_audit.pb" {
		t.Fatalf("descriptorSetRef = %q", contracts.DescriptorSetRef)
	}
	var found bool
	for _, contract := range contracts.Contracts {
		if contract.ContractType != "compute.network_audit_evidence.v1" {
			continue
		}
		found = true
		if contract.Kind != "message" || contract.Mode != "strict" {
			t.Fatalf("unexpected contract kind/mode: %#v", contract)
		}
		if contract.ProtoPackage != "workflow_plugin_compute_core.protocol.v1" {
			t.Fatalf("protoPackage = %q", contract.ProtoPackage)
		}
		if contract.GoImportPath != "github.com/GoCodeAlone/workflow-plugin-compute-core/protocol/pb" {
			t.Fatalf("goImportPath = %q", contract.GoImportPath)
		}
		if contract.SchemaDigest != protocol.NetworkAuditDescriptorDigest() {
			t.Fatalf("schemaDigest = %q, want %q", contract.SchemaDigest, protocol.NetworkAuditDescriptorDigest())
		}
		if contract.ProtocolVersion != protocol.NetworkAuditProtocolVersion {
			t.Fatalf("protocolVersion = %q", contract.ProtocolVersion)
		}
		wantMessages := map[string]bool{
			"workflow_plugin_compute_core.protocol.v1.NetworkAuditRecord":          false,
			"workflow_plugin_compute_core.protocol.v1.NetworkAuditDestination":     false,
			"workflow_plugin_compute_core.protocol.v1.NetworkAuditValidationIssue": false,
		}
		for _, name := range contract.MessageNames {
			if _, ok := wantMessages[name]; ok {
				wantMessages[name] = true
			}
		}
		for name, ok := range wantMessages {
			if !ok {
				t.Fatalf("messageNames missing %s: %#v", name, contract.MessageNames)
			}
		}
	}
	if !found {
		t.Fatal("compute.network_audit_evidence.v1 message contract not found")
	}
	var foundRuntimeBackend bool
	for _, typ := range contracts.ProtocolTypes {
		if typ.Name != "RuntimeBackendReport" {
			continue
		}
		foundRuntimeBackend = true
		if typ.Wire != "json" {
			t.Fatalf("RuntimeBackendReport wire = %q", typ.Wire)
		}
		if typ.GoType != "github.com/GoCodeAlone/workflow-plugin-compute-core/protocol.RuntimeBackendReport" {
			t.Fatalf("RuntimeBackendReport goType = %q", typ.GoType)
		}
		if typ.ProtocolVersion != protocol.Version {
			t.Fatalf("RuntimeBackendReport protocolVersion = %q", typ.ProtocolVersion)
		}
		for _, want := range []string{"supported", "degraded", "unsupported"} {
			if !slices.Contains(typ.StatusValues, want) {
				t.Fatalf("RuntimeBackendReport statusValues missing %q: %#v", want, typ.StatusValues)
			}
		}
		for _, want := range []string{"executor_providers", "provider_capability_reports"} {
			if !slices.Contains(typ.Produces, want) {
				t.Fatalf("RuntimeBackendReport produces missing %q: %#v", want, typ.Produces)
			}
		}
	}
	if !foundRuntimeBackend {
		t.Fatal("RuntimeBackendReport protocol type not found")
	}
}

func TestNetworkAuditReleaseArchiveIncludesContractArtifacts(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", ".goreleaser.yaml"))
	if err != nil {
		t.Fatalf("read .goreleaser.yaml: %v", err)
	}
	body := string(data)
	for _, want := range []string{
		"plugin.contracts.json",
		"descriptors/network_audit.pb",
		"proto/workflow_plugin_compute_core/protocol/v1/network_audit.proto",
		"proto/workflow_plugin_compute_core/protocol/v1/network_audit.fields.json",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf(".goreleaser.yaml archive files missing %s", want)
		}
	}
}
