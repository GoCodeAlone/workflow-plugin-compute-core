package protocol_test

import (
	"encoding/json"
	"slices"
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

func TestRuntimeExecutionRequestValidatesHostIndependentInvocation(t *testing.T) {
	req := protocol.RuntimeExecutionRequest{
		ProtocolVersion: protocol.Version,
		TaskID:          "task-1",
		LeaseID:         "lease-1",
		WorkloadKind:    protocol.WorkloadProvider,
		ProviderConfig: protocol.ProviderConfig{
			PluginID:   "workflow-plugin-example",
			ProviderID: "example",
			ContractID: "example.v1",
			Version:    "v1.0.0",
			ConfigRef:  "config://providers/example",
		},
		Operation: "capture_product",
		Input:     mustRawMessage(t, map[string]string{"url": "https://example.test"}),
		Env:       map[string]string{"MODE": "test"},
		Limits:    protocol.ResourceLimits{RuntimeSeconds: 30, OutputBytes: 1024},
	}

	if err := req.Validate(); err != nil {
		t.Fatalf("request invalid: %v", err)
	}
}

func mustRawMessage(t *testing.T, value any) json.RawMessage {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal raw message: %v", err)
	}
	return data
}

func TestRuntimeExecutionRequestRejectsMalformedInvocation(t *testing.T) {
	req := protocol.RuntimeExecutionRequest{
		ProtocolVersion: "wrong",
		TaskID:          "task-1",
		LeaseID:         "lease-1",
		WorkloadKind:    protocol.WorkloadProvider,
		Limits:          protocol.ResourceLimits{RuntimeSeconds: -1},
	}

	err := req.Validate()
	if err == nil {
		t.Fatal("expected malformed request to fail")
	}
	if !strings.Contains(err.Error(), "protocol_version") ||
		!strings.Contains(err.Error(), "resource_limits") {
		t.Fatalf("expected protocol/resource errors, got %v", err)
	}
}

func TestWorkloadSpecValidatesServiceWorkload(t *testing.T) {
	workload := protocol.WorkloadSpec{
		Kind: protocol.WorkloadService,
		Service: &protocol.ServiceWorkload{
			ComponentRef:    "provider://workflow-plugin-compute-service/service-runtime",
			ComponentDigest: "sha256:" + strings.Repeat("a", 64),
			Command:         []string{"serve", "--port", "8080"},
			Ports:           []protocol.ServicePort{{Name: "http", Port: 8080, Protocol: "http"}},
			HealthCheck: protocol.HealthCheck{
				Kind:            "http",
				Path:            "/healthz",
				IntervalSeconds: 5,
				TimeoutSeconds:  2,
			},
			Ingress: protocol.IngressPolicy{Mode: "private", AuthRequired: true},
			Env:     []protocol.EnvRef{{Name: "PORT", ValueRef: "config://service/port"}},
			Files: []protocol.WorkloadFileRef{{
				Path:     "config/app.toml",
				Template: "port={{ .PORT }}",
				Refs:     []protocol.EnvRef{{Name: "PORT", ValueRef: "config://service/port"}},
				Mode:     0o640,
			}},
		},
	}

	if err := workload.Validate(); err != nil {
		t.Fatalf("service workload invalid: %v", err)
	}
}

func TestServiceWorkloadRejectsUnsafeShape(t *testing.T) {
	workload := protocol.ServiceWorkload{
		ImageRef:      "repo/service:latest bad",
		ComponentRef:  "provider://workflow-plugin-compute-service/service-runtime",
		Ports:         []protocol.ServicePort{{Port: 8080, Protocol: "http"}},
		HealthCheck:   protocol.HealthCheck{Kind: "http", Path: "/healthz", IntervalSeconds: 5, TimeoutSeconds: 2},
		Ingress:       protocol.IngressPolicy{Mode: "none", AllowedCIDRs: []string{"not-a-cidr"}},
		DataDirRef:    "volume://service-data",
		DataMountPath: "../data",
	}

	err := workload.Validate()
	if err == nil {
		t.Fatal("expected unsafe service workload to fail")
	}
	for _, want := range []string{
		"mutually exclusive",
		"whitespace or NUL",
		"component_digest",
		"ports must be empty",
		"headless service requires command health check",
		"allowed_cidrs",
		"data_mount_path",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("Validate() = %v, want %q", err, want)
		}
	}
}

func TestServiceWorkloadRejectsComponentRefWhitespace(t *testing.T) {
	workload := protocol.ServiceWorkload{
		ComponentRef:    " provider://workflow-plugin-compute-service/service-runtime",
		ComponentDigest: "sha256:" + strings.Repeat("a", 64),
		Command:         []string{"serve", "--port", "8080"},
		Ports:           []protocol.ServicePort{{Name: "http", Port: 8080, Protocol: "http"}},
		HealthCheck:     protocol.HealthCheck{Kind: "http", Path: "/healthz", IntervalSeconds: 5, TimeoutSeconds: 2},
		Ingress:         protocol.IngressPolicy{Mode: "private", AuthRequired: true},
	}
	if err := workload.Validate(); err == nil || !strings.Contains(err.Error(), "surrounding whitespace") {
		t.Fatalf("service workload accepted whitespace-padded component_ref: %v", err)
	}
}

func TestWorkloadSpecValidatesNodeServiceWorkload(t *testing.T) {
	endpoint := "node.example.invalid:30303"
	workload := protocol.WorkloadSpec{
		Kind: protocol.WorkloadNodeService,
		NodeService: &protocol.NodeServiceWorkload{
			ImageRef:     "ghcr.io/gocodealone/node@sha256:" + strings.Repeat("b", 64),
			Chain:        "ethereum",
			Network:      "sepolia",
			DataDirRef:   "volume://nodes/sepolia",
			RPCSecretRef: "secret://nodes/sepolia/rpc",
			PeerPolicy: protocol.PeerPolicy{
				Mode:            "allowlist",
				AllowedPeers:    []string{endpoint},
				EgressAllowlist: []string{endpoint},
			},
			ArtifactRefs: []string{"artifact://snapshots/sepolia"},
			Command:      []string{"node", "--network", "sepolia"},
			HealthCheck: protocol.HealthCheck{
				Kind:            "command",
				Command:         []string{"node", "status"},
				IntervalSeconds: 10,
				TimeoutSeconds:  3,
			},
			Env: []protocol.EnvRef{{Name: "RPC_TOKEN", SecretRef: "secret://nodes/sepolia/rpc"}},
		},
	}

	if err := workload.Validate(); err != nil {
		t.Fatalf("node-service workload invalid: %v", err)
	}
}

func TestNodeServiceWorkloadRejectsComponentRefWhitespace(t *testing.T) {
	endpoint := "node.example.invalid:30303"
	workload := protocol.NodeServiceWorkload{
		ComponentRef:    "provider://workflow-plugin-compute-service/node-runtime ",
		ComponentDigest: "sha256:" + strings.Repeat("b", 64),
		Chain:           "ethereum",
		Network:         "sepolia",
		DataDirRef:      "volume://nodes/sepolia",
		RPCSecretRef:    "secret://nodes/sepolia/rpc",
		PeerPolicy: protocol.PeerPolicy{
			Mode:            "allowlist",
			AllowedPeers:    []string{endpoint},
			EgressAllowlist: []string{endpoint},
		},
		HealthCheck: protocol.HealthCheck{Kind: "command", Command: []string{"node", "status"}, IntervalSeconds: 10, TimeoutSeconds: 3},
	}
	if err := workload.Validate(); err == nil || !strings.Contains(err.Error(), "surrounding whitespace") {
		t.Fatalf("node-service workload accepted whitespace-padded component_ref: %v", err)
	}
}

func TestNodeServiceWorkloadRejectsMissingHealthAndUnsafePeers(t *testing.T) {
	workload := protocol.NodeServiceWorkload{
		ImageRef:     "ghcr.io/gocodealone/node@sha256:" + strings.Repeat("c", 64),
		Chain:        "ethereum",
		Network:      "mainnet",
		DataDirRef:   "volume://nodes/mainnet",
		RPCSecretRef: "secret://nodes/mainnet/rpc",
		PeerPolicy: protocol.PeerPolicy{
			Mode:            "allowlist",
			AllowedPeers:    []string{"https://peer.example.invalid:30303/path", "peer.example.invalid:notaport"},
			EgressAllowlist: []string{"other.example.invalid:30303"},
		},
	}

	err := workload.Validate()
	if err == nil {
		t.Fatal("expected unsafe node-service workload to fail")
	}
	for _, want := range []string{"peer_policy", "allowed_peers", "port", "health_check"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("Validate() = %v, want %q", err, want)
		}
	}
}

func TestWorkloadSpecAllowsReservedHostWorkloadKinds(t *testing.T) {
	for _, kind := range []protocol.WorkloadKind{protocol.WorkloadContentCache, protocol.WorkloadSupervisor} {
		if err := (protocol.WorkloadSpec{Kind: kind}).Validate(); err != nil {
			t.Fatalf("%s workload spec rejected: %v", kind, err)
		}
	}
}

func TestWorkloadFileRefRejectsTrimmedAbsolutePath(t *testing.T) {
	ref := protocol.WorkloadFileRef{
		Path:     " /etc/passwd",
		ValueRef: "config://service/file",
	}

	err := ref.Validate()
	if err == nil || !strings.Contains(err.Error(), "relative workspace path") {
		t.Fatalf("absolute path with leading whitespace accepted: %v", err)
	}
}

func TestPeerPolicyCanonicalizesNumericPort(t *testing.T) {
	policy := protocol.PeerPolicy{
		Mode:            "allowlist",
		AllowedPeers:    []string{"node.example.invalid:030303"},
		EgressAllowlist: []string{"node.example.invalid:30303"},
	}

	if err := policy.Validate(); err != nil {
		t.Fatalf("equivalent numeric peer ports rejected: %v", err)
	}
}

func TestServiceIngressEvidenceValidation(t *testing.T) {
	evidence := validServiceIngressEvidence()
	if err := evidence.Validate(); err != nil {
		t.Fatalf("valid ingress evidence rejected: %v", err)
	}

	cases := []struct {
		name string
		mut  func(*protocol.ServiceIngressEvidence)
		want string
	}{
		{"missing auth decision", func(e *protocol.ServiceIngressEvidence) { e.AuthDecisionHash = "" }, "auth_decision_hash"},
		{"missing health response", func(e *protocol.ServiceIngressEvidence) { e.LastHealthResponseHash = "" }, "last_health_response_hash"},
		{"missing helper target", func(e *protocol.ServiceIngressEvidence) { e.HelperContainerNetNSTarget = "" }, "helper_container_netns_target"},
		{"unsafe helper host", func(e *protocol.ServiceIngressEvidence) { e.HelperHost = "10.0.0.5" }, "helper_host"},
		{"queryful request path", func(e *protocol.ServiceIngressEvidence) { e.RequestPath = "/compile?token=secret" }, "query"},
		{"unsupported method", func(e *protocol.ServiceIngressEvidence) { e.RequestMethod = "PUT" }, "request_method"},
		{"failed without class", func(e *protocol.ServiceIngressEvidence) {
			e.TerminalStatus = protocol.ServiceIngressTerminalFailed
			e.ResponseStatus = 0
			e.ResponseHash = ""
			e.FailureClass = ""
		}, "failure_class"},
		{"secret request header", func(e *protocol.ServiceIngressEvidence) { e.RequestHeaderNames = []string{"authorization"} }, "header"},
		{"secret response header", func(e *protocol.ServiceIngressEvidence) { e.ResponseHeaderNames = []string{"cookie"} }, "header"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := evidence
			got.RequestHeaderNames = slices.Clone(evidence.RequestHeaderNames)
			got.ResponseHeaderNames = slices.Clone(evidence.ResponseHeaderNames)
			tc.mut(&got)
			if err := got.Validate(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate() error = %v, want containing %q", err, tc.want)
			}
		})
	}
}

func validServiceIngressEvidence() protocol.ServiceIngressEvidence {
	return protocol.ServiceIngressEvidence{
		ID:                         "ing-evidence-1",
		OrgID:                      "org-1",
		PoolID:                     "pool-1",
		ProductID:                  "edge-product",
		Hostname:                   "edge.example.invalid",
		RouteTarget:                "service-route:abc123",
		ServiceLeaseID:             "svc-1",
		TaskID:                     "task-1",
		WorkerID:                   "worker-1",
		LeaseLeasedAt:              time.Unix(100, 0).UTC(),
		LeaseRenewBy:               time.Unix(200, 0).UTC(),
		SelectedAt:                 time.Unix(101, 0).UTC(),
		LastHealthAt:               time.Unix(102, 0).UTC(),
		HealthValidUntil:           time.Unix(132, 0).UTC(),
		LastHealthResponseHash:     "sha256:" + strings.Repeat("b", 64),
		LastHealthSLOEvidenceHash:  "sha256:" + strings.Repeat("c", 64),
		AuthDecisionHash:           "sha256:" + strings.Repeat("d", 64),
		IdempotencyKey:             "idem-1",
		RequestMethod:              "POST",
		RequestPath:                "/compile",
		RequestBodyHash:            "sha256:" + strings.Repeat("e", 64),
		RequestHeaderNames:         []string{"content-type"},
		HelperImage:                "ingress-helper@sha256:" + strings.Repeat("f", 64),
		HelperScheme:               "http",
		HelperHost:                 "127.0.0.1",
		HelperPort:                 8080,
		HelperPortName:             "http",
		HelperTimeoutMS:            1000,
		HelperContainerNetNSTarget: "container:svc-container",
		HelperOutputHash:           "sha256:" + strings.Repeat("1", 64),
		HelperErrorHash:            "sha256:" + strings.Repeat("2", 64),
		ResponseStatus:             200,
		ResponseHeaderNames:        []string{"content-type"},
		ResponseHash:               "sha256:" + strings.Repeat("3", 64),
		ResponseBytes:              42,
		TerminalStatus:             protocol.ServiceIngressTerminalCompleted,
		StartedAt:                  time.Unix(103, 0).UTC(),
		FinishedAt:                 time.Unix(104, 0).UTC(),
	}
}

func TestRuntimeExecutionResultValidatesTimingAndPreview(t *testing.T) {
	result := protocol.RuntimeExecutionResult{
		StartedAt:     time.Unix(10, 0).UTC(),
		FinishedAt:    time.Unix(9, 0).UTC(),
		ResultPreview: map[string]any{"payload": strings.Repeat("x", protocol.MaxRuntimeResultPreviewBytes+1)},
	}

	err := result.Validate()
	if err == nil {
		t.Fatal("expected malformed result to fail")
	}
	if !strings.Contains(err.Error(), "finished_at") ||
		!strings.Contains(err.Error(), "result_preview") {
		t.Fatalf("expected timing/preview errors, got %v", err)
	}
}

func TestValidateRuntimeResultPreview(t *testing.T) {
	if err := protocol.ValidateRuntimeResultPreview(map[string]any{"ok": true}); err != nil {
		t.Fatalf("bounded preview rejected: %v", err)
	}
	if err := protocol.ValidateRuntimeResultPreview(map[string]any{"payload": strings.Repeat("x", protocol.MaxRuntimeResultPreviewBytes+1)}); err == nil || !strings.Contains(err.Error(), "result_preview") {
		t.Fatalf("expected oversized preview error, got %v", err)
	}
	if err := protocol.ValidateRuntimeResultPreview(map[string]any{"bad": func() {}}); err == nil || !strings.Contains(err.Error(), "JSON-serializable") {
		t.Fatalf("expected JSON serialization error, got %v", err)
	}
}

func TestRuntimeServiceResultValidatesSLOEvidence(t *testing.T) {
	result := protocol.RuntimeServiceResult{
		StartedAt:    time.Unix(1, 0).UTC(),
		FinishedAt:   time.Unix(2, 0).UTC(),
		RequestHash:  protocol.CanonicalHash("request"),
		ResponseHash: protocol.CanonicalHash("response"),
		SLOEvidence:  protocol.SLOEvidence{StatusCode: 200, LatencyMillis: 3, Healthy: true},
	}

	if err := result.Validate(); err != nil {
		t.Fatalf("service result invalid: %v", err)
	}

	result.SLOEvidence.StatusCode = 0
	if err := result.Validate(); err == nil || !strings.Contains(err.Error(), "status_code") {
		t.Fatalf("expected status code error, got %v", err)
	}
}

func TestRuntimeServiceResultValidatesStatusEvidenceHashes(t *testing.T) {
	result := protocol.RuntimeServiceResult{
		RequestHash:  protocol.CanonicalHash("request"),
		ResponseHash: protocol.CanonicalHash("response"),
		SLOEvidence:  protocol.SLOEvidence{StatusCode: 200, LatencyMillis: 3, Healthy: true},
		StatusEvidence: protocol.ServiceStatusEvidence{
			CommandHash: "not-a-hash",
			OutputHash:  protocol.CanonicalHash("output"),
		},
	}

	err := result.Validate()
	if err == nil || !strings.Contains(err.Error(), "command_hash") {
		t.Fatalf("expected command hash error, got %v", err)
	}
}

func TestRuntimeAdapterContractValidatesHostIndependentBoundary(t *testing.T) {
	contract := protocol.RuntimeAdapterContract{
		ProtocolVersion: protocol.Version,
		AdapterID:       "sandboxed-command",
		Descriptor: protocol.RuntimeDescriptor{
			Name:                  "sandboxed-command",
			Version:               "v1.2.3",
			ExecutionSecurityTier: protocol.ExecutionSandboxedContainer,
			ProofTier:             protocol.ProofArtifactHash,
			ImageDigest:           protocol.CanonicalHash("image"),
			RootFSDigest:          protocol.CanonicalHash("rootfs"),
		},
		Kinds:               []protocol.RuntimeAdapterKind{protocol.RuntimeAdapterExecution},
		WorkloadKinds:       []protocol.WorkloadKind{protocol.WorkloadCommand, protocol.WorkloadContainerBuild},
		RuntimeProfiles:     []protocol.RuntimeProfile{protocol.RuntimeProfileSandboxedOCI},
		WorkspacePolicy:     protocol.RuntimeWorkspaceRequired,
		ConformanceProfiles: []string{"protected-command-v1"},
		ResiduePolicy: protocol.ResiduePolicy{
			Mode:          protocol.ResidueModeProviderBound,
			PolicyHash:    protocol.CanonicalHash("residue"),
			MaxReuseCount: 2,
		},
	}

	if err := contract.Validate(); err != nil {
		t.Fatalf("adapter contract invalid: %v", err)
	}
}

func TestRuntimeAdapterContractRejectsAmbiguousRuntimeBoundary(t *testing.T) {
	contract := protocol.RuntimeAdapterContract{
		ProtocolVersion: "wrong",
		AdapterID:       "bad adapter",
		Descriptor: protocol.RuntimeDescriptor{
			Name:                  "adapter",
			Version:               "v1.0.0",
			ExecutionSecurityTier: protocol.ExecutionSandboxedContainer,
			ProofTier:             protocol.ProofArtifactHash,
		},
		Kinds:           []protocol.RuntimeAdapterKind{protocol.RuntimeAdapterExecution, protocol.RuntimeAdapterExecution},
		WorkloadKinds:   []protocol.WorkloadKind{protocol.WorkloadKind("unknown")},
		WorkspacePolicy: protocol.RuntimeWorkspacePolicy("maybe"),
		ResiduePolicy: protocol.ResiduePolicy{
			Mode:       protocol.ResidueModeSessionBound,
			SessionKey: "session",
		},
	}

	err := contract.Validate()
	if err == nil {
		t.Fatal("expected malformed adapter contract to fail")
	}
	for _, want := range []string{"protocol_version", "adapter_id", "descriptor", "kinds", "workload_kinds", "workspace_policy", "conformance_profiles", "residue_policy"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("expected %q in error, got %v", want, err)
		}
	}
}

func TestRuntimeAdapterContractRequiresServiceWorkloadForServiceAdapters(t *testing.T) {
	contract := protocol.RuntimeAdapterContract{
		ProtocolVersion: protocol.Version,
		AdapterID:       "service-adapter",
		Descriptor: protocol.RuntimeDescriptor{
			Name:                  "service-adapter",
			Version:               "v1.0.0",
			ExecutionSecurityTier: protocol.ExecutionSandboxedContainer,
			ProofTier:             protocol.ProofArtifactHash,
			ImageDigest:           protocol.CanonicalHash("image"),
			RootFSDigest:          protocol.CanonicalHash("rootfs"),
		},
		Kinds:               []protocol.RuntimeAdapterKind{protocol.RuntimeAdapterServiceSession},
		WorkloadKinds:       []protocol.WorkloadKind{protocol.WorkloadCommand},
		WorkspacePolicy:     protocol.RuntimeWorkspaceOptional,
		ConformanceProfiles: []string{"service-session-v1"},
	}

	err := contract.Validate()
	if err == nil || !strings.Contains(err.Error(), "service adapter kinds require service workload kind") {
		t.Fatalf("expected service workload error, got %v", err)
	}
}

func TestPlacementConstraintsSatisfiedByEvaluatesWorkerAndTaskInputs(t *testing.T) {
	constraints := protocol.PlacementConstraints{
		MinDiskBytes:         100,
		MinMemoryBytes:       200,
		MinBandwidthMbps:     300,
		RequiresIngress:      true,
		RequiredCapabilities: []string{"gpu", "tee"},
	}

	err := protocol.PlacementConstraintsSatisfiedBy(
		constraints,
		protocol.PlacementCapabilities{
			DiskBytes:     50,
			MemoryBytes:   150,
			BandwidthMbps: 250,
			CapabilityTags: []string{
				"gpu",
			},
		},
		protocol.PlacementNetworkPolicy{},
	)
	if err == nil {
		t.Fatal("expected insufficient placement inputs to fail")
	}
	for _, want := range []string{
		"disk_bytes",
		"memory_bytes",
		"bandwidth_mbps",
		"ingress",
		`required capability "tee"`,
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("expected placement error to contain %q, got %v", want, err)
		}
	}

	if err := protocol.PlacementConstraintsSatisfiedBy(
		constraints,
		protocol.PlacementCapabilities{
			DiskBytes:      100,
			MemoryBytes:    200,
			BandwidthMbps:  300,
			IngressCapable: true,
			CapabilityTags: []string{"gpu", "tee"},
		},
		protocol.PlacementNetworkPolicy{AllowIngress: true},
	); err != nil {
		t.Fatalf("expected placement inputs to satisfy constraints: %v", err)
	}

	if err := protocol.PlacementConstraintsSatisfiedBy(
		protocol.PlacementConstraints{},
		protocol.PlacementCapabilities{},
		protocol.PlacementNetworkPolicy{},
	); err != nil {
		t.Fatalf("zero constraints should be satisfied: %v", err)
	}
}

func TestRuntimeDescriptorFallsBackToProviderNameAndDevVersion(t *testing.T) {
	ref := (protocol.RuntimeDescriptor{}).ExecutorRef("command")

	if ref.Provider != "command" || ref.Version != "dev" {
		t.Fatalf("fallback executor ref = %+v", ref)
	}
}

func TestCommandWorkloadContractUsesResolvedRefs(t *testing.T) {
	workload := protocol.CommandWorkload{
		Args: []string{"go", "test", "./..."},
		Env: []protocol.EnvRef{
			{Name: "GOPRIVATE", ValueRef: "config:goprivate"},
			{Name: "GITHUB_TOKEN", SecretRef: "secret:github-token"},
		},
		ArtifactRefs: []string{"artifact://pool-1/input.tar"},
		ConfidentialPayload: &protocol.ConfidentialPayloadRef{
			CiphertextRef:  "artifact://pool-1/payload.cose",
			CiphertextHash: protocol.CanonicalHash("ciphertext"),
			KeyRefHash:     protocol.CanonicalHash("key-ref"),
			Algorithm:      "trustee-envelope-v1",
			KBSPolicyID:    "policy-1",
		},
	}

	if err := workload.Validate(); err != nil {
		t.Fatalf("valid command workload rejected: %v", err)
	}

	workload.Env[0].SecretRef = "secret:goprivate"
	if err := workload.Validate(); err == nil || !strings.Contains(err.Error(), "cannot set both value_ref and secret_ref") {
		t.Fatalf("env ref with both value and secret refs accepted: %v", err)
	}

	workload.Env[0].SecretRef = ""
	workload.ConfidentialPayload.CiphertextRef = "https://example.invalid/payload.cose"
	if err := workload.Validate(); err == nil || !strings.Contains(err.Error(), "ciphertext_ref") {
		t.Fatalf("origin URL confidential payload accepted: %v", err)
	}
}

func TestContainerBuildWorkloadContractUsesRegistryRefs(t *testing.T) {
	workload := protocol.ContainerBuildWorkload{
		ContextDirectory: ".",
		Tags:             []string{"example:latest"},
		PushTargetRef:    "registry:ghcr",
		PullTargetRef:    "registry:dockerhub",
		Env: []protocol.EnvRef{
			{Name: "DOCKER_CONFIG_JSON", SecretRef: "secret://pool-1/ghcr-docker-config"},
		},
	}

	if err := workload.Validate(); err != nil {
		t.Fatalf("valid container-build workload rejected: %v", err)
	}

	workload.Env[0].ValueRef = "config:docker-config"
	if err := workload.Validate(); err == nil || !strings.Contains(err.Error(), "cannot set both value_ref and secret_ref") {
		t.Fatalf("container-build env ref with both value and secret refs accepted: %v", err)
	}
}

func TestWASMRuntimePayloadContracts(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	wasm := protocol.WASMWorkload{
		ComponentRef:    "artifact://edge/echo.wasm",
		ComponentDigest: digest,
		ABI:             "wasm-export-i32-v1",
		Operation:       "handle_request",
		Input:           json.RawMessage(`{"path":"/index.html"}`),
	}
	if err := wasm.Validate(); err != nil {
		t.Fatalf("valid wasm workload rejected: %v", err)
	}
	wasm.ComponentRef = "file:///tmp/evil.wasm"
	if err := wasm.Validate(); err == nil || !strings.Contains(err.Error(), "component_ref") {
		t.Fatalf("host ref accepted: %v", err)
	}

	provider := protocol.ProviderWorkload{
		ProviderConfig: protocol.ProviderConfig{
			PluginID:   "workflow-plugin-product-capture",
			ProviderID: "browser",
			ContractID: "product-capture.browser.v1",
			Version:    "v0.1.0",
			ConfigRef:  "config://browser",
		},
		Operation:       "capture",
		ComponentRef:    "provider://workflow-plugin-product-capture/browser.wasm",
		ComponentDigest: digest,
		ABI:             "wasm-export-i32-v1",
		Input:           json.RawMessage(`{"url":"https://example.invalid"}`),
	}
	if err := provider.Validate(); err != nil {
		t.Fatalf("valid provider workload rejected: %v", err)
	}
	provider.ComponentRef = "provider://other-plugin/browser.wasm"
	if err := provider.Validate(); err == nil || !strings.Contains(err.Error(), "provider plugin") {
		t.Fatalf("mismatched provider component accepted: %v", err)
	}
}

func TestProductCaptureWorkloadValidation(t *testing.T) {
	workload := protocol.ProductCaptureWorkload{
		URL:            "https://www.amazon.com/dp/B08H75RTZ8",
		AllowedHosts:   []string{"www.amazon.com", "amazon.com"},
		CaptureMode:    protocol.ProductCaptureModeBrowser,
		TimeoutSeconds: 30,
		MaxHTMLBytes:   1 << 20,
		MaxImageCount:  8,
	}
	if err := workload.Validate(); err != nil {
		t.Fatalf("valid product-capture workload rejected: %v", err)
	}
	workload.URL = "https://evil.example/item"
	if err := workload.Validate(); err == nil || !strings.Contains(err.Error(), "allowed_hosts") {
		t.Fatalf("disallowed host accepted: %v", err)
	}
	workload.URL = "file:///tmp/item"
	if err := workload.Validate(); err == nil || !strings.Contains(err.Error(), "http") {
		t.Fatalf("non-http URL accepted: %v", err)
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

func TestExecutorMatchesPlacementRequirements(t *testing.T) {
	executor := protocol.ExecutorRef{
		Provider:              "sandboxed-command",
		Version:               "dev",
		ExecutionSecurityTier: protocol.ExecutionSandboxedContainer,
		ProofTier:             protocol.ProofArtifactHash,
	}

	if !protocol.ExecutorMatchesPlacementRequirements(executor, protocol.PlacementRequirements{}) {
		t.Fatal("empty placement requirements should match an executor")
	}
	if !protocol.ExecutorMatchesPlacementRequirements(executor, protocol.PlacementRequirements{
		ExecutorProvider:      "sandboxed-command",
		ExecutionSecurityTier: protocol.ExecutionSandboxedContainer,
		ProofTier:             protocol.ProofArtifactHash,
	}) {
		t.Fatal("matching provider/security/proof requirements should match executor")
	}
	for name, req := range map[string]protocol.PlacementRequirements{
		"provider": {
			ExecutorProvider:      "service-sandboxed-container",
			ExecutionSecurityTier: protocol.ExecutionSandboxedContainer,
			ProofTier:             protocol.ProofArtifactHash,
		},
		"security tier": {
			ExecutorProvider:      "sandboxed-command",
			ExecutionSecurityTier: protocol.ExecutionMicroVM,
			ProofTier:             protocol.ProofArtifactHash,
		},
		"proof tier": {
			ExecutorProvider:      "sandboxed-command",
			ExecutionSecurityTier: protocol.ExecutionSandboxedContainer,
			ProofTier:             protocol.ProofAttestedReceipt,
		},
	} {
		if protocol.ExecutorMatchesPlacementRequirements(executor, req) {
			t.Fatalf("%s mismatch unexpectedly matched executor", name)
		}
	}
}

func TestExecutorCapabilitiesHaveResourceConstrainedMatch(t *testing.T) {
	req := protocol.PlacementRequirements{
		ExecutorProvider:      "sandboxed-command",
		ExecutionSecurityTier: protocol.ExecutionSandboxedContainer,
		ProofTier:             protocol.ProofArtifactHash,
	}

	if !protocol.ResourceLimitsRequireResourceConstrainedExecutor(protocol.ResourceLimits{CPUPercent: 50}) {
		t.Fatal("cpu_percent limits should require resource-constrained executor")
	}
	if !protocol.ResourceLimitsRequireResourceConstrainedExecutor(protocol.ResourceLimits{MemoryBytes: 128 << 20}) {
		t.Fatal("memory_bytes limits should require resource-constrained executor")
	}
	if protocol.ResourceLimitsRequireResourceConstrainedExecutor(protocol.ResourceLimits{WorkspaceBytes: 1 << 30}) {
		t.Fatal("workspace-only limits should not require resource-constrained executor")
	}

	if protocol.ExecutorCapabilitiesHaveResourceConstrainedMatch(req, protocol.ExecutorCapabilities{
		Executors: []protocol.ExecutorRef{{
			Provider:              "command",
			ExecutionSecurityTier: protocol.ExecutionTrustedNative,
			ProofTier:             protocol.ProofReceiptOnly,
		}},
	}) {
		t.Fatal("trusted native executor should not satisfy resource-constrained placement")
	}

	if !protocol.ExecutorCapabilitiesHaveResourceConstrainedMatch(req, protocol.ExecutorCapabilities{
		Executors: []protocol.ExecutorRef{{
			Provider:              "sandboxed-command",
			ExecutionSecurityTier: protocol.ExecutionSandboxedContainer,
			ProofTier:             protocol.ProofArtifactHash,
		}},
	}) {
		t.Fatal("matching sandboxed executor should satisfy resource-constrained placement")
	}

	if !protocol.ExecutorCapabilitiesHaveResourceConstrainedMatch(protocol.PlacementRequirements{}, protocol.ExecutorCapabilities{
		ExecutionTiers: []protocol.ExecutionSecurityTier{protocol.ExecutionSandboxedContainer},
	}) {
		t.Fatal("legacy tier-only capabilities should satisfy when they include a constrained tier")
	}
}

func TestValidatePlacementRequirementsAgainstCapabilities(t *testing.T) {
	req := protocol.PlacementRequirements{
		ExecutorProvider:      "sandboxed-command",
		ExecutionSecurityTier: protocol.ExecutionSandboxedContainer,
		ProofTier:             protocol.ProofArtifactHash,
		RequiredCapabilities:  []string{"mobile", "mobile", "bad tag"},
	}
	caps := protocol.PlacementRequirementCapabilities{
		CapabilityTags:    []string{"mobile"},
		ExecutorProviders: []string{"other-provider"},
		ExecutionTiers:    []protocol.ExecutionSecurityTier{protocol.ExecutionTrustedNative},
		ProofTiers:        []protocol.ProofTier{protocol.ProofReceiptOnly},
		CapabilityReports: []protocol.ProviderCapabilityReport{{
			Provider: "sandboxed-command",
			Status:   protocol.ProviderCapabilityUnsupported,
			Reason:   "runtime unavailable",
		}},
		Executors: []protocol.ExecutorRef{{
			Provider:              "sandboxed-command",
			ExecutionSecurityTier: protocol.ExecutionTrustedNative,
			ProofTier:             protocol.ProofReceiptOnly,
		}},
	}

	err := protocol.ValidatePlacementRequirementsAgainstCapabilities(req, caps)
	if err == nil {
		t.Fatal("expected placement requirements to reject incompatible capabilities")
	}
	for _, want := range []string{
		"task requirements required_capabilities[1] \"mobile\" is duplicated",
		"task requirements required_capabilities[2] must not contain whitespace",
		`worker does not support executor provider "sandboxed-command"`,
		`worker executor provider "sandboxed-command" is unsupported: runtime unavailable`,
		`worker does not support execution security tier "sandboxed-container"`,
		`worker does not support proof tier "artifact-hash"`,
		"worker has no supported executor matching task placement requirements",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("expected placement error to contain %q, got %v", want, err)
		}
	}

	validCaps := protocol.PlacementRequirementCapabilities{
		CapabilityTags:    []string{"mobile"},
		ExecutorProviders: []string{"sandboxed-command"},
		ExecutionTiers:    []protocol.ExecutionSecurityTier{protocol.ExecutionSandboxedContainer},
		ProofTiers:        []protocol.ProofTier{protocol.ProofArtifactHash},
		Executors: []protocol.ExecutorRef{{
			Provider:              "sandboxed-command",
			ExecutionSecurityTier: protocol.ExecutionSandboxedContainer,
			ProofTier:             protocol.ProofArtifactHash,
		}},
	}
	validReq := req
	validReq.RequiredCapabilities = []string{"mobile"}
	if err := protocol.ValidatePlacementRequirementsAgainstCapabilities(validReq, validCaps); err != nil {
		t.Fatalf("compatible placement requirements rejected: %v", err)
	}

	unknownReq := protocol.PlacementRequirements{
		ExecutionSecurityTier: protocol.ExecutionSecurityTier("magic-vm"),
		ProofTier:             protocol.ProofTier("pinkie-promise"),
	}
	err = protocol.ValidatePlacementRequirementsAgainstCapabilities(unknownReq, protocol.PlacementRequirementCapabilities{})
	if err == nil ||
		!strings.Contains(err.Error(), "task requirements execution_security_tier") ||
		!strings.Contains(err.Error(), "task requirements proof_tier") {
		t.Fatalf("expected unknown tier errors, got %v", err)
	}
}

func TestRequiredHardwareClass(t *testing.T) {
	for name, tc := range map[string]struct {
		req  protocol.PlacementRequirements
		want string
	}{
		"explicit": {
			req:  protocol.PlacementRequirements{HardwareClass: "sev-snp"},
			want: "sev-snp",
		},
		"confidential cpu": {
			req:  protocol.PlacementRequirements{ExecutionSecurityTier: protocol.ExecutionConfidentialCPU},
			want: "confidential-cpu",
		},
		"confidential gpu": {
			req:  protocol.PlacementRequirements{ExecutionSecurityTier: protocol.ExecutionConfidentialGPU},
			want: "confidential-gpu",
		},
		"none": {
			req: protocol.PlacementRequirements{},
		},
	} {
		t.Run(name, func(t *testing.T) {
			if got := protocol.RequiredHardwareClass(tc.req); got != tc.want {
				t.Fatalf("RequiredHardwareClass() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestHardwareCapabilitiesSatisfyPlacementRequirements(t *testing.T) {
	now := time.Date(2026, 5, 26, 5, 0, 0, 0, time.UTC)
	verifiedCPU := protocol.HardwareAttestation{
		Class:      "confidential-cpu",
		Provider:   "sev-snp",
		VerifierID: "verifier-1",
		KeyID:      "key-1",
		Verified:   true,
		ExpiresAt:  now.Add(time.Hour),
	}
	verifiedGPU := protocol.HardwareAttestation{
		Class:      "confidential-gpu",
		Provider:   "nvidia-cc",
		VerifierID: "verifier-1",
		KeyID:      "key-1",
		Verified:   true,
		ExpiresAt:  now.Add(time.Hour),
	}

	for name, tc := range map[string]struct {
		req  protocol.PlacementRequirements
		caps protocol.HardwarePlacementCapabilities
		want bool
	}{
		"confidential cpu requires verified attestation": {
			req: protocol.PlacementRequirements{ExecutionSecurityTier: protocol.ExecutionConfidentialCPU},
			caps: protocol.HardwarePlacementCapabilities{
				Now: now,
				Security: protocol.HardwareSecurityCapabilities{
					HardwareAttestations: []protocol.HardwareAttestation{verifiedCPU},
				},
			},
			want: true,
		},
		"confidential cpu rejects expired attestation": {
			req: protocol.PlacementRequirements{ExecutionSecurityTier: protocol.ExecutionConfidentialCPU},
			caps: protocol.HardwarePlacementCapabilities{
				Now: now,
				Security: protocol.HardwareSecurityCapabilities{HardwareAttestations: []protocol.HardwareAttestation{{
					Class:      "confidential-cpu",
					Provider:   "sev-snp",
					VerifierID: "verifier-1",
					KeyID:      "key-1",
					Verified:   true,
					ExpiresAt:  now.Add(-time.Second),
				}}},
			},
		},
		"confidential gpu requires gpu and verified attestation": {
			req: protocol.PlacementRequirements{ExecutionSecurityTier: protocol.ExecutionConfidentialGPU},
			caps: protocol.HardwarePlacementCapabilities{
				GPUCount: 1,
				Now:      now,
				Security: protocol.HardwareSecurityCapabilities{
					HardwareAttestations: []protocol.HardwareAttestation{verifiedGPU},
				},
			},
			want: true,
		},
		"confidential gpu rejects missing gpu even with attestation": {
			req: protocol.PlacementRequirements{ExecutionSecurityTier: protocol.ExecutionConfidentialGPU},
			caps: protocol.HardwarePlacementCapabilities{Security: protocol.HardwareSecurityCapabilities{
				HardwareAttestations: []protocol.HardwareAttestation{verifiedGPU},
			}},
		},
		"custom class accepts hardware_classes": {
			req: protocol.PlacementRequirements{HardwareClass: "arm-neoverse"},
			caps: protocol.HardwarePlacementCapabilities{Security: protocol.HardwareSecurityCapabilities{
				HardwareClasses: []string{"arm-neoverse"},
			}},
			want: true,
		},
		"custom class accepts tee": {
			req: protocol.PlacementRequirements{HardwareClass: "sev-snp"},
			caps: protocol.HardwarePlacementCapabilities{Security: protocol.HardwareSecurityCapabilities{
				TEE: []string{"sev-snp"},
			}},
			want: true,
		},
		"custom class with confidential tier requires verified attestation": {
			req: protocol.PlacementRequirements{
				ExecutionSecurityTier: protocol.ExecutionConfidentialCPU,
				HardwareClass:         "sev-snp",
			},
			caps: protocol.HardwarePlacementCapabilities{Security: protocol.HardwareSecurityCapabilities{
				HardwareClasses: []string{"sev-snp"},
			}},
		},
	} {
		t.Run(name, func(t *testing.T) {
			if got := protocol.HardwareCapabilitiesSatisfyPlacementRequirements(tc.req, tc.caps); got != tc.want {
				t.Fatalf("HardwareCapabilitiesSatisfyPlacementRequirements() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAttestationDecisionBindingDigest(t *testing.T) {
	attestation := validAttestationDecision(protocol.ExecutionConfidentialCPU)
	first := attestation.BindingDigest()
	if first == "" || !strings.HasPrefix(first, "sha256:") {
		t.Fatalf("binding digest = %q", first)
	}

	attestation.Signature.Value = "rotated-signature"
	attestation.SignatureVerified = false
	if got := attestation.BindingDigest(); got != first {
		t.Fatalf("binding digest included signature-only fields: got %q want %q", got, first)
	}

	attestation.DecisionID = "attest-2"
	if got := attestation.BindingDigest(); got == first {
		t.Fatalf("binding digest did not include decision identity: %q", got)
	}
}

func TestValidateAttestedProofBinding(t *testing.T) {
	valid := validAttestedProofBinding(protocol.ExecutionConfidentialCPU)
	if err := protocol.ValidateAttestedProofBinding(valid); err != nil {
		t.Fatalf("valid attested proof binding rejected: %v", err)
	}

	for name, mutate := range map[string]func(*protocol.AttestedProofBinding){
		"missing attestation": func(binding *protocol.AttestedProofBinding) {
			binding.Verifier.Attestation = protocol.AttestationDecision{}
		},
		"missing key release": func(binding *protocol.AttestedProofBinding) {
			binding.Verifier.KeyRelease = protocol.KeyReleaseDecision{}
		},
		"missing executor proof metadata": func(binding *protocol.AttestedProofBinding) {
			binding.Executor.ProofTier = ""
		},
		"policy mismatch": func(binding *protocol.AttestedProofBinding) {
			binding.Verifier.Attestation.PolicyID = "other-policy"
		},
		"task hash mismatch": func(binding *protocol.AttestedProofBinding) {
			binding.Verifier.KeyRelease.TaskHash = "sha256:other-task"
		},
		"attestation digest mismatch": func(binding *protocol.AttestedProofBinding) {
			binding.Verifier.KeyRelease.AttestationDigest = "sha256:other-attestation"
		},
		"started before attestation": func(binding *protocol.AttestedProofBinding) {
			binding.StartedAt = time.Unix(98, 0).UTC()
		},
		"finished after key release": func(binding *protocol.AttestedProofBinding) {
			binding.FinishedAt = time.Unix(121, 0).UTC()
		},
	} {
		t.Run(name, func(t *testing.T) {
			binding := valid
			mutate(&binding)
			if err := protocol.ValidateAttestedProofBinding(binding); err == nil {
				t.Fatal("expected attested proof binding to fail")
			}
		})
	}
}

func TestValidateAttestedProofBindingRequiresConfidentialGPUEvidence(t *testing.T) {
	binding := validAttestedProofBinding(protocol.ExecutionConfidentialGPU)
	binding.Verifier.Attestation.ConfidentialGPU = false
	binding.Verifier.KeyRelease = validKeyReleaseDecisionFor(binding.Verifier.Attestation)

	err := protocol.ValidateAttestedProofBinding(binding)
	if err == nil || !strings.Contains(err.Error(), "confidential_gpu") {
		t.Fatalf("expected confidential GPU evidence error, got %v", err)
	}

	binding.Verifier.Attestation.ConfidentialGPU = true
	binding.Verifier.KeyRelease = validKeyReleaseDecisionFor(binding.Verifier.Attestation)
	if err := protocol.ValidateAttestedProofBinding(binding); err != nil {
		t.Fatalf("confidential GPU binding rejected: %v", err)
	}
}

func TestValidateAttestedServiceBinding(t *testing.T) {
	valid := validAttestedServiceBinding(protocol.ExecutionConfidentialCPU)
	if err := protocol.ValidateAttestedServiceBinding(valid); err != nil {
		t.Fatalf("valid attested service binding rejected: %v", err)
	}

	for name, mutate := range map[string]func(*protocol.AttestedServiceBinding){
		"missing attestation": func(binding *protocol.AttestedServiceBinding) {
			binding.Verifier.Attestation = protocol.AttestationDecision{}
		},
		"missing key release": func(binding *protocol.AttestedServiceBinding) {
			binding.Verifier.KeyRelease = protocol.KeyReleaseDecision{}
		},
		"policy mismatch": func(binding *protocol.AttestedServiceBinding) {
			binding.Verifier.Attestation.PolicyID = "other-policy"
		},
		"deployment mismatch": func(binding *protocol.AttestedServiceBinding) {
			binding.Verifier.KeyRelease.DependencyClosureHash = "sha256:other-deployment"
		},
		"worker mismatch": func(binding *protocol.AttestedServiceBinding) {
			binding.Verifier.KeyRelease.WorkerID = "other-worker"
		},
		"pool mismatch": func(binding *protocol.AttestedServiceBinding) {
			binding.Verifier.KeyRelease.PoolID = "other-pool"
		},
		"attestation digest mismatch": func(binding *protocol.AttestedServiceBinding) {
			binding.Verifier.KeyRelease.AttestationDigest = "sha256:other-attestation"
		},
		"started before attestation": func(binding *protocol.AttestedServiceBinding) {
			binding.StartedAt = time.Unix(98, 0).UTC()
		},
		"finished after key release": func(binding *protocol.AttestedServiceBinding) {
			binding.FinishedAt = time.Unix(121, 0).UTC()
		},
	} {
		t.Run(name, func(t *testing.T) {
			binding := valid
			mutate(&binding)
			if err := protocol.ValidateAttestedServiceBinding(binding); err == nil {
				t.Fatal("expected attested service binding to fail")
			}
		})
	}
}

func TestValidateAttestedServiceBindingAllowsExistingOptionalKeyReleaseMetadata(t *testing.T) {
	binding := validAttestedServiceBinding(protocol.ExecutionConfidentialCPU)
	binding.Verifier.KeyRelease.PolicyID = ""
	binding.Verifier.KeyRelease.TaskID = ""
	binding.Verifier.KeyRelease.TaskHash = ""
	binding.Verifier.KeyRelease.InputHash = ""
	binding.Verifier.KeyRelease.DependencyClosureHash = ""
	binding.Verifier.KeyRelease.WorkerID = ""
	binding.Verifier.KeyRelease.PoolID = ""

	if err := protocol.ValidateAttestedServiceBinding(binding); err != nil {
		t.Fatalf("service binding with optional key-release metadata omitted rejected: %v", err)
	}
}

func TestValidateAttestedServiceBindingRequiresConfidentialGPUEvidence(t *testing.T) {
	binding := validAttestedServiceBinding(protocol.ExecutionConfidentialGPU)
	binding.Verifier.Attestation.ConfidentialGPU = false
	binding.Verifier.KeyRelease = validKeyReleaseDecisionFor(binding.Verifier.Attestation)

	err := protocol.ValidateAttestedServiceBinding(binding)
	if err == nil || !strings.Contains(err.Error(), "confidential_gpu") {
		t.Fatalf("expected confidential GPU evidence error, got %v", err)
	}

	binding.Verifier.Attestation.ConfidentialGPU = true
	binding.Verifier.KeyRelease = validKeyReleaseDecisionFor(binding.Verifier.Attestation)
	if err := protocol.ValidateAttestedServiceBinding(binding); err != nil {
		t.Fatalf("confidential GPU service binding rejected: %v", err)
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

func validAttestedServiceBinding(tier protocol.ExecutionSecurityTier) protocol.AttestedServiceBinding {
	attestation := validAttestationDecision(tier)
	return protocol.AttestedServiceBinding{
		Executor: protocol.ExecutorRef{
			Provider:              "confidential-service",
			Version:               "dev",
			ExecutionSecurityTier: tier,
			ProofTier:             protocol.ProofAttestedReceipt,
			ImageDigest:           "sha256:image",
			RootFSDigest:          "sha256:rootfs",
		},
		PolicyID:       "policy-1",
		TaskID:         "task-1",
		DeploymentHash: "sha256:deps",
		WorkerID:       "worker-1",
		PoolID:         "pool-1",
		StartedAt:      time.Unix(100, 0).UTC(),
		FinishedAt:     time.Unix(101, 0).UTC(),
		Verifier: protocol.VerifierResult{
			Provider:    "attestation_key_release",
			Status:      protocol.VerificationAccepted,
			Attestation: attestation,
			KeyRelease:  validKeyReleaseDecisionFor(attestation),
		},
	}
}

func validAttestedProofBinding(tier protocol.ExecutionSecurityTier) protocol.AttestedProofBinding {
	attestation := validAttestationDecision(tier)
	return protocol.AttestedProofBinding{
		Executor: protocol.ExecutorRef{
			Provider:              "confidential-command",
			Version:               "dev",
			ExecutionSecurityTier: tier,
			ProofTier:             protocol.ProofAttestedReceipt,
			ImageDigest:           "sha256:image",
			RootFSDigest:          "sha256:rootfs",
		},
		PolicyID:              "policy-1",
		TaskID:                "task-1",
		TaskHash:              "sha256:task",
		InputHash:             "sha256:input",
		DependencyClosureHash: "sha256:deps",
		WorkerID:              "worker-1",
		PoolID:                "pool-1",
		StartedAt:             time.Unix(100, 0).UTC(),
		FinishedAt:            time.Unix(101, 0).UTC(),
		Verifier: protocol.VerifierResult{
			Provider:    "attestation_key_release",
			Status:      protocol.VerificationAccepted,
			Attestation: attestation,
			KeyRelease:  validKeyReleaseDecisionFor(attestation),
		},
	}
}

func validAttestationDecision(tier protocol.ExecutionSecurityTier) protocol.AttestationDecision {
	return protocol.AttestationDecision{
		Provider:             "fake-attestation",
		VerifierID:           "verifier-1",
		DecisionID:           "attest-1",
		HardwareClass:        string(tier),
		ExecutorImageDigest:  "sha256:image",
		ExecutorRootFSDigest: "sha256:rootfs",
		PolicyID:             "policy-1",
		Nonce:                "nonce-1",
		IssuedAt:             time.Unix(99, 0).UTC(),
		ExpiresAt:            time.Unix(120, 0).UTC(),
		SignatureVerified:    true,
		ConfidentialGPU:      tier == protocol.ExecutionConfidentialGPU,
		Signature: protocol.SignatureEnvelope{
			Algorithm: "ed25519",
			KeyID:     "attestation-key",
			Value:     "sig",
			Verified:  true,
		},
	}
}

func validKeyReleaseDecisionFor(attestation protocol.AttestationDecision) protocol.KeyReleaseDecision {
	return protocol.KeyReleaseDecision{
		Provider:              "fake-key-release",
		DecisionID:            "key-release-1",
		AttestationDecisionID: "attest-1",
		AttestationDigest:     attestation.BindingDigest(),
		AttestationProvider:   attestation.Provider,
		AttestationVerifierID: attestation.VerifierID,
		AttestationKeyID:      attestation.Signature.KeyID,
		PolicyID:              "policy-1",
		TaskID:                "task-1",
		TaskHash:              "sha256:task",
		InputHash:             "sha256:input",
		DependencyClosureHash: "sha256:deps",
		WorkerID:              "worker-1",
		PoolID:                "pool-1",
		KeyRefHash:            "sha256:key-ref",
		Released:              true,
		ExpiresAt:             time.Unix(120, 0).UTC(),
		Signature: protocol.SignatureEnvelope{
			Algorithm: "ed25519",
			KeyID:     "key-release-key",
			Value:     "sig",
			Verified:  true,
		},
	}
}

func TestValidateResourceLimitsAgainstCapacity(t *testing.T) {
	limits := protocol.ResourceLimits{
		CPUPercent:     1_100,
		MemoryBytes:    64 << 30,
		WorkspaceBytes: 1 << 40,
	}
	capacity := protocol.ResourceCapacity{
		CPUCount:    4,
		MemoryBytes: 8 << 30,
		DiskBytes:   20 << 30,
	}

	err := protocol.ValidateResourceLimitsAgainstCapacity(limits, capacity)
	if err == nil {
		t.Fatal("expected oversized resource limits to fail")
	}
	for _, want := range []string{
		"resource_limits.cpu_percent 1100 exceeds worker CPU capacity 400",
		"resource_limits.memory_bytes",
		"resource_limits.workspace_bytes",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("expected resource capacity error to contain %q, got %v", want, err)
		}
	}

	if err := protocol.ValidateResourceLimitsAgainstCapacity(protocol.ResourceLimits{
		CPUPercent:     400,
		MemoryBytes:    8 << 30,
		WorkspaceBytes: 20 << 30,
	}, capacity); err != nil {
		t.Fatalf("limits at capacity should pass: %v", err)
	}

	if err := protocol.ValidateResourceLimitsAgainstCapacity(limits, protocol.ResourceCapacity{}); err != nil {
		t.Fatalf("unknown capacity should not reject limits: %v", err)
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

func TestProviderOperationAcceptsProviderReturnArtifactIntent(t *testing.T) {
	operation := protocol.ProviderOperation{
		ID:                 "build",
		InputSchemaRef:     "schema://providers/example/operations/build/input/v1",
		InputSchemaDigest:  protocol.CanonicalHash("input"),
		OutputSchemaRef:    "schema://providers/example/operations/build/output/v1",
		OutputSchemaDigest: protocol.CanonicalHash("output"),
		ArtifactSpecs: []protocol.ProviderArtifactSpec{{
			Name:        "provenance",
			Required:    true,
			ContentType: "application/json",
			ProviderReturn: &protocol.ProviderArtifactReturnSpec{
				StepType:        "step.provider_artifact_return",
				Contract:        "workflow-plugin-ci:step.provider_artifact_return",
				ContractVersion: "v1",
				SubmitEndpoint:  "/v1/provider-return/artifact-deliveries",
			},
		}},
	}

	if err := operation.Validate(); err != nil {
		t.Fatalf("operation invalid: %v", err)
	}
	specs := operation.NormalizedArtifactSpecs()
	if len(specs) != 1 || specs[0].ProviderReturn == nil || !specs[0].ProviderReturn.Enabled() {
		t.Fatalf("provider return intent not preserved: %#v", specs)
	}
}

func TestProviderOperationRejectsMalformedProviderReturnArtifactIntent(t *testing.T) {
	valid := protocol.ProviderOperation{
		ID:                 "build",
		InputSchemaRef:     "schema://providers/example/operations/build/input/v1",
		InputSchemaDigest:  protocol.CanonicalHash("input"),
		OutputSchemaRef:    "schema://providers/example/operations/build/output/v1",
		OutputSchemaDigest: protocol.CanonicalHash("output"),
		ArtifactSpecs: []protocol.ProviderArtifactSpec{{
			Name: "provenance",
			ProviderReturn: &protocol.ProviderArtifactReturnSpec{
				StepType:        "step.provider_artifact_return",
				Contract:        "workflow-plugin-ci:step.provider_artifact_return",
				ContractVersion: "v1",
				SubmitEndpoint:  "/v1/provider-return/artifact-deliveries",
			},
		}},
	}
	cases := map[string]func(*protocol.ProviderArtifactReturnSpec){
		"missing step type": func(spec *protocol.ProviderArtifactReturnSpec) {
			spec.StepType = ""
		},
		"missing contract": func(spec *protocol.ProviderArtifactReturnSpec) {
			spec.Contract = ""
		},
		"absolute submit endpoint": func(spec *protocol.ProviderArtifactReturnSpec) {
			spec.SubmitEndpoint = "https://provider.example/upload"
		},
		"control whitespace": func(spec *protocol.ProviderArtifactReturnSpec) {
			spec.Contract = "workflow-plugin-ci:step.provider_artifact_return\n"
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			operation := valid
			returnSpec := *valid.ArtifactSpecs[0].ProviderReturn
			mutate(&returnSpec)
			operation.ArtifactSpecs = []protocol.ProviderArtifactSpec{{Name: "provenance", ProviderReturn: &returnSpec}}
			if err := operation.Validate(); err == nil {
				t.Fatalf("expected invalid provider return intent")
			}
		})
	}
}

func TestProviderArtifactDeliveryValidatesStatusAndArtifactRef(t *testing.T) {
	now := time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC)
	delivery := protocol.ProviderArtifactDelivery{
		ProtocolVersion: protocol.Version,
		ID:              "provider-artifact-delivery-1",
		OrgID:           "gocodealone",
		PoolID:          "ci",
		TaskID:          "task-1",
		ProofID:         "proof-1",
		WorkerID:        "worker-1",
		ProviderConfig: protocol.ProviderConfig{
			PluginID:   "workflow-plugin-ci",
			ProviderID: "ci",
			ContractID: "ci.v1",
			Version:    "v1",
			ConfigRef:  "config://providers/ci",
		},
		Operation: "build",
		ReturnSpec: protocol.ProviderArtifactReturnSpec{
			StepType:        "step.provider_artifact_return",
			Contract:        "workflow-plugin-ci:step.provider_artifact_return",
			ContractVersion: "v1",
			SubmitEndpoint:  "/v1/provider-return/artifact-deliveries",
		},
		Artifact: protocol.ProviderArtifactDeliveryArtifact{
			Name:        "provenance",
			Ref:         "artifact://ci/tasks/task-1/proofs/proof-1/provenance",
			ContentType: "application/json",
			SHA256:      protocol.CanonicalHash("artifact"),
			SizeBytes:   42,
		},
		Status:    protocol.ProviderArtifactDeliveryPending,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := delivery.Validate(); err != nil {
		t.Fatalf("delivery invalid: %v", err)
	}
	delivery.Status = protocol.ProviderArtifactDeliveryStatus("unknown")
	if err := delivery.Validate(); err == nil || !strings.Contains(err.Error(), "status") {
		t.Fatalf("expected status validation error, got %v", err)
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

func TestProviderContractAppliesProviderConformanceEvidence(t *testing.T) {
	contract := validBatchProviderContract()
	profile := contract.RuntimeContract.Profiles[0]
	evidence := protocol.ProviderConformanceEvidence{
		ProtocolVersion:       protocol.Version,
		ID:                    "example-real-client-evidence",
		PluginID:              contract.PluginID,
		ProviderID:            contract.ProviderID,
		ContractID:            contract.ContractID,
		Version:               contract.Version,
		RuntimeProfileID:      profile.ID,
		ConformanceProfile:    "upstream-client-v1",
		UpstreamClientName:    "example-client",
		UpstreamClientVersion: "1.2.3",
		EvidenceRef:           "artifact://providers/example/evidence/upstream-client-v1",
		EvidenceDigest:        protocol.CanonicalHash("evidence"),
		ObservedAt:            time.Now().UTC(),
	}

	if err := contract.ApplyProviderConformanceEvidence(evidence); err != nil {
		t.Fatalf("apply evidence: %v", err)
	}
	got := contract.RuntimeContract.Profiles[0]
	if got.UpstreamClientConformance != protocol.UpstreamClientConformanceRealClient ||
		got.UpstreamClientEvidenceRef != evidence.EvidenceRef ||
		got.UpstreamClientEvidenceDigest != evidence.EvidenceDigest {
		t.Fatalf("runtime profile evidence was not applied: %+v", got)
	}
	if !slices.Contains(got.ConformanceProfiles, evidence.ConformanceProfile) {
		t.Fatalf("runtime profile missing conformance profile %q: %+v", evidence.ConformanceProfile, got.ConformanceProfiles)
	}
	if err := contract.ApplyProviderConformanceEvidence(evidence); err != nil {
		t.Fatalf("reapply evidence: %v", err)
	}
	if got := contract.RuntimeContract.Profiles[0].ConformanceProfiles; countString(got, evidence.ConformanceProfile) != 1 {
		t.Fatalf("runtime profile duplicated conformance profile %q: %+v", evidence.ConformanceProfile, got)
	}

	evidence.PluginID = "workflow-plugin-other"
	if err := contract.ApplyProviderConformanceEvidence(evidence); err == nil || !strings.Contains(err.Error(), "does not match provider contract tuple") {
		t.Fatalf("expected tuple mismatch error, got %v", err)
	}
	evidence.PluginID = contract.PluginID
	evidence.RuntimeProfileID = "missing-runtime"
	if err := contract.ApplyProviderConformanceEvidence(evidence); err == nil || !strings.Contains(err.Error(), "runtime profile") {
		t.Fatalf("expected runtime profile mismatch error, got %v", err)
	}
}

func TestDefaultProviderRuntimeContractBuildsRuntimeMatrix(t *testing.T) {
	contract := protocol.DefaultProviderRuntimeContract(
		[]string{"sandboxed-command", "service-sandboxed-container"},
		[]protocol.ExecutionSecurityTier{protocol.ExecutionSandboxedContainer},
		[]protocol.ProofTier{protocol.ProofArtifactHash},
		protocol.ProviderRuntimeContractOptions{
			ConformanceProfiles:       []string{"upstream-client-v1"},
			UpstreamClientConformance: protocol.UpstreamClientConformanceRealClient,
			UpstreamClientEvidenceRef: "artifact://providers/example/evidence/upstream-client-v1",
			UpstreamClientEvidenceDigest: protocol.CanonicalHash(
				"evidence",
			),
		},
	)

	if len(contract.Profiles) != 2 {
		t.Fatalf("runtime profiles = %d, want 2: %+v", len(contract.Profiles), contract.Profiles)
	}
	for _, profile := range contract.Profiles {
		if profile.ExecutionSecurityTier != protocol.ExecutionSandboxedContainer ||
			profile.ProofTier != protocol.ProofArtifactHash ||
			profile.UpstreamClientConformance != protocol.UpstreamClientConformanceRealClient ||
			profile.UpstreamClientEvidenceRef == "" ||
			profile.UpstreamClientEvidenceDigest == "" {
			t.Fatalf("runtime profile missing shared options: %+v", profile)
		}
		if len(profile.ConformanceProfiles) < 2 ||
			!slices.Contains(profile.ConformanceProfiles, "upstream-client-v1") {
			t.Fatalf("runtime profile missing default or option conformance profiles: %+v", profile.ConformanceProfiles)
		}
	}
}

func TestProviderRuntimeContractSelectsProfileForPlacementRequirements(t *testing.T) {
	contract := protocol.DefaultProviderRuntimeContract(
		[]string{"sandboxed-command", "service-sandboxed-container"},
		[]protocol.ExecutionSecurityTier{protocol.ExecutionSandboxedContainer},
		[]protocol.ProofTier{protocol.ProofArtifactHash},
		protocol.ProviderRuntimeContractOptions{},
	)

	profile, ok := contract.RuntimeProfileForRequirements(protocol.PlacementRequirements{
		ExecutorProvider:      "service-sandboxed-container",
		ExecutionSecurityTier: protocol.ExecutionSandboxedContainer,
		ProofTier:             protocol.ProofArtifactHash,
	})

	if !ok {
		t.Fatal("expected matching runtime profile")
	}
	if profile.ExecutorProvider != "service-sandboxed-container" ||
		profile.ExecutionSecurityTier != protocol.ExecutionSandboxedContainer ||
		profile.ProofTier != protocol.ProofArtifactHash {
		t.Fatalf("selected runtime profile = %+v", profile)
	}
	if _, ok := contract.RuntimeProfileForRequirements(protocol.PlacementRequirements{
		ExecutorProvider:      "node-service-sandboxed-container",
		ExecutionSecurityTier: protocol.ExecutionSandboxedContainer,
		ProofTier:             protocol.ProofArtifactHash,
	}); ok {
		t.Fatal("unexpected runtime profile match for unsupported executor")
	}
}

func TestDefaultProviderRuntimeProfileMatchesKnownExecutorShapes(t *testing.T) {
	tests := []struct {
		executor               string
		runtimeProfile         protocol.RuntimeProfile
		conformanceProfile     string
		writableRootFS         protocol.RuntimePermission
		allowedCapabilities    []string
		allowedMountRefs       []string
		writablePaths          []string
		imageDigestRequired    bool
		rootFSDigestRequired   bool
		hostWorkspaceSupported bool
	}{
		{
			executor:               "sandboxed-command",
			runtimeProfile:         protocol.RuntimeProfileSandboxedOCI,
			conformanceProfile:     "sandboxed-oci-v1",
			writableRootFS:         protocol.RuntimePermissionForbidden,
			allowedMountRefs:       []string{"workspace"},
			writablePaths:          []string{"/tmp"},
			imageDigestRequired:    true,
			rootFSDigestRequired:   true,
			hostWorkspaceSupported: true,
		},
		{
			executor:               "sandboxed-container-build",
			runtimeProfile:         protocol.RuntimeProfileContainerBuild,
			conformanceProfile:     "container-build-v1",
			writableRootFS:         protocol.RuntimePermissionExplicit,
			allowedCapabilities:    []string{"CHOWN", "FOWNER"},
			allowedMountRefs:       []string{"workspace"},
			writablePaths:          []string{"/tmp", "/wfcompute-build"},
			imageDigestRequired:    true,
			rootFSDigestRequired:   true,
			hostWorkspaceSupported: true,
		},
		{
			executor:               "node-service-sandboxed-container",
			runtimeProfile:         protocol.RuntimeProfileServiceOCI,
			conformanceProfile:     "service-oci-v1",
			writableRootFS:         protocol.RuntimePermissionForbidden,
			allowedMountRefs:       []string{"workspace", "node-data"},
			writablePaths:          []string{"/tmp"},
			imageDigestRequired:    true,
			rootFSDigestRequired:   true,
			hostWorkspaceSupported: true,
		},
		{
			executor:               "wasm-component",
			runtimeProfile:         protocol.RuntimeProfileWASMComponent,
			conformanceProfile:     "wasm-component-v1",
			writableRootFS:         protocol.RuntimePermissionForbidden,
			imageDigestRequired:    false,
			rootFSDigestRequired:   false,
			hostWorkspaceSupported: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.executor, func(t *testing.T) {
			profile := protocol.DefaultProviderRuntimeProfile(tc.executor, protocol.ExecutionSandboxedContainer, protocol.ProofArtifactHash)
			if profile.RuntimeProfile != tc.runtimeProfile ||
				profile.WritableRootFS != tc.writableRootFS ||
				profile.ImageDigestRequired != tc.imageDigestRequired ||
				profile.RootFSDigestRequired != tc.rootFSDigestRequired ||
				profile.HostWorkspaceSupported != tc.hostWorkspaceSupported {
				t.Fatalf("runtime profile mismatch: %+v", profile)
			}
			if !slices.Contains(profile.ConformanceProfiles, tc.conformanceProfile) {
				t.Fatalf("missing conformance profile %q: %+v", tc.conformanceProfile, profile.ConformanceProfiles)
			}
			if !slices.Equal(profile.AllowedCapabilities, tc.allowedCapabilities) {
				t.Fatalf("allowed capabilities = %+v, want %+v", profile.AllowedCapabilities, tc.allowedCapabilities)
			}
			if !slices.Equal(profile.AllowedMountRefs, tc.allowedMountRefs) {
				t.Fatalf("allowed mount refs = %+v, want %+v", profile.AllowedMountRefs, tc.allowedMountRefs)
			}
			if !slices.Equal(profile.WritablePaths, tc.writablePaths) {
				t.Fatalf("writable paths = %+v, want %+v", profile.WritablePaths, tc.writablePaths)
			}
		})
	}
}

func countString(values []string, target string) int {
	count := 0
	for _, value := range values {
		if value == target {
			count++
		}
	}
	return count
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
