package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func TestCredentialReceiptSignaturesBindPayloadAndToken(t *testing.T) {
	key := TokenProofKey("agent-token")

	proof := testProofReceipt()
	proof.AgentSignature = CredentialProofSignature(proof, key)
	if !VerifyCredentialProofSignature(proof, key) {
		t.Fatal("proof credential signature should verify with same payload and token key")
	}
	tamperedProof := proof
	tamperedProof.ArtifactHash = digest("tampered")
	if VerifyCredentialProofSignature(tamperedProof, key) {
		t.Fatal("proof credential signature verified after payload tamper")
	}
	if VerifyCredentialProofSignature(proof, TokenProofKey("other-token")) {
		t.Fatal("proof credential signature verified with different token key")
	}

	service := testServiceReceipt()
	service.AgentSignature = CredentialServiceSignature(service, key)
	if !VerifyCredentialServiceSignature(service, key) {
		t.Fatal("service credential signature should verify with same payload and token key")
	}
	tamperedService := service
	tamperedService.ResponseHash = digest("tampered-service")
	if VerifyCredentialServiceSignature(tamperedService, key) {
		t.Fatal("service credential signature verified after payload tamper")
	}

	routerKey := TokenProofKey("router-token")
	edge := testEdgeRequestReceipt()
	edge.RouterSignature = CredentialEdgeSignature(edge, routerKey)
	if !VerifyCredentialEdgeSignature(edge, routerKey) {
		t.Fatal("edge credential signature should verify with same payload and token key")
	}
	tamperedEdge := edge
	tamperedEdge.ResponseHash = digest("tampered-edge")
	if VerifyCredentialEdgeSignature(tamperedEdge, routerKey) {
		t.Fatal("edge credential signature verified after payload tamper")
	}
}

func TestCredentialReceiptSignaturesRejectEmptyTokenProofKey(t *testing.T) {
	proof := testProofReceipt()
	if got := CredentialProofSignature(proof, ""); got != "" {
		t.Fatalf("CredentialProofSignature(empty key) = %q, want empty", got)
	}
	proof.AgentSignature = CredentialProofSignature(proof, TokenProofKey("agent-token"))
	if VerifyCredentialProofSignature(proof, "") {
		t.Fatal("proof credential signature verified with empty token proof key")
	}

	service := testServiceReceipt()
	if got := CredentialServiceSignature(service, ""); got != "" {
		t.Fatalf("CredentialServiceSignature(empty key) = %q, want empty", got)
	}
	service.AgentSignature = CredentialServiceSignature(service, TokenProofKey("agent-token"))
	if VerifyCredentialServiceSignature(service, "") {
		t.Fatal("service credential signature verified with empty token proof key")
	}

	edge := testEdgeRequestReceipt()
	if got := CredentialEdgeSignature(edge, ""); got != "" {
		t.Fatalf("CredentialEdgeSignature(empty key) = %q, want empty", got)
	}
	edge.RouterSignature = CredentialEdgeSignature(edge, TokenProofKey("router-token"))
	if VerifyCredentialEdgeSignature(edge, "") {
		t.Fatal("edge credential signature verified with empty token proof key")
	}
}

func TestSoftwareReceiptSignaturesDoNotSatisfyCredentialVerification(t *testing.T) {
	proof := testProofReceipt()
	proof.AgentSignature = SoftwareAgentProofSignature(proof)
	if !strings.HasPrefix(proof.AgentSignature, SoftwareAgentSignaturePrefix) {
		t.Fatalf("proof signature = %q, want software-agent prefix", proof.AgentSignature)
	}
	if VerifyCredentialProofSignature(proof, TokenProofKey("agent-token")) {
		t.Fatal("software proof signature must not satisfy credential verification")
	}

	service := testServiceReceipt()
	service.AgentSignature = SoftwareAgentServiceSignature(service)
	if !strings.HasPrefix(service.AgentSignature, SoftwareAgentSignaturePrefix) {
		t.Fatalf("service signature = %q, want software-agent prefix", service.AgentSignature)
	}
	if VerifyCredentialServiceSignature(service, TokenProofKey("agent-token")) {
		t.Fatal("software service signature must not satisfy credential verification")
	}

	edge := testEdgeRequestReceipt()
	edge.RouterSignature = SoftwareRouterEdgeSignature(edge)
	if !strings.HasPrefix(edge.RouterSignature, SoftwareRouterSignaturePrefix) {
		t.Fatalf("edge signature = %q, want software-router prefix", edge.RouterSignature)
	}
	if VerifyCredentialEdgeSignature(edge, TokenProofKey("router-token")) {
		t.Fatal("software edge signature must not satisfy credential verification")
	}
}

func TestVerifyServiceReceiptRequiresDigestAndSignaturePolicy(t *testing.T) {
	receipt := testServiceReceipt()
	receipt.AgentSignature = SoftwareAgentServiceSignature(receipt)
	if _, err := VerifyServiceReceipt(receipt, ReceiptVerificationOptions{}); err == nil || !strings.Contains(err.Error(), "agent_signature") {
		t.Fatalf("VerifyServiceReceipt() error = %v, want software fallback opt-in rejection", err)
	}
	if _, err := VerifyServiceReceipt(receipt, ReceiptVerificationOptions{AllowSoftwareFallback: true}); err != nil {
		t.Fatalf("VerifyServiceReceipt() error = %v", err)
	}

	badDigest := receipt
	badDigest.ResponseHash = "sha256:not-hex"
	if _, err := VerifyServiceReceipt(badDigest, ReceiptVerificationOptions{}); err == nil || !strings.Contains(err.Error(), "response_hash") {
		t.Fatalf("VerifyServiceReceipt() error = %v, want response_hash", err)
	}

	credential := testServiceReceipt()
	key := TokenProofKey("agent-token")
	credential.AgentSignature = CredentialServiceSignature(credential, key)
	if _, err := VerifyServiceReceipt(credential, ReceiptVerificationOptions{}); err == nil || !strings.Contains(err.Error(), "agent_signature") {
		t.Fatalf("VerifyServiceReceipt() error = %v, want credential verification gate", err)
	}
	if _, err := VerifyServiceReceipt(credential, ReceiptVerificationOptions{CredentialTokenProofKey: key}); err != nil {
		t.Fatalf("VerifyServiceReceipt() credential verified error = %v", err)
	}

	malformed := credential
	malformed.AgentSignature = CredentialProofSignaturePrefix + "not-hex"
	if _, err := VerifyServiceReceipt(malformed, ReceiptVerificationOptions{CredentialTokenProofKey: key}); err == nil || !strings.Contains(err.Error(), "agent_signature") {
		t.Fatalf("VerifyServiceReceipt() error = %v, want malformed credential signature rejection", err)
	}

	nested := receipt
	nested.SLOEvidence.DeadlineMS = -1
	nested.AgentSignature = SoftwareAgentServiceSignature(nested)
	if _, err := VerifyServiceReceipt(nested, ReceiptVerificationOptions{AllowSoftwareFallback: true}); err == nil || !strings.Contains(err.Error(), "deadline_ms") {
		t.Fatalf("VerifyServiceReceipt() error = %v, want nested slo validation", err)
	}

	nested = receipt
	nested.StatusEvidence.CommandHash = "not-a-digest"
	nested.AgentSignature = SoftwareAgentServiceSignature(nested)
	if _, err := VerifyServiceReceipt(nested, ReceiptVerificationOptions{AllowSoftwareFallback: true}); err == nil || !strings.Contains(err.Error(), "command_hash") {
		t.Fatalf("VerifyServiceReceipt() error = %v, want nested status evidence validation", err)
	}

	nested = receipt
	nested.ResourceLimits.CPUPercent = -1
	nested.AgentSignature = SoftwareAgentServiceSignature(nested)
	if _, err := VerifyServiceReceipt(nested, ReceiptVerificationOptions{AllowSoftwareFallback: true}); err == nil || !strings.Contains(err.Error(), "cpu_percent") {
		t.Fatalf("VerifyServiceReceipt() error = %v, want nested resource limit validation", err)
	}
}

func TestVerifyEdgeRequestReceiptRequiresDigestAndSignaturePolicy(t *testing.T) {
	receipt := testEdgeRequestReceipt()
	receipt.RouterSignature = SoftwareRouterEdgeSignature(receipt)
	if _, err := VerifyEdgeRequestReceipt(receipt, ReceiptVerificationOptions{}); err == nil || !strings.Contains(err.Error(), "router_signature") {
		t.Fatalf("VerifyEdgeRequestReceipt() error = %v, want software fallback opt-in rejection", err)
	}
	if _, err := VerifyEdgeRequestReceipt(receipt, ReceiptVerificationOptions{AllowSoftwareFallback: true}); err != nil {
		t.Fatalf("VerifyEdgeRequestReceipt() error = %v", err)
	}

	badDigest := receipt
	badDigest.RequestHash = "sha256:not-hex"
	if _, err := VerifyEdgeRequestReceipt(badDigest, ReceiptVerificationOptions{}); err == nil || !strings.Contains(err.Error(), "request_hash") {
		t.Fatalf("VerifyEdgeRequestReceipt() error = %v, want request_hash", err)
	}

	credential := testEdgeRequestReceipt()
	key := TokenProofKey("router-token")
	credential.RouterSignature = CredentialEdgeSignature(credential, key)
	if _, err := VerifyEdgeRequestReceipt(credential, ReceiptVerificationOptions{}); err == nil || !strings.Contains(err.Error(), "router_signature") {
		t.Fatalf("VerifyEdgeRequestReceipt() error = %v, want credential verification gate", err)
	}
	if _, err := VerifyEdgeRequestReceipt(credential, ReceiptVerificationOptions{CredentialTokenProofKey: key}); err != nil {
		t.Fatalf("VerifyEdgeRequestReceipt() credential verified error = %v", err)
	}

	malformed := credential
	malformed.RouterSignature = CredentialProofSignaturePrefix + "not-hex"
	if _, err := VerifyEdgeRequestReceipt(malformed, ReceiptVerificationOptions{CredentialTokenProofKey: key}); err == nil || !strings.Contains(err.Error(), "router_signature") {
		t.Fatalf("VerifyEdgeRequestReceipt() error = %v, want malformed credential signature rejection", err)
	}
}

func TestEdgeRequestReceiptBindsContentRefByRouteClass(t *testing.T) {
	content := testEdgeRequestReceipt()
	content.RouteTarget = "content-route:route-1"
	content.ServiceLeaseID = ""
	content.IngressEvidenceID = ""
	content.IngressEvidenceHash = ""
	content.ContentRef = digest("content")
	content.RouterSignature = SoftwareRouterEdgeSignature(content)
	if _, err := VerifyEdgeRequestReceipt(content, ReceiptVerificationOptions{AllowSoftwareFallback: true}); err != nil {
		t.Fatalf("VerifyEdgeRequestReceipt(content) error = %v", err)
	}

	missingContent := content
	missingContent.ContentRef = ""
	missingContent.RouterSignature = SoftwareRouterEdgeSignature(missingContent)
	if _, err := VerifyEdgeRequestReceipt(missingContent, ReceiptVerificationOptions{AllowSoftwareFallback: true}); err == nil || !strings.Contains(err.Error(), "content_ref") {
		t.Fatalf("VerifyEdgeRequestReceipt() error = %v, want content_ref required", err)
	}

	service := testEdgeRequestReceipt()
	service.ContentRef = digest("content")
	service.RouterSignature = SoftwareRouterEdgeSignature(service)
	if _, err := VerifyEdgeRequestReceipt(service, ReceiptVerificationOptions{AllowSoftwareFallback: true}); err == nil || !strings.Contains(err.Error(), "content_ref") {
		t.Fatalf("VerifyEdgeRequestReceipt() error = %v, want service route content_ref rejection", err)
	}

	padded := content
	padded.ContentRef = " " + digest("content") + " "
	padded.RouterSignature = SoftwareRouterEdgeSignature(padded)
	if _, err := VerifyEdgeRequestReceipt(padded, ReceiptVerificationOptions{AllowSoftwareFallback: true}); err == nil || !strings.Contains(err.Error(), "whitespace") {
		t.Fatalf("VerifyEdgeRequestReceipt() error = %v, want padded content_ref rejection", err)
	}
}

func TestProofReceiptValidateRequiresDigestFields(t *testing.T) {
	receipt := testProofReceipt()
	receipt.AgentSignature = SoftwareAgentProofSignature(receipt)
	receipt.Verifier = VerifierResult{Provider: "signed_receipt", Status: VerificationAccepted}
	if err := receipt.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	receipt.ArtifactHash = "sha256:not-hex"
	if err := receipt.Validate(); err == nil || !strings.Contains(err.Error(), "artifact_hash") {
		t.Fatalf("Validate() error = %v, want artifact_hash digest rejection", err)
	}
}

func TestReceiptPayloadIdentifiersRejectInvalidShapes(t *testing.T) {
	proof := testProofReceipt()
	proof.AgentSignature = SoftwareAgentProofSignature(proof)
	proof.Verifier = VerifierResult{Provider: "signed_receipt", Status: VerificationAccepted}
	proof.ID = "bad/id"
	if err := proof.Validate(); err == nil || !strings.Contains(err.Error(), "id") {
		t.Fatalf("ProofReceipt.Validate() error = %v, want id rejection", err)
	}

	service := testServiceReceipt()
	service.AgentSignature = SoftwareAgentServiceSignature(service)
	service.TraceID = "trace/1"
	if err := service.Validate(); err == nil || !strings.Contains(err.Error(), "trace_id") {
		t.Fatalf("ServiceReceipt.Validate() error = %v, want trace_id rejection", err)
	}
}

func testProofReceipt() ProofReceipt {
	return ProofReceipt{
		ID:                    "proof-1",
		OrgID:                 "org-1",
		TaskID:                "task-1",
		TaskHash:              digest("task"),
		InputHash:             digest("input"),
		DependencyClosureHash: digest("deps"),
		Executor:              testExecutorRef(),
		WorkerID:              "worker-1",
		PoolID:                "pool-1",
		PolicyID:              "policy-1",
		StartedAt:             time.Unix(100, 0).UTC(),
		FinishedAt:            time.Unix(101, 0).UTC(),
		ResourceUsage:         ResourceUsage{CPUMillis: 1000, MaxMemoryBytes: 4096},
		ArtifactHash:          digest("artifact"),
	}
}

func testServiceReceipt() ServiceReceipt {
	return ServiceReceipt{
		ID:             "svc-rec-1",
		OrgID:          "org-1",
		TaskID:         "task-1",
		ServiceLeaseID: "lease-1",
		WorkerID:       "worker-1",
		PoolID:         "pool-1",
		PolicyID:       "policy-1",
		Executor:       testExecutorRef(),
		DeploymentHash: digest("deployment"),
		RequestID:      "req-1",
		TraceID:        "trace-1",
		RequestHash:    digest("request"),
		ResponseHash:   digest("response"),
		StartedAt:      time.Unix(100, 0).UTC(),
		FinishedAt:     time.Unix(101, 0).UTC(),
		ResourceUsage:  ResourceUsage{CPUMillis: 1000, MaxMemoryBytes: 4096},
		SLOEvidence:    SLOEvidence{LatencyMillis: 1, StatusCode: 200, Healthy: true},
		Verifier:       VerifierResult{Provider: "signed_receipt", Status: VerificationAccepted},
	}
}

func testEdgeRequestReceipt() EdgeRequestReceipt {
	return EdgeRequestReceipt{
		ID:                  "edge-rec-1",
		OrgID:               "org-1",
		PoolID:              "pool-1",
		ProductID:           "product-1",
		Hostname:            "edge.example.invalid",
		RouteTarget:         "service-route:lease-1",
		ServiceLeaseID:      "lease-1",
		TaskID:              "task-1",
		WorkerID:            "worker-1",
		RequestID:           "req-1",
		TraceID:             "trace-1",
		Method:              "GET",
		RequestClass:        "edge-service",
		RequestHash:         digest("request"),
		ResponseHash:        digest("response"),
		StartedAt:           time.Unix(100, 0).UTC(),
		FinishedAt:          time.Unix(101, 0).UTC(),
		ResourceUsage:       ResourceUsage{NetworkRxBytes: 128, NetworkTxBytes: 2048},
		IngressEvidenceID:   "evidence-1",
		IngressEvidenceHash: digest("evidence"),
		Verifier:            VerifierResult{Provider: "signed_receipt", Status: VerificationAccepted},
	}
}

func testExecutorRef() ExecutorRef {
	return ExecutorRef{
		Provider:              "sandboxed-command",
		Version:               "dev",
		ExecutionSecurityTier: ExecutionTrustedNative,
		ProofTier:             ProofArtifactHash,
	}
}

func digest(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return "sha256:" + hex.EncodeToString(sum[:])
}
