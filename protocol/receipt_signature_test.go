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
	credential.AgentSignature = CredentialServiceSignature(credential, TokenProofKey("agent-token"))
	if _, err := VerifyServiceReceipt(credential, ReceiptVerificationOptions{}); err == nil || !strings.Contains(err.Error(), "agent_signature") {
		t.Fatalf("VerifyServiceReceipt() error = %v, want credential verification gate", err)
	}
	if _, err := VerifyServiceReceipt(credential, ReceiptVerificationOptions{CredentialSignatureVerified: true}); err != nil {
		t.Fatalf("VerifyServiceReceipt() credential verified error = %v", err)
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
	credential.RouterSignature = CredentialEdgeSignature(credential, TokenProofKey("router-token"))
	if _, err := VerifyEdgeRequestReceipt(credential, ReceiptVerificationOptions{}); err == nil || !strings.Contains(err.Error(), "router_signature") {
		t.Fatalf("VerifyEdgeRequestReceipt() error = %v, want credential verification gate", err)
	}
	if _, err := VerifyEdgeRequestReceipt(credential, ReceiptVerificationOptions{CredentialSignatureVerified: true}); err != nil {
		t.Fatalf("VerifyEdgeRequestReceipt() credential verified error = %v", err)
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
