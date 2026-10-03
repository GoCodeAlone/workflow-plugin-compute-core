package protocol_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/GoCodeAlone/workflow-plugin-compute-core/protocol"
)

var updateRecoveryVectors = flag.Bool("update-recovery-vectors", false, "regenerate public recovery contract fixtures")

type recoveryVector[T any] struct {
	Message       T      `json:"message"`
	SigningBase64 string `json:"signing_base64"`
	SigningDigest string `json:"signing_digest"`
}

type recoveryRejection[T any] struct {
	Name    string `json:"name"`
	Message T      `json:"message"`
}

type recoveryContractVectors struct {
	ValidationTime    time.Time                                                     `json:"validation_time"`
	PublicKey         string                                                        `json:"public_key"`
	WrongPublicKey    string                                                        `json:"wrong_public_key"`
	Manifest          recoveryVector[protocol.ComputeBootstrapManifest]             `json:"manifest"`
	ManifestSignature protocol.SignatureEnvelope                                    `json:"manifest_signature"`
	Receipt           recoveryVector[protocol.AgentSetupInstallReceipt]             `json:"receipt"`
	ReceiptBinding    protocol.AgentSetupInstallReceiptBinding                      `json:"receipt_binding"`
	Artifact          recoveryVector[protocol.ManagedLifecycleArtifactRef]          `json:"artifact"`
	Request           recoveryVector[protocol.ManagedProviderLifecycleRequest]      `json:"request"`
	Result            recoveryVector[protocol.ManagedProviderLifecycleResult]       `json:"result"`
	Preflight         protocol.DedicatedProviderHostPreflightResult                 `json:"preflight"`
	ReceiptRejections []recoveryRejection[protocol.AgentSetupInstallReceipt]        `json:"receipt_rejections"`
	ChangedRequests   []recoveryRejection[protocol.ManagedProviderLifecycleRequest] `json:"changed_requests_for_result"`
}

func makeRecoveryVector[T any](message T, signing []byte) recoveryVector[T] {
	sum := sha256.Sum256(signing)
	return recoveryVector[T]{Message: message, SigningBase64: base64.StdEncoding.EncodeToString(signing), SigningDigest: "sha256:" + hex.EncodeToString(sum[:])}
}

func exportedRecoveryVectors(t *testing.T) recoveryContractVectors {
	t.Helper()
	key := recoveryKey()
	m := bootstrapFixture()
	mBytes, err := m.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	mSignature, err := m.Sign(key)
	if err != nil {
		t.Fatal(err)
	}
	receipt := installReceiptFixture()
	if err := receipt.Sign(key); err != nil {
		t.Fatal(err)
	}
	rBytes, err := receipt.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	request := lifecycleFixture(t)
	if err := request.Sign(key); err != nil {
		t.Fatal(err)
	}
	qBytes, err := request.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	qHash, err := request.BindingHash()
	if err != nil {
		t.Fatal(err)
	}
	result := protocol.ManagedProviderLifecycleResult{
		ProtocolVersion: protocol.Version, TransactionID: request.TransactionID, WorkerID: request.WorkerID,
		PluginID: request.PluginID, Component: request.Component, Version: request.Version, Digest: request.Digest,
		Action: request.Action, RequestHash: qHash, IdempotencyState: "prepared", ServiceHash: recoveryDigest(), StateHash: recoveryDigest(),
		Status: protocol.ManagedLifecycleSucceeded, RollbackResult: protocol.ManagedLifecycleRollbackNotRequired,
		CompletedAt: recoveryNow, ExpiresAt: request.ExpiresAt,
	}
	if err := result.Sign(key); err != nil {
		t.Fatal(err)
	}
	sBytes, err := result.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	aBytes, err := request.ConfigRef.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	vectors := recoveryContractVectors{
		ValidationTime: recoveryNow, PublicKey: base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)),
		WrongPublicKey: base64.StdEncoding.EncodeToString(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, ed25519.SeedSize)).Public().(ed25519.PublicKey)),
		Manifest:       makeRecoveryVector(m, mBytes), ManifestSignature: mSignature,
		Receipt: makeRecoveryVector(receipt, rBytes), ReceiptBinding: receipt.Binding(),
		Artifact: makeRecoveryVector(request.ConfigRef, aBytes), Request: makeRecoveryVector(request, qBytes),
		Result: makeRecoveryVector(result, sBytes), Preflight: preflightFixture(),
	}
	for _, mutation := range []struct {
		name  string
		apply func(*protocol.AgentSetupInstallReceipt)
	}{
		{"substituted-manifest", func(r *protocol.AgentSetupInstallReceipt) { r.ManifestDigest = "sha256:" + strings.Repeat("b", 64) }},
		{"replayed-session", func(r *protocol.AgentSetupInstallReceipt) { r.InstallSessionID = "other-session" }},
		{"cross-worker", func(r *protocol.AgentSetupInstallReceipt) { r.WorkerID = "other-worker" }},
		{"changed-challenge", func(r *protocol.AgentSetupInstallReceipt) {
			r.Challenge = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{10}, 32))
		}},
		{"expired", func(r *protocol.AgentSetupInstallReceipt) {
			r.ExpiresAt = recoveryNow
			r.CompletedAt = recoveryNow.Add(-time.Second)
		}},
	} {
		changed := receipt
		mutation.apply(&changed)
		if err := changed.Sign(key); err != nil {
			t.Fatal(err)
		}
		vectors.ReceiptRejections = append(vectors.ReceiptRejections, recoveryRejection[protocol.AgentSetupInstallReceipt]{Name: mutation.name, Message: changed})
	}
	for _, mutation := range []struct {
		name  string
		apply func(*protocol.ManagedProviderLifecycleRequest)
	}{
		{"prior-state", func(r *protocol.ManagedProviderLifecycleRequest) {
			r.PriorStateHash = "sha256:" + strings.Repeat("b", 64)
		}},
		{"config-content", func(r *protocol.ManagedProviderLifecycleRequest) {
			r.ConfigRef.Digest = "sha256:" + strings.Repeat("b", 64)
			r.ConfigHash = r.ConfigRef.Digest
		}},
		{"artifact-location", func(r *protocol.ManagedProviderLifecycleRequest) { r.ConfigRef.Ref = "/api/artifacts/config-2" }},
	} {
		changed := request
		mutation.apply(&changed)
		if err := changed.ConfigRef.Sign(key); err != nil {
			t.Fatal(err)
		}
		if err := changed.Sign(key); err != nil {
			t.Fatal(err)
		}
		vectors.ChangedRequests = append(vectors.ChangedRequests, recoveryRejection[protocol.ManagedProviderLifecycleRequest]{Name: mutation.name, Message: changed})
	}
	return vectors
}

func TestRecoveryContractVectors_SharedConsumerBytes(t *testing.T) {
	const path = "testdata/recovery_contract_vectors.json"
	want := exportedRecoveryVectors(t)
	wantJSON, err := json.MarshalIndent(want, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	wantJSON = append(wantJSON, '\n')
	if *updateRecoveryVectors {
		if err := os.MkdirAll("testdata", 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, wantJSON, 0644); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, wantJSON) {
		t.Fatal("shared contract vector bytes/digests changed")
	}
	var consumer recoveryContractVectors
	if err := protocol.DecodeStrict(bytes.NewReader(data), &consumer); err != nil {
		t.Fatal(err)
	}
	public, err := base64.StdEncoding.DecodeString(consumer.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, err := range []error{
		consumer.Manifest.Message.Verify(consumer.ManifestSignature, public, consumer.ValidationTime),
		consumer.Receipt.Message.Verify(public, consumer.ReceiptBinding, consumer.ValidationTime),
		consumer.Artifact.Message.Verify(public, consumer.ValidationTime),
		consumer.Request.Message.Verify(public, consumer.ValidationTime),
		consumer.Result.Message.Verify(public, consumer.Request.Message, consumer.ValidationTime),
		consumer.Preflight.Validate(),
	} {
		if err != nil {
			t.Fatal(err)
		}
	}
	protoBytes, err := base64.StdEncoding.DecodeString(consumer.Receipt.SigningBase64)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := protocol.UnmarshalAgentSetupInstallReceiptPayloadStrict(protoBytes); err != nil {
		t.Fatal(err)
	}
	wrongPublic, err := base64.StdEncoding.DecodeString(consumer.WrongPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := consumer.Receipt.Message.Verify(wrongPublic, consumer.ReceiptBinding, consumer.ValidationTime); err == nil {
		t.Fatal("shared wrong-key vector accepted")
	}
	for _, vector := range consumer.ReceiptRejections {
		if err := vector.Message.Verify(public, consumer.ReceiptBinding, consumer.ValidationTime); err == nil {
			t.Fatalf("shared receipt rejection accepted: %s", vector.Name)
		}
	}
	for _, vector := range consumer.ChangedRequests {
		if err := vector.Message.Verify(public, consumer.ValidationTime); err != nil {
			t.Fatalf("changed request should have a valid signature: %s: %v", vector.Name, err)
		}
		if err := consumer.Result.Message.Verify(public, vector.Message, consumer.ValidationTime); err == nil {
			t.Fatalf("shared changed-request result replay accepted: %s", vector.Name)
		}
	}
}
