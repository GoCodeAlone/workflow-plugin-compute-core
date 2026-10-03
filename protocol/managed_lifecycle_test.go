package protocol_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/GoCodeAlone/workflow-plugin-compute-core/protocol"
)

func lifecycleFixture(t *testing.T) protocol.ManagedProviderLifecycleRequest {
	t.Helper()
	ref := protocol.ManagedLifecycleArtifactRef{
		ProtocolVersion: protocol.Version, TransactionID: "transaction-1", WorkerID: "worker-1", PluginID: "workflow-plugin-example", Component: "provider-binary", ComponentDigest: recoveryDigest(),
		Ref: "/api/artifacts/config-1", Digest: recoveryDigest(), MaxBytes: 4096, EnvelopeKeyID: "lifecycle-key-1", ExpiresAt: recoveryNow.Add(time.Hour),
	}
	if err := ref.Sign(recoveryKey()); err != nil {
		t.Fatal(err)
	}
	return protocol.ManagedProviderLifecycleRequest{
		ProtocolVersion: protocol.Version, Action: protocol.ManagedLifecyclePrepare, RequiredCapability: protocol.ManagedProviderLifecycleCapability,
		TransactionID: ref.TransactionID, WorkerID: ref.WorkerID, PluginID: ref.PluginID, Component: ref.Component, Version: "v1.0.0", Digest: ref.ComponentDigest,
		ConfigRef: ref, ConfigHash: ref.Digest, SecretRefs: []protocol.ManagedLifecycleArtifactRef{}, PriorStateHash: recoveryDigest(), ExpiresAt: ref.ExpiresAt,
	}
}

func TestManagedProviderLifecycle_FixedActionAndExactRefs(t *testing.T) {
	if protocol.ManagedProviderLifecycleCommand != "managed-provider-lifecycle" || protocol.ManagedProviderLifecycleCapability != "managed-provider-lifecycle-v1" {
		t.Fatal("fixed lifecycle command/capability drifted")
	}
	for _, action := range []protocol.ManagedLifecycleAction{protocol.ManagedLifecyclePrepare, protocol.ManagedLifecycleActivate, protocol.ManagedLifecycleDeactivate, protocol.ManagedLifecycleRollback, protocol.ManagedLifecycleStatus} {
		r := lifecycleFixture(t)
		r.Action = action
		if err := r.ValidateAt(recoveryNow); err != nil {
			t.Fatalf("fixed action %s invalid: %v", action, err)
		}
	}
	for name, mutate := range map[string]func(*protocol.ManagedProviderLifecycleRequest){
		"action":            func(r *protocol.ManagedProviderLifecycleRequest) { r.Action = "shell" },
		"capability":        func(r *protocol.ManagedProviderLifecycleRequest) { r.RequiredCapability = "other-v1" },
		"cross worker":      func(r *protocol.ManagedProviderLifecycleRequest) { r.ConfigRef.WorkerID = "other-worker" },
		"cross transaction": func(r *protocol.ManagedProviderLifecycleRequest) { r.ConfigRef.TransactionID = "other-transaction" },
		"cross component":   func(r *protocol.ManagedProviderLifecycleRequest) { r.ConfigRef.Component = "other-component" },
		"cross plugin":      func(r *protocol.ManagedProviderLifecycleRequest) { r.ConfigRef.PluginID = "other-plugin" },
		"wrong promoted digest": func(r *protocol.ManagedProviderLifecycleRequest) {
			r.ConfigRef.ComponentDigest = "sha256:" + strings.Repeat("b", 64)
		},
		"config hash": func(r *protocol.ManagedProviderLifecycleRequest) { r.ConfigHash = "sha256:" + strings.Repeat("b", 64) },
		"absolute ref": func(r *protocol.ManagedProviderLifecycleRequest) {
			r.ConfigRef.Ref = "https://other.example.test/artifact"
		},
		"traversal ref":     func(r *protocol.ManagedProviderLifecycleRequest) { r.ConfigRef.Ref = "/api/%2e%2e/private" },
		"encoded separator": func(r *protocol.ManagedProviderLifecycleRequest) { r.ConfigRef.Ref = "/api/%5cprivate" },
		"nested escaping":   func(r *protocol.ManagedProviderLifecycleRequest) { r.ConfigRef.Ref = "/api/%252e%252e/private" },
		"unbounded ref":     func(r *protocol.ManagedProviderLifecycleRequest) { r.ConfigRef.MaxBytes = 0 },
		"expired artifact":  func(r *protocol.ManagedProviderLifecycleRequest) { r.ConfigRef.ExpiresAt = recoveryNow },
		"expired":           func(r *protocol.ManagedProviderLifecycleRequest) { r.ExpiresAt = recoveryNow },
	} {
		t.Run(name, func(t *testing.T) {
			r := lifecycleFixture(t)
			mutate(&r)
			if err := r.ValidateAt(recoveryNow); err == nil {
				t.Fatal("unsafe lifecycle request accepted")
			}
		})
	}
	r := lifecycleFixture(t)
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"binary", "argv", "path", "env", "service_name"} {
		injected := append([]byte(`{"`+field+`":"known-contract-private-value",`), data[1:]...)
		var decoded protocol.ManagedProviderLifecycleRequest
		if err := protocol.DecodeStrict(bytes.NewReader(injected), &decoded); err == nil || strings.Contains(err.Error(), "known-contract-private-value") {
			t.Fatalf("forbidden %s accepted/disclosed: %v", field, err)
		}
	}
}

func TestManagedProviderLifecycle_SignaturesResultBindingAndRetry(t *testing.T) {
	r := lifecycleFixture(t)
	key := recoveryKey()
	public := key.Public().(ed25519.PublicKey)
	if err := r.Sign(key); err != nil {
		t.Fatal(err)
	}
	if err := r.Verify(public, recoveryNow); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var consumer protocol.ManagedProviderLifecycleRequest
	if err := protocol.DecodeStrict(bytes.NewReader(data), &consumer); err != nil {
		t.Fatal(err)
	}
	if err := consumer.Verify(public, recoveryNow); err != nil {
		t.Fatal(err)
	}
	before, err := consumer.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	if err := consumer.Sign(key); err != nil {
		t.Fatal(err)
	}
	after, err := consumer.SigningBytes()
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("identical lifecycle retry changed signing bytes")
	}
	consumer.TransactionID = "replayed-transaction"
	if err := consumer.Verify(public, recoveryNow); err == nil {
		t.Fatal("changed transaction accepted")
	}
	requestHash, err := r.BindingHash()
	if err != nil {
		t.Fatal(err)
	}
	result := protocol.ManagedProviderLifecycleResult{
		ProtocolVersion: protocol.Version, TransactionID: r.TransactionID, WorkerID: r.WorkerID, PluginID: r.PluginID, Component: r.Component, Version: r.Version, Digest: r.Digest, Action: r.Action,
		RequestHash:      requestHash,
		IdempotencyState: "prepared", ServiceHash: recoveryDigest(), StateHash: recoveryDigest(), Status: protocol.ManagedLifecycleSucceeded,
		RollbackResult: protocol.ManagedLifecycleRollbackNotRequired, CompletedAt: recoveryNow, ExpiresAt: r.ExpiresAt,
	}
	if err := result.Sign(key); err != nil {
		t.Fatal(err)
	}
	if err := result.Verify(public, r, recoveryNow); err != nil {
		t.Fatal(err)
	}
	changedSignature := result
	changedSignature.Signature = r.Signature
	if err := changedSignature.Verify(public, r, recoveryNow); err == nil {
		t.Fatal("cross-domain request signature authorized a result")
	}
	other := r
	other.WorkerID = "other-worker"
	if err := result.Verify(public, other, recoveryNow); err == nil {
		t.Fatal("cross-worker result accepted")
	}
	other = r
	other.PriorStateHash = "sha256:" + strings.Repeat("b", 64)
	if err := result.Verify(public, other, recoveryNow); err == nil {
		t.Fatal("result replayed against a changed prior-state hash")
	}
	if err := r.ConfigRef.Verify(public, recoveryNow); err != nil {
		t.Fatal(err)
	}
	wrong := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	if err := r.Verify(wrong, recoveryNow); err == nil {
		t.Fatal("wrong lifecycle key accepted")
	}
	if err := r.ConfigRef.Verify(public, r.ConfigRef.ExpiresAt); err == nil {
		t.Fatal("expired artifact accepted")
	}
}

func TestManagedProviderLifecycle_CanonicalWithoutInputMutation(t *testing.T) {
	r := lifecycleFixture(t)
	secret := r.ConfigRef
	secret.Ref = "/api/artifacts/secret-1"
	secret.ExpiresAt = secret.ExpiresAt.In(time.FixedZone("fixture", 3600))
	if err := secret.Sign(recoveryKey()); err != nil {
		t.Fatal(err)
	}
	r.SecretRefs = []protocol.ManagedLifecycleArtifactRef{secret}
	data, err := r.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	if r.SecretRefs[0].ExpiresAt.Location().String() != "fixture" {
		t.Fatal("signing mutated caller-owned secret refs")
	}
	r.SecretRefs[0].ExpiresAt = r.SecretRefs[0].ExpiresAt.UTC()
	again, err := r.SigningBytes()
	if err != nil || !bytes.Equal(data, again) {
		t.Fatal("lifecycle canonical bytes depend on timezone")
	}
	r.SecretRefs = append(r.SecretRefs, r.SecretRefs[0])
	if err := r.ValidateAt(recoveryNow); err == nil {
		t.Fatal("duplicate artifact authority accepted")
	}
}

func boolRef(v bool) *bool { return &v }

func preflightFixture() protocol.DedicatedProviderHostPreflightResult {
	return protocol.DedicatedProviderHostPreflightResult{
		ProtocolVersion: protocol.DedicatedProviderHostPreflightVersion, WorkerID: "worker-1", OS: "linux", UID: 1000,
		HomeHash: recoveryDigest(), MachineIDHash: recoveryDigest(), AgentUnitDigest: recoveryDigest(), LauncherUnitDigest: recoveryDigest(), FirewallPolicyHash: recoveryDigest(),
		AgentServiceState: protocol.HostServiceActive, LauncherServiceState: protocol.HostServiceActive,
		UserBusAvailable: boolRef(true), LingeringEnabled: boolRef(true), RootlessPodman: boolRef(true), ActionsRunnerProcessPresent: boolRef(false), ActionsRunnerServicePresent: boolRef(false),
	}
}

func TestDedicatedProviderHostPreflight_AllowlistAndRunnerDenial(t *testing.T) {
	p := preflightFixture()
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"token", "files", "env", "process_output", "home"} {
		injected := append([]byte(`{"`+field+`":"known-contract-private-value",`), data[1:]...)
		var decoded protocol.DedicatedProviderHostPreflightResult
		if err := protocol.DecodeStrict(bytes.NewReader(injected), &decoded); err == nil || strings.Contains(err.Error(), "known-contract-private-value") {
			t.Fatalf("preflight %s accepted/disclosed: %v", field, err)
		}
	}
	for _, mutate := range []func(*protocol.DedicatedProviderHostPreflightResult){
		func(p *protocol.DedicatedProviderHostPreflightResult) { p.ActionsRunnerProcessPresent = boolRef(true) },
		func(p *protocol.DedicatedProviderHostPreflightResult) { p.ActionsRunnerServicePresent = boolRef(true) },
		func(p *protocol.DedicatedProviderHostPreflightResult) { p.ActionsRunnerProcessPresent = nil },
		func(p *protocol.DedicatedProviderHostPreflightResult) {
			p.AgentServiceState = "known-contract-private-value"
		},
	} {
		changed := preflightFixture()
		mutate(&changed)
		if err := changed.Validate(); err == nil || strings.Contains(err.Error(), "known-contract-private-value") {
			t.Fatalf("unsafe preflight accepted/disclosed: %v", err)
		}
	}
}
