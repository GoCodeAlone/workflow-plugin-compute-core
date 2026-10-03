package protocol_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/GoCodeAlone/workflow-plugin-compute-core/protocol"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

var recoveryNow = time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)

func recoveryKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
}

func recoveryDigest() string { return "sha256:" + strings.Repeat("a", 64) }

func bootstrapFixture() protocol.ComputeBootstrapManifest {
	public := recoveryKey().Public().(ed25519.PublicKey)
	asset := protocol.BootstrapAssetRef{URL: "https://releases.example.test/immutable/artifact", Digest: recoveryDigest()}
	return protocol.ComputeBootstrapManifest{
		ProtocolVersion: protocol.Version, SchemaVersion: protocol.ComputeBootstrapManifestSchema,
		Version: "v1.0.0", ServerOrigin: "https://compute.example.test",
		WFCTLVersion: "v0.86.0", WFCTLAssets: []protocol.BootstrapPlatformAsset{{OS: "linux", Arch: "amd64", Asset: asset}},
		PluginComputeVersion: "v1.0.0", PluginComputeArchive: asset, Bootstrap: asset,
		PackageID: "agent-core-linux-amd64", PackageVersion: "v1.0.0", PackageManifestDigest: recoveryDigest(),
		BootstrapEpoch: 1, PackageEpoch: 1, KeysetEpoch: 1, KeysetDigest: recoveryDigest(),
		PackageSigningKeys: []protocol.BootstrapSigningKey{{KeyID: protocol.Ed25519KeyID(public), PublicKey: base64.StdEncoding.EncodeToString(public)}},
		ExpiresAt:          recoveryNow.Add(time.Hour),
	}
}

func installReceiptFixture() protocol.AgentSetupInstallReceipt {
	return protocol.AgentSetupInstallReceipt{
		ProtocolVersion: protocol.Version, ReceiptID: "receipt-1", Challenge: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)),
		InviteID: "invite-1", InstallSessionID: "session-1", WorkerID: "worker-1",
		PackageID: "agent-core-linux-amd64", PackageVersion: "v1.0.0", PackageDigest: recoveryDigest(), ManifestDigest: recoveryDigest(),
		BootstrapEpoch: 1, PackageEpoch: 1, KeysetEpoch: 1,
		LauncherDigest: recoveryDigest(), SlotID: "A", SlotDigest: recoveryDigest(), ServiceUnitDigest: recoveryDigest(), ServiceMode: "systemd-user", StartedPID: 123,
		HeartbeatID: "heartbeat-1", HeartbeatAt: recoveryNow.Add(-time.Minute),
		CloudFinalUnit: "cloud-final.service", ScrubUnit: "compute-scrub.service", WrapperHash: recoveryDigest(), ScanHitCount: 0, CodeDigest: recoveryDigest(),
		CompletedAt: recoveryNow, ExpiresAt: recoveryNow.Add(time.Hour),
	}
}

func TestBootstrapManifest_StrictDecodeAndValidation(t *testing.T) {
	for name, mutate := range map[string]func(*protocol.ComputeBootstrapManifest){
		"origin path":        func(m *protocol.ComputeBootstrapManifest) { m.ServerOrigin += "/api" },
		"origin userinfo":    func(m *protocol.ComputeBootstrapManifest) { m.ServerOrigin = "https://token@compute.example.test" },
		"http asset":         func(m *protocol.ComputeBootstrapManifest) { m.Bootstrap.URL = "http://example.test/asset" },
		"asset query":        func(m *protocol.ComputeBootstrapManifest) { m.Bootstrap.URL += "?token=known-contract-private-value" },
		"digest":             func(m *protocol.ComputeBootstrapManifest) { m.PackageManifestDigest = "sha256:bad" },
		"zero epoch":         func(m *protocol.ComputeBootstrapManifest) { m.PackageEpoch = 0 },
		"wrong key ID":       func(m *protocol.ComputeBootstrapManifest) { m.PackageSigningKeys[0].KeyID = recoveryDigest() },
		"duplicate platform": func(m *protocol.ComputeBootstrapManifest) { m.WFCTLAssets = append(m.WFCTLAssets, m.WFCTLAssets[0]) },
		"expired":            func(m *protocol.ComputeBootstrapManifest) { m.ExpiresAt = recoveryNow },
	} {
		t.Run(name, func(t *testing.T) {
			m := bootstrapFixture()
			mutate(&m)
			if err := m.ValidateAt(recoveryNow); err == nil || strings.Contains(err.Error(), "known-contract-private-value") {
				t.Fatalf("unsafe manifest accepted or disclosed input: %v", err)
			}
		})
	}
	m := bootstrapFixture()
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{
		append(append([]byte(nil), data...), []byte(` {}`)...),
		bytes.Replace(data, []byte(`"version":"v1.0.0"`), []byte(`"version":"v1.0.0","unknown":true`), 1),
		bytes.Replace(data, []byte(`"arch":"amd64"`), []byte(`"arch":"amd64","env":{}`), 1),
	} {
		var decoded protocol.ComputeBootstrapManifest
		if err := protocol.DecodeStrict(bytes.NewReader(data), &decoded); err == nil {
			t.Fatal("strict manifest decode accepted unknown/trailing data")
		}
	}
	if err := m.ValidateAt(time.Time{}); err == nil {
		t.Fatal("zero validation clock accepted")
	}
}

func TestBootstrapManifest_CanonicalEd25519Bindings(t *testing.T) {
	m := bootstrapFixture()
	key := recoveryKey()
	public := key.Public().(ed25519.PublicKey)
	sig, err := m.Sign(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Verify(sig, public, recoveryNow); err != nil {
		t.Fatal(err)
	}
	data, err := m.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	var consumer protocol.ComputeBootstrapManifest
	if err := protocol.DecodeStrict(bytes.NewReader(data), &consumer); err != nil {
		t.Fatal(err)
	}
	again, err := consumer.CanonicalBytes()
	if err != nil || !bytes.Equal(data, again) {
		t.Fatalf("cross-consumer canonical bytes differ: %v", err)
	}
	consumer.ExpiresAt = consumer.ExpiresAt.In(time.FixedZone("fixture", 3600))
	again, err = consumer.CanonicalBytes()
	if err != nil || !bytes.Equal(data, again) {
		t.Fatal("canonical bytes depend on timezone")
	}
	for _, mutate := range []func(*protocol.ComputeBootstrapManifest){
		func(m *protocol.ComputeBootstrapManifest) { m.ServerOrigin = "https://other.example.test" },
		func(m *protocol.ComputeBootstrapManifest) { m.Bootstrap.Digest = "sha256:" + strings.Repeat("b", 64) },
		func(m *protocol.ComputeBootstrapManifest) { m.KeysetEpoch++ },
		func(m *protocol.ComputeBootstrapManifest) { m.PackageID = "other-package" },
	} {
		changed := bootstrapFixture()
		mutate(&changed)
		if err := changed.Verify(sig, public, recoveryNow); err == nil {
			t.Fatal("manifest signature accepted substitution")
		}
	}
	wrong := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	if err := m.Verify(sig, wrong, recoveryNow); err == nil {
		t.Fatal("wrong bootstrap root accepted")
	}
	if _, err := m.Sign(nil); err == nil {
		t.Fatal("invalid private key accepted")
	}
	sig.Value += "\n"
	if err := m.Verify(sig, public, recoveryNow); err == nil {
		t.Fatal("noncanonical signature encoding accepted")
	}
}

func TestInstallReceipt_BindingReplayAndEd25519(t *testing.T) {
	r := installReceiptFixture()
	expected := r.Binding()
	key := recoveryKey()
	public := key.Public().(ed25519.PublicKey)
	if err := r.Sign(key); err != nil {
		t.Fatal(err)
	}
	if err := r.Verify(public, expected, recoveryNow); err != nil {
		t.Fatal(err)
	}
	first, err := r.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Sign(key); err != nil {
		t.Fatal(err)
	}
	second, err := r.SigningBytes()
	if err != nil || !bytes.Equal(first, second) {
		t.Fatal("identical retry changed receipt bytes")
	}
	for name, mutate := range map[string]func(*protocol.AgentSetupInstallReceipt){
		"worker":  func(r *protocol.AgentSetupInstallReceipt) { r.WorkerID = "other-worker" },
		"session": func(r *protocol.AgentSetupInstallReceipt) { r.InstallSessionID = "other-session" },
		"invite":  func(r *protocol.AgentSetupInstallReceipt) { r.InviteID = "other-invite" },
		"challenge": func(r *protocol.AgentSetupInstallReceipt) {
			r.Challenge = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{10}, 32))
		},
		"manifest":        func(r *protocol.AgentSetupInstallReceipt) { r.ManifestDigest = "sha256:" + strings.Repeat("b", 64) },
		"package digest":  func(r *protocol.AgentSetupInstallReceipt) { r.PackageDigest = "sha256:" + strings.Repeat("b", 64) },
		"package ID":      func(r *protocol.AgentSetupInstallReceipt) { r.PackageID = "other-package" },
		"package version": func(r *protocol.AgentSetupInstallReceipt) { r.PackageVersion = "v2.0.0" },
		"receipt ID":      func(r *protocol.AgentSetupInstallReceipt) { r.ReceiptID = "other-receipt" },
		"bootstrap epoch": func(r *protocol.AgentSetupInstallReceipt) { r.BootstrapEpoch++ },
		"package epoch":   func(r *protocol.AgentSetupInstallReceipt) { r.PackageEpoch++ },
		"keyset":          func(r *protocol.AgentSetupInstallReceipt) { r.KeysetEpoch++ },
		"launcher":        func(r *protocol.AgentSetupInstallReceipt) { r.LauncherDigest = "sha256:" + strings.Repeat("b", 64) },
		"slot":            func(r *protocol.AgentSetupInstallReceipt) { r.SlotID = "B" },
		"slot digest":     func(r *protocol.AgentSetupInstallReceipt) { r.SlotDigest = "sha256:" + strings.Repeat("b", 64) },
		"service unit":    func(r *protocol.AgentSetupInstallReceipt) { r.ServiceUnitDigest = "sha256:" + strings.Repeat("b", 64) },
		"service mode":    func(r *protocol.AgentSetupInstallReceipt) { r.ServiceMode = "other-mode" },
		"started PID":     func(r *protocol.AgentSetupInstallReceipt) { r.StartedPID++ },
		"heartbeat ID":    func(r *protocol.AgentSetupInstallReceipt) { r.HeartbeatID = "other-heartbeat" },
		"heartbeat time":  func(r *protocol.AgentSetupInstallReceipt) { r.HeartbeatAt = r.HeartbeatAt.Add(-time.Second) },
		"cloud final":     func(r *protocol.AgentSetupInstallReceipt) { r.CloudFinalUnit = "other-cloud-final.service" },
		"scrub unit":      func(r *protocol.AgentSetupInstallReceipt) { r.ScrubUnit = "other-scrub.service" },
		"wrapper":         func(r *protocol.AgentSetupInstallReceipt) { r.WrapperHash = "sha256:" + strings.Repeat("b", 64) },
		"code":            func(r *protocol.AgentSetupInstallReceipt) { r.CodeDigest = "sha256:" + strings.Repeat("b", 64) },
		"completed time":  func(r *protocol.AgentSetupInstallReceipt) { r.CompletedAt = r.CompletedAt.Add(-time.Second) },
		"expiry":          func(r *protocol.AgentSetupInstallReceipt) { r.ExpiresAt = r.ExpiresAt.Add(time.Second) },
		"scrub":           func(r *protocol.AgentSetupInstallReceipt) { r.ScanHitCount = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			changed := r
			mutate(&changed)
			if err := changed.Verify(public, expected, recoveryNow); err == nil {
				t.Fatal("signed receipt accepted changed payload")
			}
			if err := changed.Verify(public, changed.Binding(), recoveryNow); err == nil {
				t.Fatal("signature omitted a receipt payload field")
			}
			if name == "worker" || name == "challenge" || name == "session" || name == "invite" || name == "manifest" || name == "keyset" {
				if err := changed.Sign(key); err != nil {
					t.Fatal(err)
				}
				if err := changed.Verify(public, expected, recoveryNow); err == nil {
					t.Fatal("valid signature accepted different stored setup binding")
				}
			}
		})
	}
	if err := r.Verify(public, expected, r.ExpiresAt); err == nil {
		t.Fatal("expired receipt accepted")
	}
	wrong := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	if err := r.Verify(wrong, expected, recoveryNow); err == nil {
		t.Fatal("wrong receipt key accepted")
	}
	r.Signature.Value = "forged"
	r.Signature.Verified = true
	if err := r.Verify(public, expected, recoveryNow); err == nil {
		t.Fatal("caller verified flag authorized forged receipt")
	}
}

func TestInstallReceipt_DeterministicProtoAndStrictJSON(t *testing.T) {
	r := installReceiptFixture()
	payload := r.SigningPayload()
	data, err := proto.MarshalOptions{Deterministic: true}.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	want, err := r.SigningBytes()
	if err != nil || !bytes.Equal(data, want) {
		t.Fatalf("receipt does not sign the separate protobuf payload: %v", err)
	}
	decoded, err := protocol.UnmarshalAgentSetupInstallReceiptPayloadStrict(data)
	if err != nil || !proto.Equal(payload, decoded) {
		t.Fatalf("strict receipt protobuf roundtrip: %v", err)
	}
	data = append(data, protowire.AppendTag(nil, 99, protowire.VarintType)...)
	data = protowire.AppendVarint(data, 1)
	if _, err := protocol.UnmarshalAgentSetupInstallReceiptPayloadStrict(data); err == nil {
		t.Fatal("unknown receipt protobuf field accepted")
	}
	payload.Domain = "managed-provider-lifecycle-request.v1"
	wrongDomain, err := proto.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := protocol.UnmarshalAgentSetupInstallReceiptPayloadStrict(wrongDomain); err == nil {
		t.Fatal("cross-domain receipt payload accepted")
	}
	jsonData, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	jsonData = bytes.Replace(jsonData, []byte(`"receipt_id":"receipt-1"`), []byte(`"receipt_id":"receipt-1","token":"known-contract-private-value"`), 1)
	var got protocol.AgentSetupInstallReceipt
	if err := protocol.DecodeStrict(bytes.NewReader(jsonData), &got); err == nil || strings.Contains(err.Error(), "known-contract-private-value") {
		t.Fatalf("unsafe receipt JSON accepted/disclosed: %v", err)
	}
}
