package protocol_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GoCodeAlone/workflow-plugin-compute-core/protocol"
)

func packageArtifactFixture() protocol.PackageArtifactSignaturePayload {
	return protocol.PackageArtifactSignaturePayload{
		Component: "agent-core", Version: "v1.0.0",
		URL:    "/v1/agent-artifacts/agent-core/agent-linux-amd64.tar.gz",
		SHA256: "sha256:" + strings.Repeat("a", 64),
	}
}

// This is the existing workflow-compute reusable tuple, independent of the
// public payload implementation. It deliberately has no directive ID.
func existingPackageTuple(p protocol.PackageArtifactSignaturePayload) any {
	return struct {
		Component string `json:"component"`
		PluginID  string `json:"plugin_id,omitempty"`
		Version   string `json:"version"`
		URL       string `json:"url"`
		SHA256    string `json:"sha256"`
	}{p.Component, p.PluginID, p.Version, p.URL, p.SHA256}
}

func existingPackageSignature(p protocol.PackageArtifactSignaturePayload) protocol.SignatureEnvelope {
	return protocol.SignatureEnvelope{
		Algorithm: "ed25519", KeyID: "artifact-key",
		Value: base64.StdEncoding.EncodeToString(ed25519.Sign(recoveryKey(), []byte(protocol.CanonicalHash(existingPackageTuple(p))))),
	}
}

func TestPackageArtifact_ExistingTupleBytesAndKeySemantics(t *testing.T) {
	public := recoveryKey().Public().(ed25519.PublicKey)
	for _, p := range []protocol.PackageArtifactSignaturePayload{
		packageArtifactFixture(),
		{Component: "provider", PluginID: "workflow-plugin-example", Version: "v1.2.3", URL: "https://packages.example.test/immutable/a%2Fb?platform=linux&arch=amd64", SHA256: recoveryDigest()},
	} {
		got, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		want, err := json.Marshal(existingPackageTuple(p))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) || string(p.SigningBytes()) != protocol.CanonicalHash(existingPackageTuple(p)) {
			t.Error("existing tuple JSON/hash bytes changed")
		}
		sig := existingPackageSignature(p)
		for _, keyID := range []string{"artifact-key", protocol.Ed25519KeyID(public), ""} {
			sig.KeyID = keyID
			if err := p.Verify(sig, map[string]ed25519.PublicKey{keyID: public}); err != nil {
				t.Fatalf("explicitly trusted wire key rejected: %v", err)
			}
		}
		// StdEncoding.DecodeString historically accepts line breaks; do not
		// silently replace it with the bootstrap canonical-base64 policy.
		sig = existingPackageSignature(p)
		sig.Value = sig.Value[:40] + "\n" + sig.Value[40:]
		if err := p.Verify(sig, map[string]ed25519.PublicKey{"artifact-key": public}); err != nil {
			t.Fatalf("existing signature encoding rejected: %v", err)
		}
	}
}

func TestPackageArtifact_RejectsAlteredTuple(t *testing.T) {
	p := packageArtifactFixture()
	sig := existingPackageSignature(p)
	keys := map[string]ed25519.PublicKey{"artifact-key": recoveryKey().Public().(ed25519.PublicKey)}
	for _, mutation := range []struct {
		name  string
		apply func(*protocol.PackageArtifactSignaturePayload)
	}{
		{"component", func(p *protocol.PackageArtifactSignaturePayload) { p.Component = "provider" }},
		{"plugin", func(p *protocol.PackageArtifactSignaturePayload) { p.PluginID = "workflow-plugin-other" }},
		{"version", func(p *protocol.PackageArtifactSignaturePayload) { p.Version = "v1.0.1" }},
		{"url", func(p *protocol.PackageArtifactSignaturePayload) { p.URL += "?different" }},
		{"sha256", func(p *protocol.PackageArtifactSignaturePayload) { p.SHA256 = "sha256:" + strings.Repeat("b", 64) }},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			changed := p
			mutation.apply(&changed)
			if err := changed.Verify(sig, keys); err == nil {
				t.Fatal("altered tuple accepted")
			}
		})
	}
}

func TestPackageArtifact_RejectsInvalidSignatureAndTrust(t *testing.T) {
	p := packageArtifactFixture()
	public := recoveryKey().Public().(ed25519.PublicKey)
	wrong := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	const marker = "known-private-package-value"
	for _, tc := range []struct {
		name   string
		mutate func(*protocol.SignatureEnvelope, map[string]ed25519.PublicKey)
	}{
		{"algorithm", func(s *protocol.SignatureEnvelope, _ map[string]ed25519.PublicKey) { s.Algorithm = marker }},
		{"unknown-key", func(s *protocol.SignatureEnvelope, _ map[string]ed25519.PublicKey) { s.KeyID = marker }},
		{"removed-key", func(_ *protocol.SignatureEnvelope, keys map[string]ed25519.PublicKey) { delete(keys, "artifact-key") }},
		{"wrong-key", func(_ *protocol.SignatureEnvelope, keys map[string]ed25519.PublicKey) { keys["artifact-key"] = wrong }},
		{"nil-key", func(_ *protocol.SignatureEnvelope, keys map[string]ed25519.PublicKey) { keys["artifact-key"] = nil }},
		{"short-key", func(_ *protocol.SignatureEnvelope, keys map[string]ed25519.PublicKey) {
			keys["artifact-key"] = public[:31]
		}},
		{"long-key", func(_ *protocol.SignatureEnvelope, keys map[string]ed25519.PublicKey) {
			keys["artifact-key"] = append(bytes.Clone(public), 0)
		}},
		{"malformed-base64", func(s *protocol.SignatureEnvelope, _ map[string]ed25519.PublicKey) { s.Value = marker }},
		{"empty-signature", func(s *protocol.SignatureEnvelope, _ map[string]ed25519.PublicKey) { s.Value = "" }},
		{"short-signature", func(s *protocol.SignatureEnvelope, _ map[string]ed25519.PublicKey) {
			s.Value = base64.StdEncoding.EncodeToString(make([]byte, 63))
		}},
		{"long-signature", func(s *protocol.SignatureEnvelope, _ map[string]ed25519.PublicKey) {
			s.Value = base64.StdEncoding.EncodeToString(make([]byte, 65))
		}},
		{"tampered-signature", func(s *protocol.SignatureEnvelope, _ map[string]ed25519.PublicKey) {
			s.Value = base64.StdEncoding.EncodeToString(make([]byte, 64))
		}},
		{"verified-is-not-proof", func(s *protocol.SignatureEnvelope, _ map[string]ed25519.PublicKey) { s.Verified = true; s.Value = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sig := existingPackageSignature(p)
			keys := map[string]ed25519.PublicKey{"artifact-key": public}
			tc.mutate(&sig, keys)
			if err := p.Verify(sig, keys); err == nil || strings.Contains(err.Error(), marker) {
				t.Fatalf("invalid signature accepted or diagnostic disclosed source: %v", err)
			}
		})
	}
	if err := p.Verify(existingPackageSignature(p), nil); err == nil {
		t.Fatal("absent trust accepted")
	}
}

func TestPackageArtifact_RejectsOtherSigningDomains(t *testing.T) {
	p := packageArtifactFixture()
	public := recoveryKey().Public().(ed25519.PublicKey)
	raw, err := json.Marshal(existingPackageTuple(p))
	if err != nil {
		t.Fatal(err)
	}
	bootstrap := bootstrapFixture()
	bootstrapBytes, err := bootstrap.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	legacy := struct {
		DirectiveID string `json:"directive_id"`
		Component   string `json:"component"`
		PluginID    string `json:"plugin_id,omitempty"`
		Version     string `json:"version"`
		URL         string `json:"url"`
		SHA256      string `json:"sha256"`
	}{"directive-1", p.Component, p.PluginID, p.Version, p.URL, p.SHA256}
	for name, data := range map[string][]byte{
		"raw-tuple-json": raw, "raw-bootstrap-json": bootstrapBytes,
		"legacy-directive-tuple-hash": []byte(protocol.CanonicalHash(legacy)),
	} {
		t.Run(name, func(t *testing.T) {
			sig := protocol.SignatureEnvelope{Algorithm: "ed25519", KeyID: "artifact-key", Value: base64.StdEncoding.EncodeToString(ed25519.Sign(recoveryKey(), data))}
			if err := p.Verify(sig, map[string]ed25519.PublicKey{"artifact-key": public}); err == nil {
				t.Fatal("signature from another signing domain accepted")
			}
		})
	}
}

func TestPackageArtifact_PublicConsumerVectors(t *testing.T) {
	consumer := `package main
import (
 "crypto/ed25519"
 "encoding/base64"
 "encoding/json"
 "fmt"
 "os"
 "github.com/GoCodeAlone/workflow-plugin-compute-core/protocol"
)
func main() {
 var v struct {
  PublicKey string ` + "`json:\"public_key\"`" + `
  PackageArtifacts []struct {
   Payload protocol.PackageArtifactSignaturePayload ` + "`json:\"payload\"`" + `
   TupleJSON string ` + "`json:\"tuple_json\"`" + `
   SigningHash string ` + "`json:\"signing_hash\"`" + `
   Signature protocol.SignatureEnvelope ` + "`json:\"signature\"`" + `
  } ` + "`json:\"package_artifacts\"`" + `
 }
 data, err := os.ReadFile(os.Args[1]); if err != nil { panic(err) }
 if err := json.Unmarshal(data, &v); err != nil { panic(err) }
 public, err := base64.StdEncoding.DecodeString(v.PublicKey); if err != nil { panic(err) }
 if len(v.PackageArtifacts) != 2 { panic("missing external vectors") }
 for _, a := range v.PackageArtifacts {
  data, err := json.Marshal(a.Payload); if err != nil { panic(err) }
  if string(data) != a.TupleJSON || string(a.Payload.SigningBytes()) != a.SigningHash { panic("tuple mismatch") }
  keys := map[string]ed25519.PublicKey{a.Signature.KeyID: public}
  if err := a.Payload.Verify(a.Signature, keys); err != nil { panic(err) }
  a.Payload.URL += "?substituted"
  if err := a.Payload.Verify(a.Signature, keys); err == nil { panic("substitution accepted") }
 }
 fmt.Println("public package-artifact vectors: 2 accepted, 2 substitutions denied")
}
`
	name := filepath.Join(t.TempDir(), "main.go")
	if err := os.WriteFile(name, []byte(consumer), 0o600); err != nil {
		t.Fatal(err)
	}
	vectors, err := filepath.Abs("testdata/recovery_contract_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "run", name, vectors)
	data, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("actual public consumer failed: %v\n%s", err, data)
	}
	if string(data) != "public package-artifact vectors: 2 accepted, 2 substitutions denied\n" {
		t.Fatalf("unexpected public consumer result: %s", data)
	}
}
