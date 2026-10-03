package protocol

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/GoCodeAlone/workflow-plugin-compute-core/protocol/pb"
	"google.golang.org/protobuf/proto"
)

const (
	ComputeBootstrapManifestSchema = "compute-bootstrap-manifest.v1"
	AgentSetupInstallReceiptSchema = "agent-setup-install-receipt.v1"
)

type BootstrapAssetRef struct {
	URL    string `json:"url"`
	Digest string `json:"digest"`
}

type BootstrapPlatformAsset struct {
	OS    string            `json:"os"`
	Arch  string            `json:"arch"`
	Asset BootstrapAssetRef `json:"asset"`
}

type BootstrapSigningKey struct {
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
}

// ComputeBootstrapManifest is canonical JSON signed by an independently pinned
// bootstrap root. PackageSigningKeys are package roots, never bootstrap roots.
type ComputeBootstrapManifest struct {
	ProtocolVersion       string                   `json:"protocol_version"`
	SchemaVersion         string                   `json:"schema_version"`
	Version               string                   `json:"version"`
	ServerOrigin          string                   `json:"server_origin"`
	WFCTLVersion          string                   `json:"wfctl_version"`
	WFCTLAssets           []BootstrapPlatformAsset `json:"wfctl_assets"`
	PluginComputeVersion  string                   `json:"plugin_compute_version"`
	PluginComputeArchive  BootstrapAssetRef        `json:"plugin_compute_archive"`
	Bootstrap             BootstrapAssetRef        `json:"bootstrap"`
	PackageID             string                   `json:"package_id"`
	PackageVersion        string                   `json:"package_version"`
	PackageManifestDigest string                   `json:"package_manifest_digest"`
	BootstrapEpoch        uint64                   `json:"bootstrap_epoch"`
	PackageEpoch          uint64                   `json:"package_epoch"`
	KeysetEpoch           uint64                   `json:"keyset_epoch"`
	KeysetDigest          string                   `json:"keyset_digest"`
	PackageSigningKeys    []BootstrapSigningKey    `json:"package_signing_keys"`
	ExpiresAt             time.Time                `json:"expires_at"`
}

func (m ComputeBootstrapManifest) validate() error {
	var errs []error
	errs = append(errs, recoveryProtocolError(m.ProtocolVersion))
	if m.SchemaVersion != ComputeBootstrapManifestSchema {
		errs = append(errs, errors.New("schema_version must identify the compute bootstrap manifest"))
	}
	for _, field := range []struct{ name, value string }{
		{"version", m.Version}, {"wfctl_version", m.WFCTLVersion}, {"plugin_compute_version", m.PluginComputeVersion},
		{"package_id", m.PackageID}, {"package_version", m.PackageVersion},
	} {
		errs = append(errs, validateIdentifier(field.name, field.value))
	}
	u, err := recoveryHTTPSURL(m.ServerOrigin)
	if err != nil || u.Path != "" {
		errs = append(errs, errors.New("server_origin must be an HTTPS origin without path, credentials, query, or fragment"))
	}
	if len(m.WFCTLAssets) == 0 {
		errs = append(errs, errors.New("wfctl_assets is required"))
	}
	seen := make(map[string]bool)
	for i, asset := range m.WFCTLAssets {
		prefix := fmt.Sprintf("wfctl_assets[%d]", i)
		errs = append(errs, validateIdentifier(prefix+".os", asset.OS), validateIdentifier(prefix+".arch", asset.Arch), validateBootstrapAsset(prefix+".asset", asset.Asset))
		platform := asset.OS + "/" + asset.Arch
		if seen[platform] {
			errs = append(errs, errors.New("wfctl_assets must not repeat a platform"))
		}
		seen[platform] = true
	}
	errs = append(errs, validateBootstrapAsset("plugin_compute_archive", m.PluginComputeArchive), validateBootstrapAsset("bootstrap", m.Bootstrap))
	errs = append(errs, validateRequiredSHA256Digest("package_manifest_digest", m.PackageManifestDigest)...)
	errs = append(errs, validateRequiredSHA256Digest("keyset_digest", m.KeysetDigest)...)
	if m.BootstrapEpoch == 0 || m.PackageEpoch == 0 || m.KeysetEpoch == 0 {
		errs = append(errs, errors.New("bootstrap_epoch, package_epoch, and keyset_epoch must be positive"))
	}
	if len(m.PackageSigningKeys) == 0 {
		errs = append(errs, errors.New("package_signing_keys is required"))
	}
	seenKeys := make(map[string]bool)
	for _, key := range m.PackageSigningKeys {
		public, err := base64.StdEncoding.DecodeString(key.PublicKey)
		if err != nil || len(public) != ed25519.PublicKeySize || key.KeyID != Ed25519KeyID(public) {
			errs = append(errs, errors.New("package_signing_keys must contain Ed25519 public keys with matching SHA256 key IDs"))
		}
		if seenKeys[key.KeyID] {
			errs = append(errs, errors.New("package_signing_keys must not repeat a key ID"))
		}
		seenKeys[key.KeyID] = true
	}
	if m.ExpiresAt.IsZero() {
		errs = append(errs, errors.New("expires_at is required"))
	}
	return errors.Join(errs...)
}

func (m ComputeBootstrapManifest) ValidateAt(now time.Time) error {
	return errors.Join(m.validate(), recoveryExpiryError(m.ExpiresAt, now))
}

func (m ComputeBootstrapManifest) CanonicalBytes() ([]byte, error) {
	if err := m.validate(); err != nil {
		return nil, err
	}
	m.ExpiresAt = m.ExpiresAt.UTC()
	return json.Marshal(m)
}

func (m ComputeBootstrapManifest) Sign(key ed25519.PrivateKey) (SignatureEnvelope, error) {
	data, err := m.CanonicalBytes()
	if err != nil {
		return SignatureEnvelope{}, err
	}
	return signRecoveryBytes(data, key)
}

func (m ComputeBootstrapManifest) Verify(signature SignatureEnvelope, public ed25519.PublicKey, now time.Time) error {
	if err := m.ValidateAt(now); err != nil {
		return err
	}
	data, err := m.CanonicalBytes()
	if err != nil {
		return err
	}
	return verifyRecoveryBytes(data, signature, public)
}

type AgentSetupInstallReceipt struct {
	ProtocolVersion   string            `json:"protocol_version"`
	ReceiptID         string            `json:"receipt_id"`
	Challenge         string            `json:"challenge"`
	InviteID          string            `json:"invite_id"`
	InstallSessionID  string            `json:"install_session_id"`
	WorkerID          string            `json:"worker_id"`
	PackageID         string            `json:"package_id"`
	PackageVersion    string            `json:"package_version"`
	PackageDigest     string            `json:"package_digest"`
	ManifestDigest    string            `json:"manifest_digest"`
	BootstrapEpoch    uint64            `json:"bootstrap_epoch"`
	PackageEpoch      uint64            `json:"package_epoch"`
	KeysetEpoch       uint64            `json:"keyset_epoch"`
	LauncherDigest    string            `json:"launcher_digest"`
	SlotID            string            `json:"slot_id"`
	SlotDigest        string            `json:"slot_digest"`
	ServiceUnitDigest string            `json:"service_unit_digest"`
	ServiceMode       string            `json:"service_mode"`
	StartedPID        int64             `json:"started_pid"`
	HeartbeatID       string            `json:"heartbeat_id"`
	HeartbeatAt       time.Time         `json:"heartbeat_at"`
	CloudFinalUnit    string            `json:"cloud_final_unit"`
	ScrubUnit         string            `json:"scrub_unit"`
	WrapperHash       string            `json:"wrapper_hash"`
	ScanHitCount      uint64            `json:"scan_hit_count"`
	CodeDigest        string            `json:"code_digest"`
	CompletedAt       time.Time         `json:"completed_at"`
	ExpiresAt         time.Time         `json:"expires_at"`
	Signature         SignatureEnvelope `json:"signature,omitzero"`
}

// AgentSetupInstallReceiptBinding is supplied from stored setup authority, not
// from the receipt or bearer token. Challenge consumption remains host-owned.
type AgentSetupInstallReceiptBinding struct {
	Challenge        string    `json:"challenge"`
	InviteID         string    `json:"invite_id"`
	InstallSessionID string    `json:"install_session_id"`
	WorkerID         string    `json:"worker_id"`
	PackageID        string    `json:"package_id"`
	PackageVersion   string    `json:"package_version"`
	PackageDigest    string    `json:"package_digest"`
	ManifestDigest   string    `json:"manifest_digest"`
	BootstrapEpoch   uint64    `json:"bootstrap_epoch"`
	PackageEpoch     uint64    `json:"package_epoch"`
	KeysetEpoch      uint64    `json:"keyset_epoch"`
	ExpiresAt        time.Time `json:"expires_at"`
}

func (r AgentSetupInstallReceipt) Binding() AgentSetupInstallReceiptBinding {
	return AgentSetupInstallReceiptBinding{
		Challenge: r.Challenge, InviteID: r.InviteID, InstallSessionID: r.InstallSessionID, WorkerID: r.WorkerID,
		PackageID: r.PackageID, PackageVersion: r.PackageVersion, PackageDigest: r.PackageDigest, ManifestDigest: r.ManifestDigest,
		BootstrapEpoch: r.BootstrapEpoch, PackageEpoch: r.PackageEpoch, KeysetEpoch: r.KeysetEpoch, ExpiresAt: r.ExpiresAt.UTC(),
	}
}

func (r AgentSetupInstallReceipt) validate() error {
	var errs []error
	errs = append(errs, recoveryProtocolError(r.ProtocolVersion))
	for _, field := range []struct{ name, value string }{
		{"receipt_id", r.ReceiptID}, {"invite_id", r.InviteID}, {"install_session_id", r.InstallSessionID}, {"worker_id", r.WorkerID},
		{"package_id", r.PackageID}, {"package_version", r.PackageVersion}, {"service_mode", r.ServiceMode},
		{"heartbeat_id", r.HeartbeatID}, {"cloud_final_unit", r.CloudFinalUnit}, {"scrub_unit", r.ScrubUnit},
	} {
		errs = append(errs, validateIdentifier(field.name, field.value))
	}
	challenge, err := base64.StdEncoding.DecodeString(r.Challenge)
	if err != nil || len(challenge) != 32 {
		errs = append(errs, errors.New("challenge must encode 256 bits"))
	}
	for _, field := range []struct{ name, value string }{
		{"package_digest", r.PackageDigest}, {"manifest_digest", r.ManifestDigest}, {"launcher_digest", r.LauncherDigest},
		{"slot_digest", r.SlotDigest}, {"service_unit_digest", r.ServiceUnitDigest}, {"wrapper_hash", r.WrapperHash}, {"code_digest", r.CodeDigest},
	} {
		errs = append(errs, validateRequiredSHA256Digest(field.name, field.value)...)
	}
	if r.BootstrapEpoch == 0 || r.PackageEpoch == 0 || r.KeysetEpoch == 0 {
		errs = append(errs, errors.New("bootstrap_epoch, package_epoch, and keyset_epoch must be positive"))
	}
	if r.SlotID != "A" && r.SlotID != "B" {
		errs = append(errs, errors.New("slot_id must identify A or B"))
	}
	if r.StartedPID <= 0 || r.ScanHitCount != 0 {
		errs = append(errs, errors.New("started_pid must be positive and scan_hit_count must be zero"))
	}
	for _, field := range []struct {
		name  string
		value time.Time
	}{
		{"heartbeat_at", r.HeartbeatAt}, {"completed_at", r.CompletedAt}, {"expires_at", r.ExpiresAt},
	} {
		if field.value.IsZero() || !timeFromUnixNano(unixNanoOrZero(field.value)).Equal(field.value) {
			errs = append(errs, fmt.Errorf("%s must be a nonzero nanosecond timestamp", field.name))
		}
	}
	if r.HeartbeatAt.After(r.CompletedAt) || !r.CompletedAt.Before(r.ExpiresAt) {
		errs = append(errs, errors.New("heartbeat_at must not exceed completed_at, which must precede expires_at"))
	}
	return errors.Join(errs...)
}

func (r AgentSetupInstallReceipt) ValidateAt(now time.Time) error {
	var future error
	if r.CompletedAt.After(now) {
		future = errors.New("completed_at must not be in the future")
	}
	return errors.Join(r.validate(), recoveryExpiryError(r.ExpiresAt, now), future)
}

func (r AgentSetupInstallReceipt) SigningPayload() *pb.AgentSetupInstallReceiptPayload {
	return &pb.AgentSetupInstallReceiptPayload{
		Domain: AgentSetupInstallReceiptSchema, ProtocolVersion: r.ProtocolVersion, ReceiptId: r.ReceiptID, Challenge: r.Challenge,
		InviteId: r.InviteID, InstallSessionId: r.InstallSessionID, WorkerId: r.WorkerID, PackageId: r.PackageID, PackageVersion: r.PackageVersion,
		PackageDigest: r.PackageDigest, ManifestDigest: r.ManifestDigest, BootstrapEpoch: r.BootstrapEpoch, PackageEpoch: r.PackageEpoch, KeysetEpoch: r.KeysetEpoch,
		LauncherDigest: r.LauncherDigest, SlotId: r.SlotID, SlotDigest: r.SlotDigest, ServiceUnitDigest: r.ServiceUnitDigest, ServiceMode: r.ServiceMode,
		StartedPid: r.StartedPID, HeartbeatId: r.HeartbeatID, HeartbeatAtUnixNano: unixNanoOrZero(r.HeartbeatAt), CloudFinalUnit: r.CloudFinalUnit, ScrubUnit: r.ScrubUnit,
		WrapperHash: r.WrapperHash, ScanHitCount: r.ScanHitCount, CodeDigest: r.CodeDigest, CompletedAtUnixNano: unixNanoOrZero(r.CompletedAt), ExpiresAtUnixNano: unixNanoOrZero(r.ExpiresAt),
	}
}

func (r AgentSetupInstallReceipt) SigningBytes() ([]byte, error) {
	if err := r.validate(); err != nil {
		return nil, err
	}
	return proto.MarshalOptions{Deterministic: true}.Marshal(r.SigningPayload())
}

func UnmarshalAgentSetupInstallReceiptPayloadStrict(data []byte) (*pb.AgentSetupInstallReceiptPayload, error) {
	var payload pb.AgentSetupInstallReceiptPayload
	if err := proto.Unmarshal(data, &payload); err != nil {
		return nil, err
	}
	if err := rejectUnknownProtoFields(&payload); err != nil {
		return nil, err
	}
	if payload.Domain != AgentSetupInstallReceiptSchema || payload.ProtocolVersion != Version {
		return nil, errors.New("receipt payload domain/protocol is not supported")
	}
	return &payload, nil
}

func (r *AgentSetupInstallReceipt) Sign(key ed25519.PrivateKey) error {
	data, err := r.SigningBytes()
	if err != nil {
		return err
	}
	r.Signature, err = signRecoveryBytes(data, key)
	return err
}

func (r AgentSetupInstallReceipt) Verify(public ed25519.PublicKey, expected AgentSetupInstallReceiptBinding, now time.Time) error {
	if err := r.ValidateAt(now); err != nil {
		return err
	}
	expected.ExpiresAt = expected.ExpiresAt.UTC()
	if r.Binding() != expected {
		return errors.New("install receipt does not match the stored setup binding")
	}
	data, err := r.SigningBytes()
	if err != nil {
		return err
	}
	return verifyRecoveryBytes(data, r.Signature, public)
}

func Ed25519KeyID(public ed25519.PublicKey) string {
	if len(public) != ed25519.PublicKeySize {
		return ""
	}
	sum := sha256.Sum256(public)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func signRecoveryBytes(data []byte, key ed25519.PrivateKey) (SignatureEnvelope, error) {
	if len(key) != ed25519.PrivateKeySize {
		return SignatureEnvelope{}, errors.New("Ed25519 private key has invalid size")
	}
	return SignatureEnvelope{Algorithm: "ed25519", KeyID: Ed25519KeyID(key.Public().(ed25519.PublicKey)), Value: base64.StdEncoding.EncodeToString(ed25519.Sign(key, data))}, nil
}

func verifyRecoveryBytes(data []byte, signature SignatureEnvelope, public ed25519.PublicKey) error {
	if len(public) != ed25519.PublicKeySize || signature.Algorithm != "ed25519" || signature.KeyID != Ed25519KeyID(public) {
		return errors.New("signature must use the expected Ed25519 public-key fingerprint")
	}
	decoded, err := base64.StdEncoding.DecodeString(signature.Value)
	if err != nil || len(decoded) != ed25519.SignatureSize || base64.StdEncoding.EncodeToString(decoded) != signature.Value || !ed25519.Verify(public, data, decoded) {
		return errors.New("Ed25519 signature is invalid")
	}
	return nil
}

func recoveryProtocolError(version string) error {
	if version != Version {
		return errors.New("protocol_version is not supported")
	}
	return nil
}

func recoveryExpiryError(expires, now time.Time) error {
	if now.IsZero() || expires.IsZero() || !now.Before(expires) {
		return errors.New("validation time must be nonzero and precede expires_at")
	}
	return nil
}

func recoveryHTTPSURL(value string) (*url.URL, error) {
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.TrimSpace(value) != value {
		return nil, errors.New("URL must be HTTPS without credentials, query, or fragment")
	}
	return u, nil
}

func validateBootstrapAsset(name string, asset BootstrapAssetRef) error {
	_, urlErr := recoveryHTTPSURL(asset.URL)
	if urlErr != nil {
		urlErr = fmt.Errorf("%s.url must be HTTPS without credentials, query, or fragment", name)
	}
	return errors.Join(urlErr, errors.Join(validateRequiredSHA256Digest(name+".digest", asset.Digest)...))
}

// Domain-separated JSON is used only by lifecycle envelopes. Bootstrap signs
// its canonical manifest itself; install receipts sign their protobuf payload.
func recoverySigningJSON(domain string, payload any) ([]byte, error) {
	return json.Marshal(struct {
		Domain  string `json:"domain"`
		Payload any    `json:"payload"`
	}{Domain: domain, Payload: payload})
}
