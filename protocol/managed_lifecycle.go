package protocol

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/url"
	"strings"
	"time"
)

const (
	ManagedProviderLifecycleCapability    = "managed-provider-lifecycle-v1"
	ManagedProviderLifecycleCommand       = "managed-provider-lifecycle"
	DedicatedProviderHostPreflightVersion = "dedicated-provider-host-preflight.v1"
)

type ManagedLifecycleAction string

const (
	ManagedLifecyclePrepare    ManagedLifecycleAction = "prepare"
	ManagedLifecycleActivate   ManagedLifecycleAction = "activate"
	ManagedLifecycleDeactivate ManagedLifecycleAction = "deactivate"
	ManagedLifecycleRollback   ManagedLifecycleAction = "rollback"
	ManagedLifecycleStatus     ManagedLifecycleAction = "status"
)

func validManagedLifecycleAction(action ManagedLifecycleAction) bool {
	switch action {
	case ManagedLifecyclePrepare, ManagedLifecycleActivate, ManagedLifecycleDeactivate, ManagedLifecycleRollback, ManagedLifecycleStatus:
		return true
	default:
		return false
	}
}

// ManagedLifecycleArtifactRef describes encrypted, server-relative material.
// Content fetch/ack, key custody, and terminal revocation remain host-owned.
type ManagedLifecycleArtifactRef struct {
	ProtocolVersion string            `json:"protocol_version"`
	TransactionID   string            `json:"transaction_id"`
	WorkerID        string            `json:"worker_id"`
	PluginID        string            `json:"plugin_id"`
	Component       string            `json:"component"`
	ComponentDigest string            `json:"component_digest"`
	Ref             string            `json:"ref"`
	Digest          string            `json:"digest"`
	MaxBytes        int64             `json:"max_bytes"`
	EnvelopeKeyID   string            `json:"envelope_key_id"`
	ExpiresAt       time.Time         `json:"expires_at"`
	Signature       SignatureEnvelope `json:"signature,omitzero"`
}

func (r ManagedLifecycleArtifactRef) validate() error {
	var errs []error
	errs = append(errs, recoveryProtocolError(r.ProtocolVersion))
	for _, field := range []struct{ name, value string }{
		{"transaction_id", r.TransactionID}, {"worker_id", r.WorkerID}, {"plugin_id", r.PluginID}, {"component", r.Component}, {"envelope_key_id", r.EnvelopeKeyID},
	} {
		errs = append(errs, validateIdentifier(field.name, field.value))
	}
	errs = append(errs, validateRequiredSHA256Digest("component_digest", r.ComponentDigest)...)
	errs = append(errs, validateRequiredSHA256Digest("digest", r.Digest)...)
	u, err := url.Parse(r.Ref)
	if err != nil || u.IsAbs() || u.Host != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || !strings.HasPrefix(r.Ref, "/") || strings.HasPrefix(r.Ref, "//") || strings.ContainsAny(r.Ref, "\\\x00\r\n") || strings.ContainsAny(u.Path, "\\%\x00\r\n") || strings.HasPrefix(u.Path, "//") {
		errs = append(errs, errors.New("ref must be a server-relative artifact URL without query, fragment, or credentials"))
	} else {
		for _, segment := range strings.Split(u.Path, "/") {
			if segment == ".." || segment == "." {
				errs = append(errs, errors.New("ref must not contain traversal"))
				break
			}
		}
	}
	if r.MaxBytes <= 0 {
		errs = append(errs, errors.New("max_bytes must be positive"))
	}
	if r.ExpiresAt.IsZero() {
		errs = append(errs, errors.New("expires_at is required"))
	}
	return errors.Join(errs...)
}

func (r ManagedLifecycleArtifactRef) ValidateAt(now time.Time) error {
	return errors.Join(r.validate(), recoveryExpiryError(r.ExpiresAt, now))
}

func (r ManagedLifecycleArtifactRef) SigningBytes() ([]byte, error) {
	if err := r.validate(); err != nil {
		return nil, err
	}
	r.Signature = SignatureEnvelope{}
	r.ExpiresAt = r.ExpiresAt.UTC()
	return recoverySigningJSON("managed-lifecycle-artifact.v1", r)
}

func (r *ManagedLifecycleArtifactRef) Sign(key ed25519.PrivateKey) error {
	data, err := r.SigningBytes()
	if err != nil {
		return err
	}
	r.Signature, err = signRecoveryBytes(data, key)
	return err
}

func (r ManagedLifecycleArtifactRef) Verify(public ed25519.PublicKey, now time.Time) error {
	if err := r.ValidateAt(now); err != nil {
		return err
	}
	data, err := r.SigningBytes()
	if err != nil {
		return err
	}
	return verifyRecoveryBytes(data, r.Signature, public)
}

// The command and executable are deliberately absent. Consumers resolve only
// the promoted component digest, then pass this request on the fixed stdin path.
type ManagedProviderLifecycleRequest struct {
	ProtocolVersion    string                        `json:"protocol_version"`
	Action             ManagedLifecycleAction        `json:"action"`
	RequiredCapability string                        `json:"required_capability"`
	TransactionID      string                        `json:"transaction_id"`
	WorkerID           string                        `json:"worker_id"`
	PluginID           string                        `json:"plugin_id"`
	Component          string                        `json:"component"`
	Version            string                        `json:"version"`
	Digest             string                        `json:"digest"`
	ConfigRef          ManagedLifecycleArtifactRef   `json:"config_ref"`
	ConfigHash         string                        `json:"config_hash"`
	SecretRefs         []ManagedLifecycleArtifactRef `json:"secret_refs"`
	PriorStateHash     string                        `json:"prior_state_hash"`
	ExpiresAt          time.Time                     `json:"expires_at"`
	Signature          SignatureEnvelope             `json:"signature,omitzero"`
}

func (r ManagedProviderLifecycleRequest) validate() error {
	var errs []error
	errs = append(errs, recoveryProtocolError(r.ProtocolVersion))
	if !validManagedLifecycleAction(r.Action) {
		errs = append(errs, errors.New("action must be prepare, activate, deactivate, rollback, or status"))
	}
	if r.RequiredCapability != ManagedProviderLifecycleCapability {
		errs = append(errs, errors.New("required_capability must be managed-provider-lifecycle-v1"))
	}
	for _, field := range []struct{ name, value string }{
		{"transaction_id", r.TransactionID}, {"worker_id", r.WorkerID}, {"plugin_id", r.PluginID}, {"component", r.Component}, {"version", r.Version},
	} {
		errs = append(errs, validateIdentifier(field.name, field.value))
	}
	for _, field := range []struct{ name, value string }{
		{"digest", r.Digest}, {"config_hash", r.ConfigHash}, {"prior_state_hash", r.PriorStateHash},
	} {
		errs = append(errs, validateRequiredSHA256Digest(field.name, field.value)...)
	}
	if r.ConfigHash != r.ConfigRef.Digest {
		errs = append(errs, errors.New("config_hash must match config_ref.digest"))
	}
	refs := append([]ManagedLifecycleArtifactRef{r.ConfigRef}, r.SecretRefs...)
	seen := make(map[string]bool)
	for _, ref := range refs {
		errs = append(errs, ref.validate())
		if ref.TransactionID != r.TransactionID || ref.WorkerID != r.WorkerID || ref.PluginID != r.PluginID || ref.Component != r.Component || ref.ComponentDigest != r.Digest {
			errs = append(errs, errors.New("artifact ref must match request transaction, worker, plugin, component, and promoted digest"))
		}
		if seen[ref.Ref] {
			errs = append(errs, errors.New("artifact refs must not repeat a server-relative URL"))
		}
		seen[ref.Ref] = true
	}
	if r.ExpiresAt.IsZero() {
		errs = append(errs, errors.New("expires_at is required"))
	}
	return errors.Join(errs...)
}

func (r ManagedProviderLifecycleRequest) ValidateAt(now time.Time) error {
	var errs []error
	errs = append(errs, r.validate(), recoveryExpiryError(r.ExpiresAt, now), r.ConfigRef.ValidateAt(now))
	for _, ref := range r.SecretRefs {
		errs = append(errs, ref.ValidateAt(now))
	}
	return errors.Join(errs...)
}

func (r ManagedProviderLifecycleRequest) SigningBytes() ([]byte, error) {
	if err := r.validate(); err != nil {
		return nil, err
	}
	r.Signature = SignatureEnvelope{}
	r.ExpiresAt = r.ExpiresAt.UTC()
	r.ConfigRef.ExpiresAt = r.ConfigRef.ExpiresAt.UTC()
	r.SecretRefs = append([]ManagedLifecycleArtifactRef{}, r.SecretRefs...)
	for i := range r.SecretRefs {
		r.SecretRefs[i].ExpiresAt = r.SecretRefs[i].ExpiresAt.UTC()
	}
	return recoverySigningJSON("managed-provider-lifecycle-request.v1", r)
}

func (r *ManagedProviderLifecycleRequest) Sign(key ed25519.PrivateKey) error {
	data, err := r.SigningBytes()
	if err != nil {
		return err
	}
	r.Signature, err = signRecoveryBytes(data, key)
	return err
}

// BindingHash binds a terminal result to every signature-free request input.
func (r ManagedProviderLifecycleRequest) BindingHash() (string, error) {
	data, err := r.SigningBytes()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func (r ManagedProviderLifecycleRequest) Verify(public ed25519.PublicKey, now time.Time) error {
	if err := r.ValidateAt(now); err != nil {
		return err
	}
	data, err := r.SigningBytes()
	if err != nil {
		return err
	}
	return verifyRecoveryBytes(data, r.Signature, public)
}

type ManagedLifecycleResultStatus string
type ManagedLifecycleRollbackResult string

const (
	ManagedLifecycleSucceeded           ManagedLifecycleResultStatus   = "succeeded"
	ManagedLifecycleFailed              ManagedLifecycleResultStatus   = "failed"
	ManagedLifecycleRollbackNotRequired ManagedLifecycleRollbackResult = "not-required"
	ManagedLifecycleRollbackSucceeded   ManagedLifecycleRollbackResult = "succeeded"
	ManagedLifecycleRollbackFailed      ManagedLifecycleRollbackResult = "failed"
)

type ManagedProviderLifecycleResult struct {
	ProtocolVersion  string                         `json:"protocol_version"`
	TransactionID    string                         `json:"transaction_id"`
	WorkerID         string                         `json:"worker_id"`
	PluginID         string                         `json:"plugin_id"`
	Component        string                         `json:"component"`
	Version          string                         `json:"version"`
	Digest           string                         `json:"digest"`
	Action           ManagedLifecycleAction         `json:"action"`
	RequestHash      string                         `json:"request_hash"`
	IdempotencyState string                         `json:"idempotency_state"`
	ServiceHash      string                         `json:"service_hash"`
	StateHash        string                         `json:"state_hash"`
	Status           ManagedLifecycleResultStatus   `json:"status"`
	RollbackResult   ManagedLifecycleRollbackResult `json:"rollback_result"`
	CompletedAt      time.Time                      `json:"completed_at"`
	ExpiresAt        time.Time                      `json:"expires_at"`
	Signature        SignatureEnvelope              `json:"signature,omitzero"`
}

func (r ManagedProviderLifecycleResult) validate() error {
	var errs []error
	errs = append(errs, recoveryProtocolError(r.ProtocolVersion))
	for _, field := range []struct{ name, value string }{
		{"transaction_id", r.TransactionID}, {"worker_id", r.WorkerID}, {"plugin_id", r.PluginID}, {"component", r.Component}, {"version", r.Version}, {"idempotency_state", r.IdempotencyState},
	} {
		errs = append(errs, validateIdentifier(field.name, field.value))
		errs = append(errs, validateRuntimeBackendPublicText(field.name, field.value)...)
	}
	for _, field := range []struct{ name, value string }{{"digest", r.Digest}, {"request_hash", r.RequestHash}, {"service_hash", r.ServiceHash}, {"state_hash", r.StateHash}} {
		errs = append(errs, validateRequiredSHA256Digest(field.name, field.value)...)
	}
	if !validManagedLifecycleAction(r.Action) || (r.Status != ManagedLifecycleSucceeded && r.Status != ManagedLifecycleFailed) {
		errs = append(errs, errors.New("action or status is not supported"))
	}
	if r.RollbackResult != ManagedLifecycleRollbackNotRequired && r.RollbackResult != ManagedLifecycleRollbackSucceeded && r.RollbackResult != ManagedLifecycleRollbackFailed {
		errs = append(errs, errors.New("rollback_result is not supported"))
	}
	if r.CompletedAt.IsZero() || r.ExpiresAt.IsZero() || !r.CompletedAt.Before(r.ExpiresAt) {
		errs = append(errs, errors.New("completed_at must be nonzero and precede expires_at"))
	}
	return errors.Join(errs...)
}

func (r ManagedProviderLifecycleResult) ValidateAt(now time.Time) error {
	var future error
	if r.CompletedAt.After(now) {
		future = errors.New("completed_at must not be in the future")
	}
	return errors.Join(r.validate(), recoveryExpiryError(r.ExpiresAt, now), future)
}

func (r ManagedProviderLifecycleResult) SigningBytes() ([]byte, error) {
	if err := r.validate(); err != nil {
		return nil, err
	}
	r.Signature = SignatureEnvelope{}
	r.CompletedAt, r.ExpiresAt = r.CompletedAt.UTC(), r.ExpiresAt.UTC()
	return recoverySigningJSON("managed-provider-lifecycle-result.v1", r)
}

func (r *ManagedProviderLifecycleResult) Sign(key ed25519.PrivateKey) error {
	data, err := r.SigningBytes()
	if err != nil {
		return err
	}
	r.Signature, err = signRecoveryBytes(data, key)
	return err
}

func (r ManagedProviderLifecycleResult) Verify(public ed25519.PublicKey, request ManagedProviderLifecycleRequest, now time.Time) error {
	if err := r.ValidateAt(now); err != nil {
		return err
	}
	if err := request.ValidateAt(now); err != nil {
		return err
	}
	requestHash, err := request.BindingHash()
	if err != nil {
		return err
	}
	if r.RequestHash != requestHash || r.TransactionID != request.TransactionID || r.WorkerID != request.WorkerID || r.PluginID != request.PluginID || r.Component != request.Component || r.Version != request.Version || r.Digest != request.Digest || r.Action != request.Action || !r.ExpiresAt.Equal(request.ExpiresAt) {
		return errors.New("lifecycle result does not match the request binding")
	}
	data, err := r.SigningBytes()
	if err != nil {
		return err
	}
	return verifyRecoveryBytes(data, r.Signature, public)
}

type HostServiceState string

const (
	HostServiceActive       HostServiceState = "active"
	HostServiceInactive     HostServiceState = "inactive"
	HostServiceFailed       HostServiceState = "failed"
	HostServiceActivating   HostServiceState = "activating"
	HostServiceDeactivating HostServiceState = "deactivating"
	HostServiceNotFound     HostServiceState = "not-found"
)

// Evidence contains only public identity, hashes, presence-aware booleans and
// fixed service states. No ambient process, file, or environment bytes cross it.
type DedicatedProviderHostPreflightResult struct {
	ProtocolVersion             string           `json:"protocol_version"`
	WorkerID                    string           `json:"worker_id"`
	OS                          string           `json:"os"`
	UID                         uint32           `json:"uid"`
	HomeHash                    string           `json:"home_hash"`
	MachineIDHash               string           `json:"machine_id_hash"`
	AgentUnitDigest             string           `json:"agent_unit_digest"`
	LauncherUnitDigest          string           `json:"launcher_unit_digest"`
	FirewallPolicyHash          string           `json:"firewall_policy_hash"`
	AgentServiceState           HostServiceState `json:"agent_service_state"`
	LauncherServiceState        HostServiceState `json:"launcher_service_state"`
	UserBusAvailable            *bool            `json:"user_bus_available"`
	LingeringEnabled            *bool            `json:"lingering_enabled"`
	RootlessPodman              *bool            `json:"rootless_podman"`
	ActionsRunnerProcessPresent *bool            `json:"actions_runner_process_present"`
	ActionsRunnerServicePresent *bool            `json:"actions_runner_service_present"`
}

func (r DedicatedProviderHostPreflightResult) Validate() error {
	var errs []error
	if r.ProtocolVersion != DedicatedProviderHostPreflightVersion || r.OS != "linux" {
		errs = append(errs, errors.New("protocol_version and os must identify the Linux dedicated-host preflight"))
	}
	errs = append(errs, validateIdentifier("worker_id", r.WorkerID))
	errs = append(errs, validateRuntimeBackendPublicText("worker_id", r.WorkerID)...)
	for _, field := range []struct{ name, value string }{
		{"home_hash", r.HomeHash}, {"machine_id_hash", r.MachineIDHash}, {"agent_unit_digest", r.AgentUnitDigest}, {"launcher_unit_digest", r.LauncherUnitDigest}, {"firewall_policy_hash", r.FirewallPolicyHash},
	} {
		errs = append(errs, validateRequiredSHA256Digest(field.name, field.value)...)
	}
	for _, state := range []HostServiceState{r.AgentServiceState, r.LauncherServiceState} {
		switch state {
		case HostServiceActive, HostServiceInactive, HostServiceFailed, HostServiceActivating, HostServiceDeactivating, HostServiceNotFound:
		default:
			errs = append(errs, errors.New("service state is not supported"))
		}
	}
	if r.UserBusAvailable == nil || r.LingeringEnabled == nil || r.RootlessPodman == nil || r.ActionsRunnerProcessPresent == nil || r.ActionsRunnerServicePresent == nil {
		errs = append(errs, errors.New("preflight booleans must be explicitly present"))
	}
	if (r.ActionsRunnerProcessPresent != nil && *r.ActionsRunnerProcessPresent) || (r.ActionsRunnerServicePresent != nil && *r.ActionsRunnerServicePresent) {
		errs = append(errs, errors.New("dedicated host must contain no Actions runner process or service"))
	}
	return errors.Join(errs...)
}
