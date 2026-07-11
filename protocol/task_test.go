package protocol_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/GoCodeAlone/workflow-plugin-compute-core/protocol"
)

func TestTaskValidatesPortableWorkloadContract(t *testing.T) {
	task := validTask(t)

	if err := task.Validate(); err != nil {
		t.Fatalf("task invalid: %v", err)
	}
}

func TestTaskRejectsMalformedPortableContract(t *testing.T) {
	task := validTask(t)
	task.ProtocolVersion = "wrong"
	task.Status = protocol.TaskStatus("mystery")
	task.OrgID = ""
	task.Workload = protocol.WorkloadSpec{Kind: protocol.WorkloadProvider}
	task.TimeoutSeconds = -1
	task.ResourceLimits = protocol.ResourceLimits{RuntimeSeconds: -1}
	task.Signature = protocol.SignatureEnvelope{}

	err := task.Validate()
	if err == nil {
		t.Fatal("expected malformed task to fail")
	}
	for _, want := range []string{
		"protocol_version",
		"status",
		"org_id",
		"workload",
		"timeout_seconds",
		"resource_limits",
		"signature",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("Validate() = %v, want %q", err, want)
		}
	}
}

func TestLeaseValidatesAgentWireContract(t *testing.T) {
	lease := validLease(t)

	if err := lease.Validate(); err != nil {
		t.Fatalf("lease invalid: %v", err)
	}
}

func TestLeaseRejectsMalformedAgentWireContract(t *testing.T) {
	lease := validLease(t)
	lease.Executor.Provider = ""
	lease.Executor.Version = ""
	lease.CapabilitySnapshot.OS = ""
	lease.ResiduePolicy.PolicyHash = "bad"
	lease.ExpiresAt = lease.LeasedAt.Add(-time.Second)

	err := lease.Validate()
	if err == nil {
		t.Fatal("expected malformed lease to fail")
	}
	for _, want := range []string{
		"executor.provider",
		"capability_snapshot.os",
		"residue_policy",
		"expires_at",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("Validate() = %v, want %q", err, want)
		}
	}
}

func TestLeaseAcceptsProviderArtifactSpecsWithoutLegacyArtifactMembership(t *testing.T) {
	lease := validLease(t)
	lease.ProviderArtifactSpecs = []protocol.ProviderArtifactSpec{{
		Name:             "provider_result",
		ContentType:      "application/json",
		MaxBytes:         4096,
		RetentionSeconds: 3600,
		ProviderReturn: &protocol.ProviderArtifactReturnSpec{
			StepType:       "provider_artifact_return",
			Contract:       "workflow-plugin-ci:provider_artifact_return",
			SubmitEndpoint: "/v1/provider-return/artifact-deliveries",
		},
	}}

	if err := lease.Validate(); err != nil {
		t.Fatalf("lease invalid: %v", err)
	}
}

func TestLeaseRejectsInvalidProviderArtifactSpecs(t *testing.T) {
	cases := []struct {
		name  string
		specs []protocol.ProviderArtifactSpec
		want  string
	}{
		{
			name:  "invalid name",
			specs: []protocol.ProviderArtifactSpec{{Name: "results/output"}},
			want:  `provider_artifact_specs[0].name "results/output" is invalid`,
		},
		{
			name: "duplicate name",
			specs: []protocol.ProviderArtifactSpec{
				{Name: "result"},
				{Name: "result"},
			},
			want: `provider_artifact_specs[1].name "result" is duplicated`,
		},
		{
			name:  "malformed content type",
			specs: []protocol.ProviderArtifactSpec{{Name: "result", ContentType: "application/json\n"}},
			want:  "provider_artifact_specs[0].content_type is invalid",
		},
		{
			name:  "negative max bytes",
			specs: []protocol.ProviderArtifactSpec{{Name: "result", MaxBytes: -1}},
			want:  "provider_artifact_specs[0].max_bytes must not be negative",
		},
		{
			name:  "negative retention seconds",
			specs: []protocol.ProviderArtifactSpec{{Name: "result", RetentionSeconds: -1}},
			want:  "provider_artifact_specs[0].retention_seconds must not be negative",
		},
		{
			name: "invalid provider return",
			specs: []protocol.ProviderArtifactSpec{{
				Name:           "result",
				ProviderReturn: &protocol.ProviderArtifactReturnSpec{},
			}},
			want: "provider_artifact_specs[0].provider_return:",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lease := validLease(t)
			lease.ProviderArtifactSpecs = tc.specs

			err := lease.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate() error = %v, want containing %q", err, tc.want)
			}
		})
	}
}

func validTask(t *testing.T) protocol.Task {
	t.Helper()
	input := mustTaskRawMessage(t, map[string]any{
		"url":           "https://example.test/products/sku-1",
		"allowed_hosts": []string{"example.test"},
		"capture_mode":  string(protocol.ProductCaptureModeBrowser),
	})
	workload := protocol.WorkloadSpec{
		Kind: protocol.WorkloadProvider,
		Provider: &protocol.ProviderWorkload{
			ProviderConfig: protocol.ProviderConfig{
				PluginID:   "workflow-plugin-product-capture",
				ProviderID: "browser",
				ContractID: "product-capture.browser.v1",
				Version:    "v1.0.0",
				ConfigRef:  "config://providers/product-capture/browser",
			},
			Operation: "capture_product",
			ImageRef:  "ghcr.io/gocodealone/product-capture@sha256:" + strings.Repeat("a", 64),
			Input:     input,
		},
	}
	return protocol.Task{
		ProtocolVersion: protocol.Version,
		ID:              "task-product-capture-1",
		ProductID:       "product-capture",
		OrgID:           "org-1",
		PoolID:          "pool-1",
		PolicyID:        "policy-1",
		Status:          protocol.TaskQueued,
		Workload:        workload,
		ResourceLimits:  protocol.ResourceLimits{RuntimeSeconds: 30, OutputBytes: 1024},
		InputHash:       protocol.CanonicalHash(workload),
		RequestedAt:     time.Date(2026, 6, 6, 4, 0, 0, 0, time.UTC),
		TimeoutSeconds:  60,
		Labels:          map[string]string{"plugin": "product-capture"},
		Signature: protocol.SignatureEnvelope{
			Algorithm: "test-sha256",
			KeyID:     "test-key",
			Value:     strings.Repeat("b", 64),
		},
	}
}

func validLease(t *testing.T) protocol.Lease {
	t.Helper()
	leasedAt := time.Date(2026, 6, 6, 4, 0, 0, 0, time.UTC)
	return protocol.Lease{
		ID:       "lease-1",
		TaskID:   "task-product-capture-1",
		WorkerID: "worker-1",
		PoolID:   "pool-1",
		Executor: protocol.ExecutorRef{
			Provider: "sandboxed-command",
			Version:  "v1.0.0",
		},
		CapabilitySnapshot: protocol.Capabilities{
			OS:   "darwin",
			Arch: "arm64",
		},
		NetworkPolicy: protocol.NetworkPolicy{
			Mode: protocol.NetworkModeOffline,
		},
		ResiduePolicy: protocol.ResiduePolicy{
			Mode:                protocol.ResidueModeSessionBound,
			SessionKey:          "task-product-capture-1",
			PolicyHash:          "sha256:" + strings.Repeat("c", 64),
			ExplicitWorkerBound: true,
		},
		LeasedAt:  leasedAt,
		ExpiresAt: leasedAt.Add(5 * time.Minute),
	}
}

func mustTaskRawMessage(t *testing.T, value any) json.RawMessage {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal raw message: %v", err)
	}
	return data
}
