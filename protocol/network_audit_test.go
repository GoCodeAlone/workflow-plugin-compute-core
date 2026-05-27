package protocol_test

import (
	"strings"
	"testing"
	"time"

	"github.com/GoCodeAlone/workflow-plugin-compute-core/protocol"
	pb "github.com/GoCodeAlone/workflow-plugin-compute-core/protocol/pb"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

func TestNetworkAuditProtocolVersion(t *testing.T) {
	if protocol.NetworkAuditProtocolVersion != "compute.v1alpha1" {
		t.Fatalf("NetworkAuditProtocolVersion = %q", protocol.NetworkAuditProtocolVersion)
	}
}

func TestNetworkAuditDestinationValidation(t *testing.T) {
	validDigest := protocol.CanonicalHash("destination")
	cases := []struct {
		name        string
		destination protocol.NetworkAuditDestination
		wantCode    protocol.NetworkAuditValidationCode
	}{
		{
			name: "endpoint",
			destination: protocol.NetworkAuditDestination{
				Kind:  protocol.NetworkAuditDestinationEndpoint,
				Value: "https://collector.example.invalid/audit",
			},
		},
		{
			name: "sha256",
			destination: protocol.NetworkAuditDestination{
				Kind:  protocol.NetworkAuditDestinationSHA256,
				Value: validDigest,
			},
		},
		{
			name: "artifact",
			destination: protocol.NetworkAuditDestination{
				Kind:  protocol.NetworkAuditDestinationArtifact,
				Value: "artifact://network-audit/evidence.json",
			},
		},
		{
			name: "network lifecycle",
			destination: protocol.NetworkAuditDestination{
				Kind:  protocol.NetworkAuditDestinationLifecycle,
				Value: "network-lifecycle://lease-123/egress",
			},
		},
		{
			name: "invalid endpoint",
			destination: protocol.NetworkAuditDestination{
				Kind:  protocol.NetworkAuditDestinationEndpoint,
				Value: "https://collector.example.invalid/audit?token=secret-token",
			},
			wantCode: protocol.NetworkAuditValidationDestinationInvalid,
		},
		{
			name: "invalid sha256",
			destination: protocol.NetworkAuditDestination{
				Kind:  protocol.NetworkAuditDestinationSHA256,
				Value: "sha256:not-a-digest",
			},
			wantCode: protocol.NetworkAuditValidationDestinationInvalid,
		},
		{
			name: "invalid artifact",
			destination: protocol.NetworkAuditDestination{
				Kind:  protocol.NetworkAuditDestinationArtifact,
				Value: "artifact://../secret",
			},
			wantCode: protocol.NetworkAuditValidationDestinationInvalid,
		},
		{
			name: "invalid network lifecycle",
			destination: protocol.NetworkAuditDestination{
				Kind:  protocol.NetworkAuditDestinationLifecycle,
				Value: "network-lifecycle://lease-123/../secret",
			},
			wantCode: protocol.NetworkAuditValidationDestinationInvalid,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			record := validNetworkAuditRecord()
			record.Destination = tc.destination
			issues := record.ValidateNetworkAudit()
			if tc.wantCode == "" {
				if len(issues) != 0 {
					t.Fatalf("expected valid destination, got issues: %#v", issues)
				}
				return
			}
			assertNetworkAuditIssue(t, issues, tc.wantCode)
		})
	}
}

func TestNetworkAuditValidationIssuesAreTypedAndRedacted(t *testing.T) {
	record := validNetworkAuditRecord()
	rawSecret := "secret-token-value"
	record.ProtocolVersion = "wrong-" + rawSecret
	record.RecordID = ""
	record.Destination = protocol.NetworkAuditDestination{
		Kind:  protocol.NetworkAuditDestinationKind("side-channel"),
		Value: "https://collector.example.invalid/audit?token=" + rawSecret,
	}
	record.ResourceUsage.CPUMillis = -1
	record.Labels = map[string]string{"bad/key": rawSecret}
	record.FinishedAt = record.StartedAt.Add(-time.Second)

	issues := record.ValidateNetworkAudit()
	wantCodes := []protocol.NetworkAuditValidationCode{
		protocol.NetworkAuditValidationProtocolVersionInvalid,
		protocol.NetworkAuditValidationRecordIDRequired,
		protocol.NetworkAuditValidationDestinationInvalid,
		protocol.NetworkAuditValidationResourceUsageInvalid,
		protocol.NetworkAuditValidationLabelInvalid,
		protocol.NetworkAuditValidationTimeRangeInvalid,
	}
	for _, code := range wantCodes {
		assertNetworkAuditIssue(t, issues, code)
	}
	for _, issue := range issues {
		if issue.Code == "" {
			t.Fatalf("issue missing typed code: %#v", issue)
		}
		if strings.Contains(issue.Message, rawSecret) {
			t.Fatalf("issue leaked raw rejected value: %#v", issue)
		}
	}
}

func TestNetworkAuditProtoRoundTripStrict(t *testing.T) {
	record := validNetworkAuditRecord()
	message := record.ToProto()
	data, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		t.Fatalf("marshal proto: %v", err)
	}

	decoded, err := protocol.UnmarshalNetworkAuditRecordProtoStrict(data)
	if err != nil {
		t.Fatalf("strict unmarshal: %v", err)
	}
	roundTrip, err := protocol.NetworkAuditRecordFromProto(decoded)
	if err != nil {
		t.Fatalf("from proto: %v", err)
	}
	if got, want := protocol.CanonicalHash(roundTrip), protocol.CanonicalHash(record); got != want {
		t.Fatalf("round trip hash mismatch: got %s want %s", got, want)
	}
}

func TestNetworkAuditProtoRejectsUnknownFields(t *testing.T) {
	message := validNetworkAuditRecord().ToProto()
	data, err := proto.Marshal(message)
	if err != nil {
		t.Fatalf("marshal proto: %v", err)
	}
	data = append(data, protowire.AppendTag(nil, 99, protowire.VarintType)...)
	data = protowire.AppendVarint(data, 1)
	if _, err := protocol.UnmarshalNetworkAuditRecordProtoStrict(data); err == nil {
		t.Fatal("expected strict unmarshal to reject top-level unknown fields")
	}
}

func TestNetworkAuditProtoRejectsNestedUnknownFields(t *testing.T) {
	message := validNetworkAuditRecord().ToProto()
	message.Destination.ProtoReflect().SetUnknown(protowire.AppendVarint(
		protowire.AppendTag(nil, 99, protowire.VarintType),
		1,
	))
	data, err := proto.Marshal(message)
	if err != nil {
		t.Fatalf("marshal proto: %v", err)
	}
	if _, err := protocol.UnmarshalNetworkAuditRecordProtoStrict(data); err == nil {
		t.Fatal("expected strict unmarshal to reject nested unknown fields")
	}
}

func TestNetworkAuditProtoRejectsInvalidIntegerRanges(t *testing.T) {
	message := validNetworkAuditRecord().ToProto()
	message.ResourceUsage.CpuMillis = -1
	if _, err := protocol.NetworkAuditRecordFromProto(message); err == nil {
		t.Fatal("expected negative resource usage to be rejected")
	}

	message = validNetworkAuditRecord().ToProto()
	message.StartedAtUnixNano = -1
	if _, err := protocol.NetworkAuditRecordFromProto(message); err == nil {
		t.Fatal("expected negative timestamp to be rejected")
	}
}

func TestNetworkAuditRejectsTooManyLabels(t *testing.T) {
	record := validNetworkAuditRecord()
	record.Labels = make(map[string]string, protocol.NetworkAuditMaxLabels+1)
	for i := range protocol.NetworkAuditMaxLabels + 1 {
		record.Labels["label"+string(rune('a'+i))] = "value"
	}
	issues := record.ValidateNetworkAudit()
	assertNetworkAuditIssue(t, issues, protocol.NetworkAuditValidationLabelCountExceeded)
}

func TestNetworkAuditGoProtoParity(t *testing.T) {
	record := validNetworkAuditRecord()
	protoRecord := record.ToProto()
	if protoRecord.GetProtocolVersion() != record.ProtocolVersion {
		t.Fatalf("protocol version mismatch")
	}
	got, err := protocol.NetworkAuditRecordFromProto(protoRecord)
	if err != nil {
		t.Fatalf("from proto: %v", err)
	}
	if got.ResourceUsage.NetworkTxBytes != record.ResourceUsage.NetworkTxBytes {
		t.Fatalf("resource usage mismatch: got %d want %d", got.ResourceUsage.NetworkTxBytes, record.ResourceUsage.NetworkTxBytes)
	}

	var _ *pb.NetworkAuditRecord = protoRecord
}

func validNetworkAuditRecord() protocol.NetworkAuditRecord {
	started := time.Unix(1_700_000_000, 0).UTC()
	return protocol.NetworkAuditRecord{
		ProtocolVersion: protocol.NetworkAuditProtocolVersion,
		RecordID:        "audit-record-1",
		TaskID:          "task-1",
		LeaseID:         "lease-1",
		WorkerID:        "worker-1",
		Provider: protocol.NetworkAuditProviderEvidence{
			ProviderID:       "local",
			PluginName:       "workflow-compute",
			PluginVersion:    "v1.2.3",
			ContractID:       "network-audit",
			ContractVersion:  "v1",
			DescriptorDigest: protocol.CanonicalHash("descriptor"),
		},
		Destination: protocol.NetworkAuditDestination{
			Kind:  protocol.NetworkAuditDestinationEndpoint,
			Value: "https://collector.example.invalid/audit",
		},
		ResourceUsage: protocol.ResourceUsage{
			CPUMillis:      10,
			MaxMemoryBytes: 4096,
			NetworkRxBytes: 128,
			NetworkTxBytes: 256,
		},
		Labels: map[string]string{
			"scenario": "no-account",
		},
		StartedAt:  started,
		FinishedAt: started.Add(time.Second),
		ObservedAt: started.Add(2 * time.Second),
	}
}

func assertNetworkAuditIssue(t *testing.T, issues []protocol.NetworkAuditValidationIssue, code protocol.NetworkAuditValidationCode) {
	t.Helper()
	for _, issue := range issues {
		if issue.Code == code {
			return
		}
	}
	t.Fatalf("missing issue code %q in %#v", code, issues)
}
