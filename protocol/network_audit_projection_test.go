package protocol_test

import (
	"strings"
	"testing"
	"time"

	"github.com/GoCodeAlone/workflow-plugin-compute-core/protocol"
)

func TestNetworkAuditProjectDestination(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		kind protocol.NetworkAuditDestinationKind
	}{
		{"endpoint", "https://collector.example.invalid/audit", protocol.NetworkAuditDestinationEndpoint},
		{"digest", protocol.CanonicalHash("destination"), protocol.NetworkAuditDestinationSHA256},
		{"artifact", "artifact://network-audit/evidence.json", protocol.NetworkAuditDestinationArtifact},
		{"lifecycle", "network-lifecycle://lease-1/egress", protocol.NetworkAuditDestinationLifecycle},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			destination, issues := protocol.ProjectNetworkAuditDestination(tc.raw)
			if len(issues) != 0 {
				t.Fatalf("expected projected destination, got issues: %#v", issues)
			}
			if destination.Kind != tc.kind || destination.Value != tc.raw {
				t.Fatalf("unexpected destination: %#v", destination)
			}
		})
	}

	_, issues := protocol.ProjectNetworkAuditDestination("https://collector.example.invalid/audit?token=secret-token")
	assertNetworkAuditIssue(t, issues, protocol.NetworkAuditValidationDestinationInvalid)
	for _, issue := range issues {
		if strings.Contains(issue.Message, "secret-token") {
			t.Fatalf("destination issue leaked raw value: %#v", issue)
		}
	}
}

func TestNetworkAuditProjectLifecycle(t *testing.T) {
	destination, issues := protocol.ProjectNetworkAuditLifecycle("lease-1", "egress")
	if len(issues) != 0 {
		t.Fatalf("expected lifecycle projection, got issues: %#v", issues)
	}
	if destination.Kind != protocol.NetworkAuditDestinationLifecycle || destination.Value != "network-lifecycle://lease-1/egress" {
		t.Fatalf("unexpected lifecycle destination: %#v", destination)
	}

	created, err := protocol.NewNetworkAuditLifecycleDestination("lease-1", "dns")
	if err != nil {
		t.Fatalf("new lifecycle destination: %v", err)
	}
	if created.Value != "network-lifecycle://lease-1/dns" {
		t.Fatalf("unexpected lifecycle destination: %#v", created)
	}
}

func TestNetworkAuditProjectLabelsProviderAndID(t *testing.T) {
	labels, issues := protocol.ProjectNetworkAuditLabels(map[string]string{
		"scenario": "no-account",
	})
	if len(issues) != 0 {
		t.Fatalf("expected projected labels, got issues: %#v", issues)
	}
	labels["scenario"] = "mutated"
	if got := labels["scenario"]; got != "mutated" {
		t.Fatalf("expected local mutation to affect projected copy only, got %q", got)
	}

	provider, issues := protocol.ProjectNetworkAuditProvider("local", "workflow-compute", "v1.2.3", "network-audit", "v1", protocol.CanonicalHash("descriptor"))
	if len(issues) != 0 {
		t.Fatalf("expected projected provider, got issues: %#v", issues)
	}
	if provider.ProviderID != "local" || provider.PluginName != "workflow-compute" {
		t.Fatalf("unexpected provider projection: %#v", provider)
	}

	left, err := protocol.ProjectNetworkAuditID("ab", "c")
	if err != nil {
		t.Fatalf("project id: %v", err)
	}
	right, err := protocol.ProjectNetworkAuditID("a", "bc")
	if err != nil {
		t.Fatalf("project id: %v", err)
	}
	if left == right {
		t.Fatal("component digest projection collided")
	}
	if !strings.HasPrefix(left, "network-audit-sha256-") {
		t.Fatalf("unexpected audit id: %q", left)
	}
	record := validNetworkAuditRecord()
	record.RecordID = left
	if issues := record.ValidateNetworkAudit(); len(issues) != 0 {
		t.Fatalf("projected id did not validate as record id: %#v", issues)
	}
}

func TestNetworkAuditRefProjector(t *testing.T) {
	record := validNetworkAuditRecord()
	projector, err := protocol.NewNetworkAuditRefProjector([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("new projector: %v", err)
	}
	projection, err := projector.Project(record, protocol.NetworkAuditRefOptions{
		Stability: protocol.NetworkAuditRefStable,
		Timestamp: record.StartedAt.In(time.FixedZone("test", -5*60*60)),
	})
	if err != nil {
		t.Fatalf("project ref: %v", err)
	}
	if projection.Epoch != protocol.NetworkAuditRefKeyEpoch {
		t.Fatalf("unexpected epoch: %q", projection.Epoch)
	}
	if projection.Ref != "network-audit-ref-v1:stable:e1de3b6b44e27a56bc87cd84de9947cadcd77e69e768dad495f5b1766f8f3b19" {
		t.Fatalf("unexpected ref vector: %q", projection.Ref)
	}
	if projection.Timestamp != "2023-11-14T22:13:20Z" {
		t.Fatalf("timestamp was not normalized: %q", projection.Timestamp)
	}

	ephemeral, err := projector.Project(record, protocol.NetworkAuditRefOptions{
		Stability: protocol.NetworkAuditRefEphemeral,
		Timestamp: record.StartedAt.Add(time.Second),
	})
	if err != nil {
		t.Fatalf("project ephemeral ref: %v", err)
	}
	if ephemeral.Ref == projection.Ref || ephemeral.Stability != protocol.NetworkAuditRefEphemeral {
		t.Fatalf("ephemeral ref was not distinct: %#v", ephemeral)
	}

	mutated := record
	mutated.ResourceUsage.NetworkTxBytes++
	mutatedProjection, err := projector.Project(mutated, protocol.NetworkAuditRefOptions{
		Stability: protocol.NetworkAuditRefStable,
		Timestamp: record.StartedAt,
	})
	if err != nil {
		t.Fatalf("project mutated ref: %v", err)
	}
	if mutatedProjection.Ref == projection.Ref {
		t.Fatal("ref projection did not bind full record content")
	}
}

func TestNetworkAuditLifecycleRejectsMalformedRefs(t *testing.T) {
	record := validNetworkAuditRecord()
	record.Destination = protocol.NetworkAuditDestination{
		Kind:  protocol.NetworkAuditDestinationLifecycle,
		Value: "network-lifecycle://lease-1/",
	}
	assertNetworkAuditIssue(t, record.ValidateNetworkAudit(), protocol.NetworkAuditValidationDestinationInvalid)
}

func TestNetworkAuditRefProjectorRejectsWeakKeys(t *testing.T) {
	_, err := protocol.NewNetworkAuditRefProjector([]byte("short-secret"))
	if err == nil {
		t.Fatal("expected weak key rejection")
	}
	if strings.Contains(err.Error(), "short-secret") {
		t.Fatalf("weak key error leaked raw key: %v", err)
	}
}

func TestNetworkAuditLegacyClassification(t *testing.T) {
	findings := protocol.ClassifyLegacyNetworkAuditRecord(map[string]any{
		"destination": "https://collector.example.invalid/audit?token=secret-token",
		"labels": map[string]any{
			"bad/key": "secret-token",
		},
		"resource_usage": map[string]any{
			"network_tx_bytes": -1,
		},
	})
	wantCodes := []protocol.NetworkAuditValidationCode{
		protocol.NetworkAuditValidationDestinationInvalid,
		protocol.NetworkAuditValidationLabelInvalid,
		protocol.NetworkAuditValidationResourceUsageInvalid,
	}
	for _, code := range wantCodes {
		assertNetworkAuditIssue(t, findings, code)
	}
	for _, finding := range findings {
		if strings.Contains(finding.Message, "secret-token") {
			t.Fatalf("legacy finding leaked raw value: %#v", finding)
		}
	}
}
