package pb_test

import (
	"testing"

	"google.golang.org/protobuf/proto"

	pb "github.com/GoCodeAlone/workflow-plugin-compute-core/protocol/pb"
)

// TestRuntimeProviderMessages verifies that all generated message types exist,
// round-trip via proto.Marshal/Unmarshal, and that the oneof on RunEvent works.
// NOTE: There is intentionally NO reference to a CanRun method — the service
// contract does not include it.
func TestRuntimeProviderMessages(t *testing.T) {
	t.Run("RunRequest round-trip", func(t *testing.T) {
		orig := &pb.RunRequest{
			ExecutorProvider: "docker",
			Input:            []byte("echo hello"),
			Env:              map[string]string{"FOO": "bar"},
			TaskId:           "task-1",
			LeaseId:          "lease-1",
		}
		b, err := proto.Marshal(orig)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		got := &pb.RunRequest{}
		if err := proto.Unmarshal(b, got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if got.ExecutorProvider != orig.ExecutorProvider {
			t.Errorf("executor_provider mismatch: got %q want %q", got.ExecutorProvider, orig.ExecutorProvider)
		}
		if got.TaskId != orig.TaskId {
			t.Errorf("task_id mismatch: got %q want %q", got.TaskId, orig.TaskId)
		}
	})

	t.Run("RunResult round-trip", func(t *testing.T) {
		orig := &pb.RunResult{
			ExitCode:     42,
			ArtifactHash: "sha256:abc",
			Artifacts:    []string{"out.tar.gz"},
		}
		b, err := proto.Marshal(orig)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		got := &pb.RunResult{}
		if err := proto.Unmarshal(b, got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if got.ExitCode != orig.ExitCode {
			t.Errorf("exit_code mismatch: got %d want %d", got.ExitCode, orig.ExitCode)
		}
	})

	t.Run("ProviderCapabilities round-trip", func(t *testing.T) {
		orig := &pb.ProviderCapabilities{
			ProviderId:        "compute-local",
			WorkloadKinds:     []string{"container", "wasm"},
			ExecutorProviders: []string{"docker"},
			RuntimeProfiles:   []string{"default"},
		}
		b, err := proto.Marshal(orig)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		got := &pb.ProviderCapabilities{}
		if err := proto.Unmarshal(b, got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if got.ProviderId != orig.ProviderId {
			t.Errorf("provider_id mismatch: got %q want %q", got.ProviderId, orig.ProviderId)
		}
		if len(got.WorkloadKinds) != len(orig.WorkloadKinds) {
			t.Errorf("workload_kinds len mismatch: got %d want %d", len(got.WorkloadKinds), len(orig.WorkloadKinds))
		}
	})

	t.Run("StartSessionRequest round-trip", func(t *testing.T) {
		orig := &pb.StartSessionRequest{
			ExecutorProvider: "docker",
			Input:            []byte("session-input"),
			Env:              map[string]string{"KEY": "val"},
			TaskId:           "t2",
			LeaseId:          "l2",
		}
		b, err := proto.Marshal(orig)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		got := &pb.StartSessionRequest{}
		if err := proto.Unmarshal(b, got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if got.LeaseId != orig.LeaseId {
			t.Errorf("lease_id mismatch: got %q want %q", got.LeaseId, orig.LeaseId)
		}
	})

	t.Run("SessionHandle round-trip", func(t *testing.T) {
		orig := &pb.SessionHandle{SessionId: "sess-abc"}
		b, err := proto.Marshal(orig)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		got := &pb.SessionHandle{}
		if err := proto.Unmarshal(b, got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if got.SessionId != orig.SessionId {
			t.Errorf("session_id mismatch: got %q want %q", got.SessionId, orig.SessionId)
		}
	})

	t.Run("SessionEvent round-trip", func(t *testing.T) {
		orig := &pb.SessionEvent{
			EventType:   "health",
			Evidence:    []byte("sig"),
			TsUnixNanos: 1234567890,
		}
		b, err := proto.Marshal(orig)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		got := &pb.SessionEvent{}
		if err := proto.Unmarshal(b, got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if got.TsUnixNanos != orig.TsUnixNanos {
			t.Errorf("ts_unix_nanos mismatch: got %d want %d", got.TsUnixNanos, orig.TsUnixNanos)
		}
	})

	t.Run("ControlSessionRequest round-trip", func(t *testing.T) {
		orig := &pb.ControlSessionRequest{
			SessionId: "sess-abc",
			Action:    "stop",
			Payload:   []byte("{}"),
		}
		b, err := proto.Marshal(orig)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		got := &pb.ControlSessionRequest{}
		if err := proto.Unmarshal(b, got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if got.Action != orig.Action {
			t.Errorf("action mismatch: got %q want %q", got.Action, orig.Action)
		}
	})

	t.Run("ControlSessionResponse round-trip", func(t *testing.T) {
		orig := &pb.ControlSessionResponse{Healthy: true, Message: "ok"}
		b, err := proto.Marshal(orig)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		got := &pb.ControlSessionResponse{}
		if err := proto.Unmarshal(b, got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if !got.Healthy {
			t.Error("healthy should be true")
		}
	})

	t.Run("RunEvent oneof stdout", func(t *testing.T) {
		ev := &pb.RunEvent{Event: &pb.RunEvent_Stdout{Stdout: []byte("hello\n")}}
		b, err := proto.Marshal(ev)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		got := &pb.RunEvent{}
		if err := proto.Unmarshal(b, got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		stdout, ok := got.Event.(*pb.RunEvent_Stdout)
		if !ok {
			t.Fatalf("expected RunEvent_Stdout oneof, got %T", got.Event)
		}
		if string(stdout.Stdout) != "hello\n" {
			t.Errorf("stdout mismatch: got %q", stdout.Stdout)
		}
	})

	t.Run("RunEvent oneof terminal RunResult", func(t *testing.T) {
		ev := &pb.RunEvent{Event: &pb.RunEvent_Terminal{
			Terminal: &pb.RunResult{ExitCode: 0, ArtifactHash: "sha256:def"},
		}}
		b, err := proto.Marshal(ev)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		got := &pb.RunEvent{}
		if err := proto.Unmarshal(b, got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		term, ok := got.Event.(*pb.RunEvent_Terminal)
		if !ok {
			t.Fatalf("expected RunEvent_Terminal oneof, got %T", got.Event)
		}
		if term.Terminal.ArtifactHash != "sha256:def" {
			t.Errorf("artifact_hash mismatch: got %q", term.Terminal.ArtifactHash)
		}
	})
}

// stub implements RuntimeProviderServiceServer for the compile-time interface check.
type stub struct {
	pb.UnimplementedRuntimeProviderServiceServer
}

// TestRuntimeProviderServiceInterfaces verifies that the gRPC service
// interfaces exist and are properly shaped.
func TestRuntimeProviderServiceInterfaces(t *testing.T) {
	// Compile-time check: stub must satisfy the server interface.
	var _ pb.RuntimeProviderServiceServer = (*stub)(nil)

	// Client constructor must compile with a nil connection.
	_ = pb.NewRuntimeProviderServiceClient(nil)
}

// TestDescribeRequest verifies the empty DescribeRequest message.
func TestDescribeRequest(t *testing.T) {
	orig := &pb.DescribeRequest{}
	b, err := proto.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := &pb.DescribeRequest{}
	if err := proto.Unmarshal(b, got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
}
