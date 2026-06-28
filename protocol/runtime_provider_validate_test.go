package protocol_test

import (
	"testing"

	"github.com/GoCodeAlone/workflow-plugin-compute-core/protocol"
	pb "github.com/GoCodeAlone/workflow-plugin-compute-core/protocol/pb"
)

// TestValidateRunRequest covers nil, empty ExecutorProvider, and valid input.
func TestValidateRunRequest(t *testing.T) {
	t.Run("nil errors", func(t *testing.T) {
		if err := protocol.ValidateRunRequest(nil); err == nil {
			t.Fatal("expected error for nil RunRequest")
		}
	})

	t.Run("empty ExecutorProvider errors", func(t *testing.T) {
		r := &pb.RunRequest{ExecutorProvider: ""}
		if err := protocol.ValidateRunRequest(r); err == nil {
			t.Fatal("expected error for empty ExecutorProvider")
		}
	})

	t.Run("whitespace ExecutorProvider errors", func(t *testing.T) {
		r := &pb.RunRequest{ExecutorProvider: "   "}
		if err := protocol.ValidateRunRequest(r); err == nil {
			t.Fatal("expected error for whitespace-only ExecutorProvider")
		}
	})

	t.Run("valid passes", func(t *testing.T) {
		r := &pb.RunRequest{ExecutorProvider: "docker"}
		if err := protocol.ValidateRunRequest(r); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

// TestValidateStartSessionRequest covers nil, empty ExecutorProvider, and valid.
func TestValidateStartSessionRequest(t *testing.T) {
	t.Run("nil errors", func(t *testing.T) {
		if err := protocol.ValidateStartSessionRequest(nil); err == nil {
			t.Fatal("expected error for nil StartSessionRequest")
		}
	})

	t.Run("empty ExecutorProvider errors", func(t *testing.T) {
		r := &pb.StartSessionRequest{ExecutorProvider: ""}
		if err := protocol.ValidateStartSessionRequest(r); err == nil {
			t.Fatal("expected error for empty ExecutorProvider")
		}
	})

	t.Run("whitespace ExecutorProvider errors", func(t *testing.T) {
		r := &pb.StartSessionRequest{ExecutorProvider: "  "}
		if err := protocol.ValidateStartSessionRequest(r); err == nil {
			t.Fatal("expected error for whitespace-only ExecutorProvider")
		}
	})

	t.Run("valid passes", func(t *testing.T) {
		r := &pb.StartSessionRequest{ExecutorProvider: "firecracker"}
		if err := protocol.ValidateStartSessionRequest(r); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

// TestValidateProviderCapabilities covers nil, empty ProviderId, empty ExecutorProviders, and valid.
func TestValidateProviderCapabilities(t *testing.T) {
	t.Run("nil errors", func(t *testing.T) {
		if err := protocol.ValidateProviderCapabilities(nil); err == nil {
			t.Fatal("expected error for nil ProviderCapabilities")
		}
	})

	t.Run("empty ProviderId errors", func(t *testing.T) {
		c := &pb.ProviderCapabilities{
			ProviderId:        "",
			ExecutorProviders: []string{"docker"},
		}
		if err := protocol.ValidateProviderCapabilities(c); err == nil {
			t.Fatal("expected error for empty ProviderId")
		}
	})

	t.Run("empty ExecutorProviders errors", func(t *testing.T) {
		c := &pb.ProviderCapabilities{
			ProviderId:        "my-provider",
			ExecutorProviders: nil,
		}
		if err := protocol.ValidateProviderCapabilities(c); err == nil {
			t.Fatal("expected error for empty ExecutorProviders")
		}
	})

	t.Run("blank-only ExecutorProviders errors", func(t *testing.T) {
		c := &pb.ProviderCapabilities{
			ProviderId:        "my-provider",
			ExecutorProviders: []string{"", "   "},
		}
		if err := protocol.ValidateProviderCapabilities(c); err == nil {
			t.Fatal("expected error for ExecutorProviders with only blank entries")
		}
	})

	t.Run("valid passes", func(t *testing.T) {
		c := &pb.ProviderCapabilities{
			ProviderId:        "my-provider",
			ExecutorProviders: []string{"docker"},
		}
		if err := protocol.ValidateProviderCapabilities(c); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

// TestValidateSessionEvent covers nil, empty EventType, and valid.
func TestValidateSessionEvent(t *testing.T) {
	t.Run("nil errors", func(t *testing.T) {
		if err := protocol.ValidateSessionEvent(nil); err == nil {
			t.Fatal("expected error for nil SessionEvent")
		}
	})

	t.Run("empty EventType errors", func(t *testing.T) {
		e := &pb.SessionEvent{EventType: ""}
		if err := protocol.ValidateSessionEvent(e); err == nil {
			t.Fatal("expected error for empty EventType")
		}
	})

	t.Run("valid passes", func(t *testing.T) {
		e := &pb.SessionEvent{EventType: "output"}
		if err := protocol.ValidateSessionEvent(e); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

// TestValidateControlSessionRequest covers nil, empty SessionId, empty Action, and valid.
func TestValidateControlSessionRequest(t *testing.T) {
	t.Run("nil errors", func(t *testing.T) {
		if err := protocol.ValidateControlSessionRequest(nil); err == nil {
			t.Fatal("expected error for nil ControlSessionRequest")
		}
	})

	t.Run("empty SessionId errors", func(t *testing.T) {
		r := &pb.ControlSessionRequest{SessionId: "", Action: "pause"}
		if err := protocol.ValidateControlSessionRequest(r); err == nil {
			t.Fatal("expected error for empty SessionId")
		}
	})

	t.Run("empty Action errors", func(t *testing.T) {
		r := &pb.ControlSessionRequest{SessionId: "sess-1", Action: ""}
		if err := protocol.ValidateControlSessionRequest(r); err == nil {
			t.Fatal("expected error for empty Action")
		}
	})

	t.Run("valid passes", func(t *testing.T) {
		r := &pb.ControlSessionRequest{SessionId: "sess-1", Action: "pause"}
		if err := protocol.ValidateControlSessionRequest(r); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}
