package protocol_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/GoCodeAlone/workflow-plugin-compute-core/protocol"
)

type stubServiceSessionProvider struct{}

func (stubServiceSessionProvider) Name() string { return "stream-service-session" }

func (stubServiceSessionProvider) Descriptor() protocol.RuntimeDescriptor {
	return protocol.RuntimeDescriptor{Name: "stream-service-session", Version: "test"}
}

func (stubServiceSessionProvider) CanServe(protocol.Task, protocol.Lease) bool { return true }

func (stubServiceSessionProvider) RunService(context.Context, protocol.ServiceRunRequest) (protocol.RuntimeServiceResult, error) {
	return protocol.RuntimeServiceResult{ResponseHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, nil
}

func (stubServiceSessionProvider) StartServiceSession(context.Context, protocol.ServiceRunRequest) (protocol.ServiceSession, error) {
	return stubServiceSession{}, nil
}

type stubServiceSession struct{}

func (stubServiceSession) Health(context.Context) (protocol.RuntimeServiceResult, error) {
	return protocol.RuntimeServiceResult{ResponseHash: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}, nil
}

func (stubServiceSession) Stop(context.Context) (protocol.RuntimeServiceResult, error) {
	return protocol.RuntimeServiceResult{ResponseHash: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}, nil
}

func TestPublicServiceSessionProviderContractCompiles(t *testing.T) {
	t.Parallel()
	var provider protocol.ServiceSessionProvider = stubServiceSessionProvider{}
	req := protocol.ServiceRunRequest{
		Workspace:    "/workspace",
		Env:          map[string]string{"STREAM_ID": "s1"},
		Network:      protocol.NetworkBinding{Mode: protocol.NetworkModeRelay},
		RuntimeScope: protocol.ContainerRuntimeScope{Args: []string{"--network=none"}},
		DataMounts: []protocol.SandboxMount{{
			HostPath:       "/host/data",
			ContainerPath:  "/data",
			ReadOnly:       true,
			RequiredPrefix: "/host",
		}},
	}
	if !provider.CanServe(req.Task, req.Lease) {
		t.Fatalf("expected stub provider to serve")
	}
	session, err := provider.StartServiceSession(context.Background(), req)
	if err != nil {
		t.Fatalf("start service session: %v", err)
	}
	result, err := session.Health(context.Background())
	if err != nil {
		t.Fatalf("health: %v", err)
	}
	if result.ResponseHash == "" {
		t.Fatalf("expected health result to round-trip")
	}
}

func TestServiceRunRequestJSONShape(t *testing.T) {
	t.Parallel()
	req := protocol.ServiceRunRequest{
		Workspace: "/workspace",
		Env:       map[string]string{"STREAM_ID": "s1"},
		Network: protocol.NetworkBinding{
			Mode:            protocol.NetworkModeRelay,
			SandboxNetwork:  "wf-stream-session",
			GatewayEndpoint: "http://127.0.0.1:8080",
		},
		RuntimeScope:    protocol.ContainerRuntimeScope{Args: []string{"--network=none"}},
		HTTPHelperImage: "ghcr.io/gocodealone/http-helper@sha256:" + strings.Repeat("a", 64),
		DataMounts: []protocol.SandboxMount{{
			HostPath:       "/host/data",
			ContainerPath:  "/data",
			ReadOnly:       true,
			RequiredPrefix: "/host",
		}},
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal service run request: %v", err)
	}
	for _, want := range []string{
		`"runtime_scope"`,
		`"http_helper_image"`,
		`"data_mounts"`,
		`"sandbox_network"`,
		`"gateway_endpoint"`,
		`"container_path"`,
		`"required_prefix"`,
	} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("ServiceRunRequest JSON = %s, want %s", data, want)
		}
	}
}
