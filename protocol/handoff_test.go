package protocol_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/GoCodeAlone/workflow-plugin-compute-core/protocol"
)

func TestStreamHandleValidate(t *testing.T) {
	t.Parallel()
	valid := protocol.StreamHandle{
		URL:          "rtmp://stream.example/live/session-1",
		Protocol:     "rtmp",
		AuthTokenRef: "secret://stream/session-1/publish-token",
		Codecs:       []string{"h264", "aac"},
		ExpiresAt:    "2026-06-30T08:00:00Z",
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid stream handle: %v", err)
	}
	for name, mutate := range map[string]func(*protocol.StreamHandle){
		"missing url":      func(h *protocol.StreamHandle) { h.URL = "" },
		"missing protocol": func(h *protocol.StreamHandle) { h.Protocol = "" },
		"missing token":    func(h *protocol.StreamHandle) { h.AuthTokenRef = "" },
		"missing codecs":   func(h *protocol.StreamHandle) { h.Codecs = nil },
		"missing expiry":   func(h *protocol.StreamHandle) { h.ExpiresAt = "" },
	} {
		t.Run(name, func(t *testing.T) {
			h := valid
			mutate(&h)
			if err := h.Validate(); err == nil {
				t.Fatalf("expected invalid stream handle")
			}
		})
	}
}

func TestContentInputRefValidate(t *testing.T) {
	t.Parallel()
	valid := protocol.ContentInputRef{
		Name:        "source-video",
		Ref:         "s3://media-bucket/input.mov",
		TargetPath:  "inputs/source.mov",
		SHA256:      "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ContentType: "video/quicktime",
		SizeBytes:   42,
		ProviderID:  "workflow-plugin-aws",
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid content input ref: %v", err)
	}
	for name, mutate := range map[string]func(*protocol.ContentInputRef){
		"missing name":       func(r *protocol.ContentInputRef) { r.Name = "" },
		"bad ref scheme":     func(r *protocol.ContentInputRef) { r.Ref = "https://example.invalid/input.mov" },
		"raw credential ref": func(r *protocol.ContentInputRef) { r.Ref = "s3://AKIASECRET:pw@media-bucket/input.mov" },
		"unsafe target path": func(r *protocol.ContentInputRef) { r.TargetPath = "../input.mov" },
		"bad sha":            func(r *protocol.ContentInputRef) { r.SHA256 = "sha256:not-hex" },
		"negative size":      func(r *protocol.ContentInputRef) { r.SizeBytes = -1 },
		"bad provider id":    func(r *protocol.ContentInputRef) { r.ProviderID = "aws/plugin" },
	} {
		t.Run(name, func(t *testing.T) {
			ref := valid
			mutate(&ref)
			if err := ref.Validate(); err == nil {
				t.Fatalf("expected invalid content input ref")
			}
		})
	}
	for _, ref := range []string{
		"content://media/source.mov",
		"s3://media-bucket/input.mov",
		"gs://media-bucket/input.mov",
		"spaces://media-bucket/input.mov",
	} {
		candidate := valid
		candidate.Ref = ref
		if err := candidate.Validate(); err != nil {
			t.Fatalf("ref %q rejected: %v", ref, err)
		}
	}
}

func TestContentInputRefReportsPreciseMalformedRefReasons(t *testing.T) {
	ref := protocol.ContentInputRef{
		Name:        "source-video",
		Ref:         " s3://media-bucket/input.mov ",
		TargetPath:  "inputs/source.mov",
		ContentType: "video/quicktime",
		ProviderID:  "workflow-plugin-aws",
	}
	err := ref.Validate()
	if err == nil || !strings.Contains(err.Error(), "surrounding whitespace") {
		t.Fatalf("whitespace ref error = %v, want surrounding whitespace", err)
	}

	ref.Ref = "s3://media-bucket/input.mov?version=1"
	err = ref.Validate()
	if err == nil || !strings.Contains(err.Error(), "query or fragment") {
		t.Fatalf("query ref error = %v, want query or fragment", err)
	}
}

func TestStreamInputRefValidate(t *testing.T) {
	t.Parallel()
	valid := protocol.StreamInputRef{
		Name: "live-main",
		Handle: protocol.StreamHandle{
			URL:          "rtmp://stream.example/live/session-1",
			Protocol:     "rtmp",
			AuthTokenRef: "secret://stream/session-1/read-token",
			Codecs:       []string{"h264", "aac"},
			ExpiresAt:    "2026-06-30T08:00:00Z",
		},
		ProviderID: "workflow-plugin-stream",
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid stream input ref: %v", err)
	}
	for name, mutate := range map[string]func(*protocol.StreamInputRef){
		"missing name":    func(r *protocol.StreamInputRef) { r.Name = "" },
		"bad protocol":    func(r *protocol.StreamInputRef) { r.Handle.Protocol = "ftp" },
		"bad token ref":   func(r *protocol.StreamInputRef) { r.Handle.AuthTokenRef = "raw-token" },
		"missing codec":   func(r *protocol.StreamInputRef) { r.Handle.Codecs = []string{"h264", ""} },
		"bad expiry":      func(r *protocol.StreamInputRef) { r.Handle.ExpiresAt = "tomorrow" },
		"bad provider id": func(r *protocol.StreamInputRef) { r.ProviderID = "stream/plugin" },
	} {
		t.Run(name, func(t *testing.T) {
			ref := valid
			mutate(&ref)
			if err := ref.Validate(); err == nil {
				t.Fatalf("expected invalid stream input ref")
			}
		})
	}
}

func TestForwardableArtifactRefValidate(t *testing.T) {
	t.Parallel()
	valid := protocol.ForwardableArtifactRef{
		Handle:           "artifact://task-1/output.ts",
		Digest:           "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ContentType:      "video/mp2t",
		TransferTokenRef: "secret://transfer/task-1/output",
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid artifact ref: %v", err)
	}
	for name, mutate := range map[string]func(*protocol.ForwardableArtifactRef){
		"missing handle":       func(r *protocol.ForwardableArtifactRef) { r.Handle = "" },
		"bad digest":           func(r *protocol.ForwardableArtifactRef) { r.Digest = "sha256:not-hex" },
		"missing content type": func(r *protocol.ForwardableArtifactRef) { r.ContentType = "" },
		"missing token":        func(r *protocol.ForwardableArtifactRef) { r.TransferTokenRef = "" },
	} {
		t.Run(name, func(t *testing.T) {
			ref := valid
			mutate(&ref)
			if err := ref.Validate(); err == nil {
				t.Fatalf("expected invalid artifact ref")
			}
		})
	}
}

func TestRedundancyPolicyValidate(t *testing.T) {
	t.Parallel()
	if err := (protocol.RedundancyPolicy{Tier: protocol.RedundancyNone}).Validate(); err != nil {
		t.Fatalf("none policy: %v", err)
	}
	if err := (protocol.RedundancyPolicy{Tier: protocol.RedundancyWarmStandby, StandbyCount: 1, CutoverDeadlineMS: 500}).Validate(); err != nil {
		t.Fatalf("warm standby policy: %v", err)
	}
	if err := (protocol.RedundancyPolicy{Tier: protocol.RedundancyWarmStandby}).Validate(); err == nil {
		t.Fatalf("expected warm standby without standby count to fail")
	}
	err := (protocol.RedundancyPolicy{Tier: protocol.RedundancyActiveActive, StandbyCount: 2, CutoverDeadlineMS: 100}).Validate()
	if !errors.Is(err, protocol.ErrRedundancyTierNotEnabledV1) {
		t.Fatalf("active-active error = %v, want ErrRedundancyTierNotEnabledV1", err)
	}
}

func TestServiceSessionRuntimeAdapterValidationAllowsVideoStream(t *testing.T) {
	t.Parallel()
	contract := protocol.RuntimeAdapterContract{
		ProtocolVersion: protocol.Version,
		AdapterID:       "stream-service-session",
		Descriptor: protocol.RuntimeDescriptor{
			Name:                  "stream-service-session",
			Version:               "v0.1.0",
			ExecutionSecurityTier: protocol.ExecutionSandboxedContainer,
			ProofTier:             protocol.ProofStreamSegmentManifest,
			ImageDigest:           "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			RootFSDigest:          "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		},
		Kinds:               []protocol.RuntimeAdapterKind{protocol.RuntimeAdapterServiceSession},
		WorkloadKinds:       []protocol.WorkloadKind{protocol.WorkloadVideoStream},
		RuntimeProfiles:     []protocol.RuntimeProfile{protocol.RuntimeProfileServiceOCI},
		WorkspacePolicy:     protocol.RuntimeWorkspaceRequired,
		ConformanceProfiles: []string{"service-session-v1"},
		ResiduePolicy: protocol.ResiduePolicy{
			Mode:       protocol.ResidueModeSessionBound,
			SessionKey: "stream-session",
			PolicyHash: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		},
	}
	if err := contract.Validate(); err != nil {
		t.Fatalf("service-session video-stream contract should validate: %v", err)
	}
	contract.Kinds = []protocol.RuntimeAdapterKind{protocol.RuntimeAdapterServiceRun}
	if err := contract.Validate(); err == nil {
		t.Fatalf("service-run contract should still reject video-stream without service/node-service")
	}
}
