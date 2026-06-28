package protocol_test

import (
	"testing"

	"github.com/GoCodeAlone/workflow-plugin-compute-core/protocol"
)

func TestStreamSpecEmptyIngestProtocolsErrors(t *testing.T) {
	s := protocol.StreamSpec{}
	if err := s.Validate(); err == nil {
		t.Fatal("expected error for empty StreamSpec, got nil")
	}
}

func TestStreamSpecMissingTargetRefErrors(t *testing.T) {
	s := protocol.StreamSpec{
		IngestProtocols: []string{"rtmp"},
		Destinations:    []protocol.StreamDestination{{TargetRef: ""}},
	}
	if err := s.Validate(); err == nil {
		t.Fatal("expected error for destination with empty TargetRef, got nil")
	}
}

func TestStreamSpecValidPasses(t *testing.T) {
	s := protocol.StreamSpec{
		IngestProtocols: []string{"rtmp", "srt"},
		Destinations: []protocol.StreamDestination{
			{TargetRef: "stream://live/channel-1"},
		},
		ViewerEgress: protocol.ViewerEgressConfig{HLS: true},
		Recording:    true,
	}
	if err := s.Validate(); err != nil {
		t.Fatalf("expected valid StreamSpec to pass, got: %v", err)
	}
}

func TestStreamSpecInvalidNestedTransformErrors(t *testing.T) {
	s := protocol.StreamSpec{
		IngestProtocols: []string{"rtmp"},
		Destinations: []protocol.StreamDestination{
			{TargetRef: "stream://live/channel-3", Transform: &protocol.MediaTransformSpec{FPS: -1}},
		},
	}
	if err := s.Validate(); err == nil {
		t.Fatal("expected error for destination with invalid nested transform, got nil")
	}
}

func TestStreamSpecValidWithTransformPasses(t *testing.T) {
	s := protocol.StreamSpec{
		IngestProtocols: []string{"whip"},
		Destinations: []protocol.StreamDestination{
			{
				TargetRef: "stream://live/channel-2",
				Transform: &protocol.MediaTransformSpec{Scale: "1080p", Codec: "h264"},
			},
		},
	}
	if err := s.Validate(); err != nil {
		t.Fatalf("expected valid StreamSpec with transform to pass, got: %v", err)
	}
}
