package protocol_test

import (
	"testing"

	"github.com/GoCodeAlone/workflow-plugin-compute-core/protocol"
)

func TestMediaTransformSpecNegativeFPSErrors(t *testing.T) {
	m := protocol.MediaTransformSpec{FPS: -1}
	if err := m.Validate(); err == nil {
		t.Fatal("expected error for negative FPS, got nil")
	}
}

func TestMediaTransformSpecNegativeBitrateErrors(t *testing.T) {
	m := protocol.MediaTransformSpec{BitrateKbps: -100}
	if err := m.Validate(); err == nil {
		t.Fatal("expected error for negative BitrateKbps, got nil")
	}
}

func TestMediaTransformSpecRenditionEmptyNameErrors(t *testing.T) {
	m := protocol.MediaTransformSpec{
		Renditions: []protocol.Rendition{{Name: "", Scale: "720p", BitrateKbps: 2000}},
	}
	if err := m.Validate(); err == nil {
		t.Fatal("expected error for Rendition with empty Name, got nil")
	}
}

func TestMediaTransformSpecRenditionNegativeBitrateErrors(t *testing.T) {
	m := protocol.MediaTransformSpec{
		Renditions: []protocol.Rendition{{Name: "hd", BitrateKbps: -1}},
	}
	if err := m.Validate(); err == nil {
		t.Fatal("expected error for Rendition with negative BitrateKbps, got nil")
	}
}

func TestMediaTransformSpecValidPasses(t *testing.T) {
	m := protocol.MediaTransformSpec{
		Scale:       "1080p",
		Codec:       "h264",
		Container:   "mp4",
		FPS:         30,
		BitrateKbps: 4000,
	}
	if err := m.Validate(); err != nil {
		t.Fatalf("expected valid MediaTransformSpec to pass, got: %v", err)
	}
}

func TestMediaTransformSpecWithRenditionsPasses(t *testing.T) {
	m := protocol.MediaTransformSpec{
		Scale: "1080p",
		Renditions: []protocol.Rendition{
			{Name: "hd", Scale: "1080p", BitrateKbps: 4000},
			{Name: "sd", Scale: "480p", BitrateKbps: 1200},
		},
	}
	if err := m.Validate(); err != nil {
		t.Fatalf("expected valid MediaTransformSpec with renditions to pass, got: %v", err)
	}
}
