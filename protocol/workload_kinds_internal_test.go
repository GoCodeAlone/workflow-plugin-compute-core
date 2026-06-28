package protocol

import "testing"

// Internal test: validWorkloadKind is unexported, so this lives in package
// protocol (matching the package-protocol test precedent in this repo) rather
// than forcing a test-only exported wrapper.
func TestValidWorkloadKindAcceptsVideoKinds(t *testing.T) {
	for _, kind := range []WorkloadKind{WorkloadVideoStream, WorkloadMediaTransform} {
		if !validWorkloadKind(kind) {
			t.Fatalf("validWorkloadKind(%q) = false, want true", kind)
		}
	}
}

func TestVideoWorkloadKindValues(t *testing.T) {
	if WorkloadVideoStream != "video-stream" {
		t.Fatalf("WorkloadVideoStream = %q, want %q", WorkloadVideoStream, "video-stream")
	}
	if WorkloadMediaTransform != "media-transform" {
		t.Fatalf("WorkloadMediaTransform = %q, want %q", WorkloadMediaTransform, "media-transform")
	}
}
