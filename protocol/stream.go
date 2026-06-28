package protocol

import (
	"errors"
	"fmt"
)

// StreamDestination describes a single output target for a live stream.
type StreamDestination struct {
	TargetRef string              `json:"target_ref"`
	Transform *MediaTransformSpec `json:"transform,omitempty"`
	Rendition string              `json:"rendition,omitempty"`
}

// ViewerEgressConfig controls viewer-facing delivery protocols.
type ViewerEgressConfig struct {
	HLS  bool `json:"hls,omitempty"`
	WHEP bool `json:"whep,omitempty"`
}

// StreamSpec defines a live video-stream workload.
type StreamSpec struct {
	IngestProtocols []string            `json:"ingest_protocols"`
	Destinations    []StreamDestination `json:"destinations,omitempty"`
	ViewerEgress    ViewerEgressConfig  `json:"viewer_egress,omitempty"`
	Recording       bool                `json:"recording,omitempty"`
	RedundancyTier  string              `json:"redundancy_tier,omitempty"`
}

// Validate returns an error if the StreamSpec is not well-formed.
func (s StreamSpec) Validate() error {
	var errs []error
	if len(s.IngestProtocols) == 0 {
		errs = append(errs, errors.New("ingest_protocols must not be empty"))
	}
	for i, d := range s.Destinations {
		if d.TargetRef == "" {
			errs = append(errs, fmt.Errorf("destinations[%d]: target_ref is required", i))
		}
		if d.Transform != nil {
			if err := d.Transform.Validate(); err != nil {
				errs = append(errs, fmt.Errorf("destinations[%d].transform: %w", i, err))
			}
		}
	}
	return errors.Join(errs...)
}
