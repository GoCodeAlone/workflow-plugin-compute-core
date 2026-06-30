package protocol

import "errors"

// Rendition describes a single output variant in a transcoding ladder.
type Rendition struct {
	Name        string `json:"name"`
	Scale       string `json:"scale,omitempty"`
	BitrateKbps int    `json:"bitrate_kbps,omitempty"`
}

// MediaTransformSpec defines a media-transform workload.
type MediaTransformSpec struct {
	Scale       string      `json:"scale,omitempty"`
	Crop        string      `json:"crop,omitempty"`
	Pan         string      `json:"pan,omitempty"`
	FPS         int         `json:"fps,omitempty"`
	Codec       string      `json:"codec,omitempty"`
	Container   string      `json:"container,omitempty"`
	BitrateKbps int         `json:"bitrate_kbps,omitempty"`
	Renditions  []Rendition `json:"renditions,omitempty"`
}

// Validate returns an error if the MediaTransformSpec is not well-formed.
func (m MediaTransformSpec) Validate() error {
	var errs []error
	if m.FPS < 0 {
		errs = append(errs, errors.New("fps cannot be negative"))
	}
	if m.BitrateKbps < 0 {
		errs = append(errs, errors.New("bitrate_kbps cannot be negative"))
	}
	for _, r := range m.Renditions {
		if r.Name == "" {
			errs = append(errs, errors.New("rendition name is required"))
		}
		if r.BitrateKbps < 0 {
			errs = append(errs, errors.New("rendition bitrate_kbps cannot be negative"))
		}
	}
	return errors.Join(errs...)
}
