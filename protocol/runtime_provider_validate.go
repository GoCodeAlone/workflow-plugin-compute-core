package protocol

import (
	"errors"
	"strings"

	pb "github.com/GoCodeAlone/workflow-plugin-compute-core/protocol/pb"
)

// ValidateRunRequest validates the wire fields of a RunRequest.
// Input and Env are optional; ExecutorProvider is required.
func ValidateRunRequest(r *pb.RunRequest) error {
	if r == nil {
		return errors.New("run_request is required")
	}
	var errs []error
	if strings.TrimSpace(r.ExecutorProvider) == "" {
		errs = append(errs, errors.New("executor_provider is required"))
	}
	return errors.Join(errs...)
}

// ValidateStartSessionRequest validates the wire fields of a StartSessionRequest.
// Input and Env are optional; ExecutorProvider is required.
func ValidateStartSessionRequest(r *pb.StartSessionRequest) error {
	if r == nil {
		return errors.New("start_session_request is required")
	}
	var errs []error
	if strings.TrimSpace(r.ExecutorProvider) == "" {
		errs = append(errs, errors.New("executor_provider is required"))
	}
	return errors.Join(errs...)
}

// ValidateProviderCapabilities validates the wire fields of a ProviderCapabilities.
// ProviderId is required; ExecutorProviders must contain at least one entry.
func ValidateProviderCapabilities(c *pb.ProviderCapabilities) error {
	if c == nil {
		return errors.New("provider_capabilities is required")
	}
	var errs []error
	if strings.TrimSpace(c.ProviderId) == "" {
		errs = append(errs, errors.New("provider_id is required"))
	}
	if len(c.ExecutorProviders) == 0 {
		errs = append(errs, errors.New("executor_providers must contain at least one entry"))
	} else {
		hasNonBlank := false
		for _, p := range c.ExecutorProviders {
			if strings.TrimSpace(p) != "" {
				hasNonBlank = true
				break
			}
		}
		if !hasNonBlank {
			errs = append(errs, errors.New("executor_providers must contain at least one non-blank entry"))
		}
	}
	return errors.Join(errs...)
}

// ValidateSessionEvent validates the wire fields of a SessionEvent.
// EventType is required. Evidence is unsigned at this layer and host-signed later;
// no crypto validation is performed here.
func ValidateSessionEvent(e *pb.SessionEvent) error {
	if e == nil {
		return errors.New("session_event is required")
	}
	var errs []error
	if strings.TrimSpace(e.EventType) == "" {
		errs = append(errs, errors.New("event_type is required"))
	}
	return errors.Join(errs...)
}

// ValidateControlSessionRequest validates the wire fields of a ControlSessionRequest.
// Both SessionId and Action are required.
func ValidateControlSessionRequest(r *pb.ControlSessionRequest) error {
	if r == nil {
		return errors.New("control_session_request is required")
	}
	var errs []error
	if strings.TrimSpace(r.SessionId) == "" {
		errs = append(errs, errors.New("session_id is required"))
	}
	if strings.TrimSpace(r.Action) == "" {
		errs = append(errs, errors.New("action is required"))
	}
	return errors.Join(errs...)
}
