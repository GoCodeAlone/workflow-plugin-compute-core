package protocol

import (
	"errors"
	"fmt"
	"strings"
)

var ErrRedundancyTierNotEnabledV1 = errors.New("redundancy tier is not enabled in v1")

type StreamHandle struct {
	URL          string   `json:"url"`
	Protocol     string   `json:"protocol"`
	AuthTokenRef string   `json:"auth_token_ref"`
	Codecs       []string `json:"codecs"`
	ExpiresAt    string   `json:"expires_at"`
}

func (h StreamHandle) Validate() error {
	var errs []error
	if strings.TrimSpace(h.URL) == "" {
		errs = append(errs, errors.New("url is required"))
	}
	if strings.TrimSpace(h.Protocol) == "" {
		errs = append(errs, errors.New("protocol is required"))
	}
	if strings.TrimSpace(h.AuthTokenRef) == "" {
		errs = append(errs, errors.New("auth_token_ref is required"))
	}
	if len(h.Codecs) == 0 {
		errs = append(errs, errors.New("codecs is required"))
	}
	for i, codec := range h.Codecs {
		if strings.TrimSpace(codec) == "" {
			errs = append(errs, fmt.Errorf("codecs[%d] is required", i))
		}
	}
	if strings.TrimSpace(h.ExpiresAt) == "" {
		errs = append(errs, errors.New("expires_at is required"))
	}
	return errors.Join(errs...)
}

type ForwardableArtifactRef struct {
	Handle           string `json:"handle"`
	Digest           string `json:"digest"`
	ContentType      string `json:"content_type"`
	TransferTokenRef string `json:"transfer_token_ref"`
}

func (r ForwardableArtifactRef) Validate() error {
	var errs []error
	if strings.TrimSpace(r.Handle) == "" {
		errs = append(errs, errors.New("handle is required"))
	}
	if !validSHA256Ref(r.Digest) {
		errs = append(errs, errors.New("digest must be sha256:<64 hex chars>"))
	}
	if strings.TrimSpace(r.ContentType) == "" {
		errs = append(errs, errors.New("content_type is required"))
	}
	if strings.TrimSpace(r.TransferTokenRef) == "" {
		errs = append(errs, errors.New("transfer_token_ref is required"))
	}
	return errors.Join(errs...)
}

type RedundancyTier string

const (
	RedundancyNone         RedundancyTier = "none"
	RedundancyWarmStandby  RedundancyTier = "warm-standby"
	RedundancyActiveActive RedundancyTier = "active-active"
)

type RedundancyPolicy struct {
	Tier              RedundancyTier `json:"tier"`
	StandbyCount      int            `json:"standby_count,omitempty"`
	CutoverDeadlineMS int            `json:"cutover_deadline_ms,omitempty"`
}

func (p RedundancyPolicy) Validate() error {
	switch p.Tier {
	case "", RedundancyNone:
		return nil
	case RedundancyWarmStandby:
		var errs []error
		if p.StandbyCount <= 0 {
			errs = append(errs, errors.New("standby_count must be positive for warm-standby"))
		}
		if p.CutoverDeadlineMS < 0 {
			errs = append(errs, errors.New("cutover_deadline_ms cannot be negative"))
		}
		return errors.Join(errs...)
	case RedundancyActiveActive:
		return ErrRedundancyTierNotEnabledV1
	default:
		return fmt.Errorf("tier %q is unsupported", p.Tier)
	}
}
