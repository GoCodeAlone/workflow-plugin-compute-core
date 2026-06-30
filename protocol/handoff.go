package protocol

import (
	"errors"
	"fmt"
	"mime"
	"net/url"
	"path"
	"strings"
	"time"
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
	} else if !validStreamProtocol(h.Protocol) {
		errs = append(errs, fmt.Errorf("protocol %q is unsupported", h.Protocol))
	}
	if strings.TrimSpace(h.AuthTokenRef) == "" {
		errs = append(errs, errors.New("auth_token_ref is required"))
	} else if err := validateScopedRef("auth_token_ref", h.AuthTokenRef, "secret://"); err != nil {
		errs = append(errs, err)
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
	} else if _, err := time.Parse(time.RFC3339, h.ExpiresAt); err != nil {
		errs = append(errs, errors.New("expires_at must be RFC3339"))
	}
	return errors.Join(errs...)
}

type ContentInputRef struct {
	Name        string `json:"name"`
	Ref         string `json:"ref"`
	TargetPath  string `json:"target_path"`
	SHA256      string `json:"sha256,omitempty"`
	ContentType string `json:"content_type,omitempty"`
	SizeBytes   int64  `json:"size_bytes,omitempty"`
	ProviderID  string `json:"provider_id,omitempty"`
}

func (r ContentInputRef) Validate() error {
	var errs []error
	if err := validateIdentifier("name", r.Name); err != nil {
		errs = append(errs, err)
	}
	if err := validateContentInputRef("ref", r.Ref); err != nil {
		errs = append(errs, err)
	}
	if !validRelativeWorkspacePath(r.TargetPath) {
		errs = append(errs, errors.New("target_path must be a relative workspace path"))
	}
	if r.SHA256 != "" && !validSHA256Ref(r.SHA256) {
		errs = append(errs, errors.New("sha256 must be sha256:<64 hex chars>"))
	}
	if r.ContentType != "" {
		if _, _, err := mime.ParseMediaType(r.ContentType); err != nil {
			errs = append(errs, fmt.Errorf("content_type is invalid: %w", err))
		}
	}
	if r.SizeBytes < 0 {
		errs = append(errs, errors.New("size_bytes cannot be negative"))
	}
	if r.ProviderID != "" {
		if err := validateIdentifier("provider_id", r.ProviderID); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

type StreamInputRef struct {
	Name       string       `json:"name"`
	Handle     StreamHandle `json:"handle"`
	ProviderID string       `json:"provider_id,omitempty"`
}

func (r StreamInputRef) Validate() error {
	var errs []error
	if err := validateIdentifier("name", r.Name); err != nil {
		errs = append(errs, err)
	}
	if err := r.Handle.Validate(); err != nil {
		errs = append(errs, fmt.Errorf("handle: %w", err))
	}
	if r.ProviderID != "" {
		if err := validateIdentifier("provider_id", r.ProviderID); err != nil {
			errs = append(errs, err)
		}
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

func validStreamProtocol(protocol string) bool {
	switch protocol {
	case "rtmp", "srt", "whip", "webrtc", "hls", "dash":
		return true
	default:
		return false
	}
}

func validateContentInputRef(name, value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s is required", name)
	}
	if strings.TrimSpace(value) != value {
		return fmt.Errorf("%s must not contain surrounding whitespace", name)
	}
	var scheme string
	for _, candidate := range []string{"content://", "s3://", "gs://", "spaces://"} {
		if strings.HasPrefix(value, candidate) {
			scheme = candidate
			break
		}
	}
	if scheme == "" {
		return fmt.Errorf("%s must use content://, s3://, gs://, or spaces:// scoped ref", name)
	}
	if err := validateScopedRef(name, value, scheme); err != nil {
		return err
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return fmt.Errorf("%s is invalid: %w", name, err)
	}
	if parsed.User != nil {
		return fmt.Errorf("%s must not contain raw credential material", name)
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("%s must not contain query or fragment", name)
	}
	lower := strings.ToLower(value)
	for _, marker := range []string{"access_key=", "secret_key=", "token=", "password=", "credential=", "aws_secret_access_key"} {
		if strings.Contains(lower, marker) {
			return fmt.Errorf("%s must not contain raw credential material", name)
		}
	}
	return nil
}

func validRelativeWorkspacePath(value string) bool {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" || trimmed != value || strings.HasPrefix(trimmed, "/") || strings.Contains(trimmed, "\\") || strings.Contains(trimmed, "\x00") {
		return false
	}
	clean := path.Clean(trimmed)
	return clean != "." && clean != ".." && !strings.HasPrefix(clean, "../")
}
