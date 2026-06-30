package protocol

import (
	"errors"
	"fmt"
	"time"
)

// SegmentProvenance describes how a segment's integrity was established.
type SegmentProvenance string

const (
	// ProvenanceHostVerified means the host measured and verified the segment.
	ProvenanceHostVerified SegmentProvenance = "host-verified"
	// ProvenanceAttested means the segment hash was provided by the worker and
	// attested rather than independently measured.
	ProvenanceAttested SegmentProvenance = "attested"
)

// DeliveryConsumerKind distinguishes the type of consumer receiving segments.
type DeliveryConsumerKind string

const (
	// ConsumerViewer is an end-viewer consuming the stream.
	ConsumerViewer DeliveryConsumerKind = "viewer"
	// ConsumerEdgeRelay is an edge relay re-distributing the stream.
	ConsumerEdgeRelay DeliveryConsumerKind = "edge-relay"
)

// Segment describes a single contiguous segment of a live stream.
type Segment struct {
	Index      int               `json:"index"`
	DurationMS int64             `json:"duration_ms"`
	Bytes      int64             `json:"bytes"`
	SHA256     string            `json:"sha256"`
	Provenance SegmentProvenance `json:"provenance"`
}

// SampledFrame is a spot-check frame hash used for content authenticity.
type SampledFrame struct {
	PTS    int64  `json:"pts"`
	SHA256 string `json:"sha256"`
}

// LivenessNonce is issued by the host and must appear in the manifest within a
// reflection window, proving the stream is live and not a replay.
type LivenessNonce struct {
	Nonce          string    `json:"nonce"`
	IssuedAt       time.Time `json:"issued_at"`
	ReflectedInSeq int       `json:"reflected_in_seq"`
}

// DeliveryReceipt records that a consumer received a segment range.
// For cross-checking, SHA256 must equal the SHA256 of the referenced segment
// when the receipt covers exactly one segment (SeqStart == SeqEnd).
type DeliveryReceipt struct {
	ConsumerID string               `json:"consumer_id"`
	Kind       DeliveryConsumerKind `json:"kind"`
	SeqStart   int                  `json:"seq_start"`
	SeqEnd     int                  `json:"seq_end"`
	Bytes      int64                `json:"bytes"`
	// SHA256 is the hash of the delivered segment range; for single-segment
	// receipts (SeqStart == SeqEnd) it must equal the segment's SHA256.
	SHA256 string `json:"sha256"`
	// Sig is an opaque signature over this receipt; verification of the
	// cryptographic signature itself is wired by the host layer.
	Sig []byte `json:"sig,omitempty"`
}

// Discontinuity marks an intentional gap in segment continuity (e.g. network drop).
// A gap between PrevSeq and ResumeSeq is considered covered if a Discontinuity
// with matching PrevSeq and ResumeSeq exists in the manifest.
// Sig is an opaque signature over this marker; verification of the cryptographic
// signature itself is wired by the host layer.
type Discontinuity struct {
	At        time.Time `json:"at"`
	Reason    string    `json:"reason"`
	PrevSeq   int       `json:"prev_seq"`
	ResumeSeq int       `json:"resume_seq"`
	Sig       []byte    `json:"sig,omitempty"`
}

// StreamManifest is the evidence payload attached to a streaming task receipt.
// It collects segments, liveness proofs, delivery receipts, and discontinuity
// markers for a single manifest window (identified by Seq).
//
// Field naming note: WorkerReportedDeliveredBytes carries the advisory byte count
// as reported by the worker (json: "worker_reported_delivered_bytes"). It is
// worker-supplied and MUST NOT be used for billing. Use VerifiedDeliveredBytes()
// for the authoritative cross-checked figure.
type StreamManifest struct {
	Seq       int       `json:"seq"`
	StreamID  string    `json:"stream_id"`
	StartedAt time.Time `json:"started_at"`

	LivenessNonces []LivenessNonce `json:"liveness_nonces,omitempty"`
	Segments       []Segment       `json:"segments,omitempty"`
	SampledFrames  []SampledFrame  `json:"sampled_frames,omitempty"`

	DeliveryReceipts []DeliveryReceipt `json:"delivery_receipts,omitempty"`

	// WorkerReportedDeliveredBytes is the advisory byte count as reported by the
	// worker. It is worker-supplied and MUST NOT be used for billing; callers
	// must use VerifiedDeliveredBytes() instead.
	WorkerReportedDeliveredBytes int64 `json:"worker_reported_delivered_bytes,omitempty"`

	// AttestedPushedBytesByDestination is a typed map from destination ref to
	// pushed byte count, as attested by the worker.
	AttestedPushedBytesByDestination map[string]int64 `json:"attested_pushed_bytes_by_destination,omitempty"`

	Discontinuities []Discontinuity `json:"discontinuities,omitempty"`
	DroppedFrames   int64           `json:"dropped_frames,omitempty"`

	// Sig is an opaque signature over this manifest; verification of the
	// cryptographic signature itself is wired by the host layer.
	Sig []byte `json:"sig,omitempty"`
}

// VerifiedDeliveredBytes returns the authoritative cross-checked byte count:
// the sum of host-verified segment Bytes for delivery receipts that (a) cover
// exactly one segment (SeqStart == SeqEnd), (b) whose SHA256 matches that
// segment's SHA256, and (c) whose segment has ProvenanceHostVerified.
//
// The segment's Bytes field (not the receipt's Bytes claim) is credited, so a
// worker cannot inflate the total by submitting an oversized Bytes value on a
// receipt whose SHA256 was copied from the public manifest.
//
// This is the canonical figure for billing and SLA calculations. The advisory
// WorkerReportedDeliveredBytes field on StreamManifest is worker-supplied and
// MUST NOT be used for billing.
func (m StreamManifest) VerifiedDeliveredBytes() int64 {
	idx := make(map[int]Segment, len(m.Segments))
	for _, s := range m.Segments {
		idx[s.Index] = s
	}
	var total int64
	for _, r := range m.DeliveryReceipts {
		if r.SeqStart != r.SeqEnd {
			continue
		}
		seg, ok := idx[r.SeqStart]
		if !ok {
			continue
		}
		if seg.Provenance != ProvenanceHostVerified {
			continue
		}
		if seg.SHA256 != r.SHA256 {
			continue
		}
		total += seg.Bytes // credit host-verified segment bytes, never the worker's claim
	}
	return total
}

// StreamReceipt is a periodic signed wrapper carrying a StreamManifest.
// Identity fields mirror ServiceReceipt conventions.
type StreamReceipt struct {
	ID             string         `json:"id"`
	OrgID          string         `json:"org_id"`
	TaskID         string         `json:"task_id"`
	ServiceLeaseID string         `json:"service_lease_id,omitempty"`
	WorkerID       string         `json:"worker_id"`
	PoolID         string         `json:"pool_id,omitempty"`
	PolicyID       string         `json:"policy_id,omitempty"`
	Manifest       StreamManifest `json:"manifest"`
	// Sig is an opaque signature over this receipt; real verification is
	// handled by the host layer.
	Sig []byte `json:"sig,omitempty"`
}

// Validate returns an error if the StreamReceipt is not well-formed.
func (r StreamReceipt) Validate() error {
	var errs []error
	if r.TaskID == "" {
		errs = append(errs, errors.New("task_id is required"))
	}
	if r.WorkerID == "" {
		errs = append(errs, errors.New("worker_id is required"))
	}
	if r.Manifest.StreamID == "" {
		errs = append(errs, errors.New("manifest.stream_id is required"))
	}
	if len(r.Manifest.Segments) == 0 {
		errs = append(errs, errors.New("manifest must contain at least one segment"))
	}
	return errors.Join(errs...)
}

// VerifyManifest performs content verification of a StreamManifest:
//
//  1. Segments must be present and Index values strictly increasing (monotonic).
//  2. Each LivenessNonce in the manifest must match an entry in issuedNonces by
//     Nonce value; ReflectedInSeq must reference an existing segment index; the
//     estimated reflection time (manifest.StartedAt + cumulative DurationMS
//     through the referenced segment) must be within reflectWindow of IssuedAt.
//     Note: liveness-nonce *presence* enforcement (ensuring every issued nonce
//     actually appears in the manifest) is the host layer's responsibility;
//     issuedNonces here is treated as a lookup registry, not an exhaustive list.
//  3. Each DeliveryReceipt must cover exactly one segment (SeqStart == SeqEnd);
//     range receipts (SeqStart != SeqEnd) are not supported in v1 and cause an
//     error. Single-segment receipts must have a SHA256 equal to that segment's.
//  4. Segment Index continuity: a gap is permitted only if a Discontinuity
//     marker whose PrevSeq/ResumeSeq bracket it exists; an unmarked gap is an
//     error.
//
// All discovered problems are collected and returned via errors.Join.
func VerifyManifest(m StreamManifest, issuedNonces []LivenessNonce, reflectWindow time.Duration) error {
	var errs []error

	// 1. Segments: must be non-empty and strictly increasing.
	if len(m.Segments) == 0 {
		return errors.New("manifest contains no segments")
	}

	// Build a map from index → segment and validate monotonicity + gaps.
	segByIndex := make(map[int]Segment, len(m.Segments))
	for i, s := range m.Segments {
		if i > 0 && s.Index <= m.Segments[i-1].Index {
			errs = append(errs, fmt.Errorf("segment[%d]: index %d is not strictly greater than previous index %d",
				i, s.Index, m.Segments[i-1].Index))
		}
		segByIndex[s.Index] = s
	}

	// 4. Check index continuity; gaps must be covered by a Discontinuity.
	for i := 1; i < len(m.Segments); i++ {
		prev := m.Segments[i-1].Index
		cur := m.Segments[i].Index
		if cur == prev+1 {
			continue
		}
		// Gap: prev..cur. Verify a Discontinuity covers it.
		if !gapCovered(prev, cur, m.Discontinuities) {
			errs = append(errs, fmt.Errorf("unmarked sequence gap between segment index %d and %d", prev, cur))
		}
	}

	// Build cumulative duration map for reflection-time estimation.
	// cumDuration[i] = sum of DurationMS for segments[0..i] (inclusive).
	cumDuration := make([]time.Duration, len(m.Segments))
	cumDuration[0] = time.Duration(m.Segments[0].DurationMS) * time.Millisecond
	for i := 1; i < len(m.Segments); i++ {
		cumDuration[i] = cumDuration[i-1] + time.Duration(m.Segments[i].DurationMS)*time.Millisecond
	}
	// segPosition maps a segment Index to its position (0-based) in the slice.
	segPosition := make(map[int]int, len(m.Segments))
	for pos, s := range m.Segments {
		segPosition[s.Index] = pos
	}

	// 2. Liveness nonce checks.
	issuedByNonce := make(map[string]LivenessNonce, len(issuedNonces))
	for _, n := range issuedNonces {
		issuedByNonce[n.Nonce] = n
	}
	for _, n := range m.LivenessNonces {
		issued, known := issuedByNonce[n.Nonce]
		if !known {
			errs = append(errs, fmt.Errorf("liveness nonce %q not found in issued nonces", n.Nonce))
			continue
		}
		pos, hasSeg := segPosition[n.ReflectedInSeq]
		if !hasSeg {
			errs = append(errs, fmt.Errorf("liveness nonce %q reflects segment index %d which does not exist",
				n.Nonce, n.ReflectedInSeq))
			continue
		}
		// Reflection time = end of the referenced segment.
		reflectionTime := m.StartedAt.Add(cumDuration[pos])
		diff := reflectionTime.Sub(issued.IssuedAt)
		if diff < 0 {
			diff = -diff
		}
		if diff > reflectWindow {
			errs = append(errs, fmt.Errorf(
				"liveness nonce %q: reflection time %v is outside window (%v) of issued time %v (diff=%v)",
				n.Nonce, reflectionTime, reflectWindow, issued.IssuedAt, diff))
		}
	}

	// 3. Delivery receipt SHA256 cross-check; range receipts are not supported in v1.
	for i, r := range m.DeliveryReceipts {
		if r.SeqStart != r.SeqEnd {
			errs = append(errs, fmt.Errorf(
				"delivery_receipt[%d]: range receipts (SeqStart=%d, SeqEnd=%d) are not supported in v1",
				i, r.SeqStart, r.SeqEnd))
			continue
		}
		seg, ok := segByIndex[r.SeqStart]
		if !ok {
			errs = append(errs, fmt.Errorf("delivery_receipt[%d]: references segment index %d which does not exist",
				i, r.SeqStart))
			continue
		}
		if seg.SHA256 != r.SHA256 {
			errs = append(errs, fmt.Errorf(
				"delivery_receipt[%d]: SHA256 %q does not match segment %d SHA256 %q",
				i, r.SHA256, r.SeqStart, seg.SHA256))
		}
	}

	return errors.Join(errs...)
}

// gapCovered returns true if at least one Discontinuity marker's PrevSeq and
// ResumeSeq bracket the gap between prevIdx and curIdx (i.e. PrevSeq == prevIdx
// and ResumeSeq == curIdx).
func gapCovered(prevIdx, curIdx int, discontinuities []Discontinuity) bool {
	for _, d := range discontinuities {
		if d.PrevSeq == prevIdx && d.ResumeSeq == curIdx {
			return true
		}
	}
	return false
}
