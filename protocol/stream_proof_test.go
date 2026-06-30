package protocol_test

import (
	"testing"
	"time"

	"github.com/GoCodeAlone/workflow-plugin-compute-core/protocol"
)

func baseSegments() []protocol.Segment {
	return []protocol.Segment{
		{Index: 0, DurationMS: 2000, Bytes: 10_000, SHA256: "aaa", Provenance: protocol.ProvenanceHostVerified},
		{Index: 1, DurationMS: 2000, Bytes: 8_000, SHA256: "bbb", Provenance: protocol.ProvenanceAttested},
	}
}

func TestVerifyManifest(t *testing.T) {
	t.Parallel()

	startedAt := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	window := 5 * time.Second

	t.Run("well-formed manifest passes", func(t *testing.T) {
		t.Parallel()
		// Nonce issued at T+1s; reflected in segment 0 whose end-time is T+2s.
		// Reflection window: |2s - 1s| = 1s <= 5s → ok.
		segs := baseSegments()
		m := protocol.StreamManifest{
			Seq:       1,
			StreamID:  "s1",
			StartedAt: startedAt,
			Segments:  segs,
			LivenessNonces: []protocol.LivenessNonce{
				{Nonce: "n1", IssuedAt: startedAt.Add(1 * time.Second), ReflectedInSeq: 0},
			},
			DeliveryReceipts: []protocol.DeliveryReceipt{
				{ConsumerID: "c1", Kind: protocol.ConsumerViewer, SeqStart: 0, SeqEnd: 0, Bytes: 10_000, SHA256: "aaa"},
			},
		}
		issued := []protocol.LivenessNonce{
			{Nonce: "n1", IssuedAt: startedAt.Add(1 * time.Second)},
		}
		if err := protocol.VerifyManifest(m, issued, window); err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
	})

	t.Run("mutated receipt hash returns error", func(t *testing.T) {
		t.Parallel()
		m := protocol.StreamManifest{
			Seq:       1,
			StreamID:  "s1",
			StartedAt: startedAt,
			Segments:  baseSegments(),
			DeliveryReceipts: []protocol.DeliveryReceipt{
				// SHA256 does not match segment 0's "aaa"
				{ConsumerID: "c1", Kind: protocol.ConsumerViewer, SeqStart: 0, SeqEnd: 0, Bytes: 10_000, SHA256: "zzz"},
			},
		}
		if err := protocol.VerifyManifest(m, nil, window); err == nil {
			t.Fatal("expected error for mismatched receipt hash, got nil")
		}
	})

	t.Run("unmarked sequence gap returns error", func(t *testing.T) {
		t.Parallel()
		m := protocol.StreamManifest{
			Seq:       1,
			StreamID:  "s1",
			StartedAt: startedAt,
			// Gap: index 0 → index 2 (index 1 missing, no Discontinuity covers it)
			Segments: []protocol.Segment{
				{Index: 0, DurationMS: 2000, Bytes: 10_000, SHA256: "aaa", Provenance: protocol.ProvenanceHostVerified},
				{Index: 2, DurationMS: 2000, Bytes: 9_000, SHA256: "ccc", Provenance: protocol.ProvenanceHostVerified},
			},
		}
		if err := protocol.VerifyManifest(m, nil, window); err == nil {
			t.Fatal("expected error for unmarked sequence gap, got nil")
		}
	})

	t.Run("gap covered by discontinuity marker passes", func(t *testing.T) {
		t.Parallel()
		m := protocol.StreamManifest{
			Seq:       1,
			StreamID:  "s1",
			StartedAt: startedAt,
			Segments: []protocol.Segment{
				{Index: 0, DurationMS: 2000, Bytes: 10_000, SHA256: "aaa", Provenance: protocol.ProvenanceHostVerified},
				{Index: 2, DurationMS: 2000, Bytes: 9_000, SHA256: "ccc", Provenance: protocol.ProvenanceHostVerified},
			},
			Discontinuities: []protocol.Discontinuity{
				{At: startedAt.Add(2 * time.Second), Reason: "network drop", PrevSeq: 0, ResumeSeq: 2,
					Sig: []byte("host-sig")},
			},
		}
		if err := protocol.VerifyManifest(m, nil, window); err != nil {
			t.Fatalf("expected no error for covered gap, got: %v", err)
		}
	})

	t.Run("inflated receipt bytes do not count — seg.Bytes used not r.Bytes", func(t *testing.T) {
		t.Parallel()
		// Worker copies the public SHA256 ("aaa") but claims 1e18 bytes.
		// VerifiedDeliveredBytes must credit seg.Bytes (10_000), not r.Bytes.
		m := protocol.StreamManifest{
			Seq:       1,
			StreamID:  "s1",
			StartedAt: startedAt,
			Segments: []protocol.Segment{
				{Index: 0, DurationMS: 2000, Bytes: 10_000, SHA256: "aaa", Provenance: protocol.ProvenanceHostVerified},
			},
			DeliveryReceipts: []protocol.DeliveryReceipt{
				{ConsumerID: "attacker", Kind: protocol.ConsumerViewer, SeqStart: 0, SeqEnd: 0,
					Bytes: 1_000_000_000_000_000_000, SHA256: "aaa"},
			},
		}
		want := int64(10_000)
		if got := m.VerifiedDeliveredBytes(); got != want {
			t.Fatalf("VerifiedDeliveredBytes() = %d, want %d (r.Bytes must not be credited)", got, want)
		}
	})

	t.Run("range receipt in v1 manifest returns error", func(t *testing.T) {
		t.Parallel()
		// SeqStart != SeqEnd — range receipts are not supported in v1.
		m := protocol.StreamManifest{
			Seq:       1,
			StreamID:  "s1",
			StartedAt: startedAt,
			Segments:  baseSegments(),
			DeliveryReceipts: []protocol.DeliveryReceipt{
				{ConsumerID: "c1", Kind: protocol.ConsumerViewer, SeqStart: 0, SeqEnd: 5,
					Bytes: 50_000, SHA256: "range-hash"},
			},
		}
		if err := protocol.VerifyManifest(m, nil, window); err == nil {
			t.Fatal("expected error for range receipt in v1 manifest, got nil")
		}
	})

	t.Run("nonce reflected outside window returns error", func(t *testing.T) {
		t.Parallel()
		// Nonce issued at T+100s; reflected in segment 0 whose end-time is T+2s.
		// |2s - 100s| = 98s > 5s window → error.
		m := protocol.StreamManifest{
			Seq:       1,
			StreamID:  "s1",
			StartedAt: startedAt,
			Segments:  baseSegments(),
			LivenessNonces: []protocol.LivenessNonce{
				{Nonce: "n2", IssuedAt: startedAt.Add(100 * time.Second), ReflectedInSeq: 0},
			},
		}
		issued := []protocol.LivenessNonce{
			{Nonce: "n2", IssuedAt: startedAt.Add(100 * time.Second)},
		}
		if err := protocol.VerifyManifest(m, issued, window); err == nil {
			t.Fatal("expected error for nonce outside window, got nil")
		}
	})

	t.Run("VerifiedDeliveredBytes returns only cross-checked host-verified bytes", func(t *testing.T) {
		t.Parallel()
		// Segment 0: host-verified, SHA256 "aaa", bytes 10000
		// Segment 1: attested only, SHA256 "bbb", bytes 8000
		// Receipt for seg 0: SHA256 "aaa" → matches → counts
		// Receipt for seg 1: SHA256 "bbb" → matches BUT segment is attested (not host-verified) → does not count
		m := protocol.StreamManifest{
			Seq:       1,
			StreamID:  "s1",
			StartedAt: startedAt,
			Segments:  baseSegments(),
			DeliveryReceipts: []protocol.DeliveryReceipt{
				{ConsumerID: "c1", Kind: protocol.ConsumerViewer, SeqStart: 0, SeqEnd: 0, Bytes: 10_000, SHA256: "aaa"},
				{ConsumerID: "c1", Kind: protocol.ConsumerViewer, SeqStart: 1, SeqEnd: 1, Bytes: 8_000, SHA256: "bbb"},
			},
		}
		want := int64(10_000)
		if got := m.VerifiedDeliveredBytes(); got != want {
			t.Fatalf("VerifiedDeliveredBytes() = %d, want %d", got, want)
		}
	})
}
