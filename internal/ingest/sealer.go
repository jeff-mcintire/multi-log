// Package ingest holds the persistent sealer and the ingest HTTP gateway.
//
// The sealer is the single-writer-per-tenant component: it assigns the monotonic
// sequence number, links each entry into the per-tenant hash chain, and persists
// to the log store. Phase 1 runs one gateway instance, so a mutex provides the
// single-writer guarantee; Phase 2 shards sealers by tenant.
package ingest

import (
	"context"
	"sync"

	"github.com/mythforge/multi-log/internal/chain"
	"github.com/mythforge/multi-log/internal/crypto"
)

// LogStore is the persistence the sealer needs: where to resume each tenant's
// chain (Head) and where to write sealed entries (Append).
type LogStore interface {
	Head(ctx context.Context, tenantID string) (nextSeq uint64, prevHash []byte, err error)
	Append(ctx context.Context, entries []*chain.Entry) error
}

// Record is one raw log line handed to the sealer.
type Record struct {
	Source     string
	Raw        string
	EventTime  int64 // source timestamp (nanos); untrusted
	IngestTime int64 // server receive time (nanos); trusted
}

// Sealer seals batches of records, one tenant at a time.
type Sealer struct {
	mu    sync.Mutex
	store LogStore
	heads map[string]*headState
}

type headState struct {
	nextSeq  uint64
	prevHash []byte
}

func NewSealer(store LogStore) *Sealer {
	return &Sealer{store: store, heads: map[string]*headState{}}
}

// SealBatch assigns sequence numbers and chain hashes to a batch of records for
// one tenant, persists them, and returns the sealed entries. The head is only
// advanced after a successful write, so a failed append can be safely retried.
func (s *Sealer) SealBatch(ctx context.Context, tenantID string, recs []Record) ([]*chain.Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	h, ok := s.heads[tenantID]
	if !ok {
		nextSeq, prevHash, err := s.store.Head(ctx, tenantID)
		if err != nil {
			return nil, err
		}
		h = &headState{nextSeq: nextSeq, prevHash: prevHash}
		s.heads[tenantID] = h
	}

	seq := h.nextSeq
	prev := h.prevHash
	entries := make([]*chain.Entry, 0, len(recs))
	for _, r := range recs {
		leaf := crypto.EntryLeaf(tenantID, seq, r.EventTime, r.IngestTime, r.Source, r.Raw)
		entryHash := crypto.ChainHash(prev, leaf)
		entries = append(entries, &chain.Entry{
			TenantID:   tenantID,
			Seq:        seq,
			EventTime:  r.EventTime,
			IngestTime: r.IngestTime,
			Source:     r.Source,
			Raw:        r.Raw,
			PrevHash:   prev,
			EntryHash:  entryHash,
		})
		prev = entryHash
		seq++
	}

	if err := s.store.Append(ctx, entries); err != nil {
		return nil, err
	}
	h.nextSeq = seq
	h.prevHash = prev
	return entries, nil
}
