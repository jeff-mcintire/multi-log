package chain

import (
	"sync"

	"github.com/mythforge/multi-log/internal/crypto"
)

// Sealer is the single-writer-per-tenant component that assigns the monotonic
// sequence number and computes the hash chain. In the real system there is
// exactly one sealer owning each tenant (sharded by tenant id) so the chain has
// a clean linear order with no races. Here a mutex enforces the same invariant.
type Sealer struct {
	mu    sync.Mutex
	store *Store
	heads map[string]*head
}

type head struct {
	nextSeq  uint64
	prevHash []byte
}

func NewSealer(store *Store) *Sealer {
	return &Sealer{store: store, heads: map[string]*head{}}
}

// Seal assigns the next sequence number for the tenant, links the entry into the
// chain, stores it, and returns it. seq is the source of truth for position;
// wall-clock time is never trusted for ordering.
func (s *Sealer) Seal(tenantID, source, raw string, eventTime, ingestTime int64) *Entry {
	s.mu.Lock()
	defer s.mu.Unlock()

	h, ok := s.heads[tenantID]
	if !ok {
		h = &head{nextSeq: 0, prevHash: crypto.Genesis(tenantID)}
		s.heads[tenantID] = h
	}

	leaf := crypto.EntryLeaf(tenantID, h.nextSeq, eventTime, ingestTime, source, raw)
	entryHash := crypto.ChainHash(h.prevHash, leaf)

	e := &Entry{
		TenantID:   tenantID,
		Seq:        h.nextSeq,
		EventTime:  eventTime,
		IngestTime: ingestTime,
		Source:     source,
		Raw:        raw,
		PrevHash:   h.prevHash,
		EntryHash:  entryHash,
	}
	s.store.Append(e)

	h.nextSeq++
	h.prevHash = entryHash
	return e
}
