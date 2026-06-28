// Package chain models the log store and the single-writer-per-tenant sealer
// that assigns sequence numbers and computes the hash chain.
//
// In production the Store is ClickHouse; here it is an in-memory stand-in that an
// "insider" can freely mutate, which is exactly the threat we want to defend
// against. Entries are held in append order, which equals sequence order.
package chain

import "sort"

// Entry is one log record. PrevHash and EntryHash are the chain columns; the
// remaining fields are the immutable payload committed to by EntryHash.
type Entry struct {
	TenantID   string
	Seq        uint64
	EventTime  int64 // timestamp from the source (untrusted)
	IngestTime int64 // server receive time (trusted clock)
	Source     string
	Raw        string
	PrevHash   []byte
	EntryHash  []byte
}

// Store holds entries per tenant. It is intentionally simple and mutable so the
// demo can simulate an attacker editing or deleting rows.
type Store struct {
	entries map[string][]*Entry
}

func NewStore() *Store {
	return &Store{entries: map[string][]*Entry{}}
}

// Append adds an already-sealed entry. Only the Sealer should call this.
func (s *Store) Append(e *Entry) {
	s.entries[e.TenantID] = append(s.entries[e.TenantID], e)
}

// Tenant returns the tenant's entries in sequence order.
func (s *Store) Tenant(id string) []*Entry {
	es := s.entries[id]
	sort.Slice(es, func(i, j int) bool { return es[i].Seq < es[j].Seq })
	return es
}

// Range returns the entries with seq in [start, end] inclusive, and whether the
// full contiguous range was found. A missing entry (false) is the signature of a
// deletion or truncation.
func (s *Store) Range(id string, start, end uint64) ([]*Entry, bool) {
	byseq := map[uint64]*Entry{}
	for _, e := range s.entries[id] {
		byseq[e.Seq] = e
	}
	out := make([]*Entry, 0, end-start+1)
	for seq := start; seq <= end; seq++ {
		e, ok := byseq[seq]
		if !ok {
			return out, false
		}
		out = append(out, e)
	}
	return out, true
}

// Delete removes the entry with the given seq from a tenant. It exists to let
// the demo simulate an insider deleting or truncating rows; the real store has
// no such honest path for committed entries.
func (s *Store) Delete(tenantID string, seq uint64) {
	es := s.entries[tenantID]
	out := es[:0]
	for _, e := range es {
		if e.Seq != seq {
			out = append(out, e)
		}
	}
	s.entries[tenantID] = out
}

// Tenants lists all tenant ids present.
func (s *Store) Tenants() []string {
	ids := make([]string, 0, len(s.entries))
	for id := range s.entries {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
