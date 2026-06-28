// Package witness models the independent anchors that make tampering detectable.
// A hash chain alone is defeated by an insider who rewrites the database and
// recomputes the chain; what they cannot forge is an anchor held outside their
// control. There are two kinds, because the real services behave differently:
//
//   - CheckpointStore — durably STORES the checkpoint object, immutably.
//     Production: S3 Object Lock (COMPLIANCE mode) in an isolated account.
//
//   - Notary — does not store anything; it returns a verifiable PROOF that a
//     checkpoint id existed at a point in time. You keep the proof.
//     Production: an RFC 3161 timestamp authority, and OpenTimestamps (Bitcoin).
//
// Three independent witnesses = one CheckpointStore (WORM) + two Notaries.
package witness

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"

	"github.com/mythforge/multi-log/internal/checkpoint"
)

// ErrImmutable is returned when something tries to overwrite an existing
// anchored checkpoint. Real WORM storage enforces this at the platform level.
var ErrImmutable = errors.New("witness: refusing to overwrite an already-anchored checkpoint")

// CheckpointStore is an append-only, immutable record of full checkpoints.
type CheckpointStore interface {
	Name() string
	Put(cp checkpoint.Checkpoint) error
	Get(tenantID string, seqEnd uint64) (checkpoint.Checkpoint, bool, error)
	All(tenantID string) ([]checkpoint.Checkpoint, error)
}

// Proof is an opaque, self-verifying attestation that a checkpoint id existed.
// Its integrity does not depend on where it is stored, so an insider may hold it
// in a writable database yet still cannot forge one for a different id.
type Proof struct {
	Notary string // which notary produced it
	Format string // "rfc3161" | "opentimestamps" | "mock-hmac"
	Token  []byte // the DER timestamp token / .ots bytes / mac
}

// Notary produces and verifies timestamp proofs over a checkpoint id.
type Notary interface {
	Name() string
	Stamp(checkpointID []byte) (Proof, error)
	Verify(p Proof, checkpointID []byte) error
}

// ProofLedger holds the proofs we keep (control-plane DB + customer-delivered
// copies), keyed by tenant and the checkpoint's ending sequence. It is
// deliberately mutable: proofs are self-verifying, so this storage need not be
// trusted.
type ProofLedger struct {
	m map[string][]Proof
}

func NewProofLedger() *ProofLedger { return &ProofLedger{m: map[string][]Proof{}} }

func ledgerKey(tenantID string, seqEnd uint64) string {
	return fmt.Sprintf("%s/%d", tenantID, seqEnd)
}

func (l *ProofLedger) Add(tenantID string, seqEnd uint64, p Proof) {
	k := ledgerKey(tenantID, seqEnd)
	l.m[k] = append(l.m[k], p)
}

func (l *ProofLedger) Get(tenantID string, seqEnd uint64) []Proof {
	return l.m[ledgerKey(tenantID, seqEnd)]
}

// MemStore is an append-only in-memory CheckpointStore for the offline demo and
// tests. It enforces the one property that matters: no overwrite once anchored.
type MemStore struct {
	name    string
	records map[string]map[uint64]checkpoint.Checkpoint
}

func NewMemStore(name string) *MemStore {
	return &MemStore{name: name, records: map[string]map[uint64]checkpoint.Checkpoint{}}
}

func (s *MemStore) Name() string { return s.name }

func (s *MemStore) Put(cp checkpoint.Checkpoint) error {
	byTenant := s.records[cp.TenantID]
	if byTenant == nil {
		byTenant = map[uint64]checkpoint.Checkpoint{}
		s.records[cp.TenantID] = byTenant
	}
	if _, exists := byTenant[cp.SeqEnd]; exists {
		return ErrImmutable
	}
	byTenant[cp.SeqEnd] = cp
	return nil
}

func (s *MemStore) Get(tenantID string, seqEnd uint64) (checkpoint.Checkpoint, bool, error) {
	cp, ok := s.records[tenantID][seqEnd]
	return cp, ok, nil
}

func (s *MemStore) All(tenantID string) ([]checkpoint.Checkpoint, error) {
	byTenant := s.records[tenantID]
	out := make([]checkpoint.Checkpoint, 0, len(byTenant))
	for _, cp := range byTenant {
		out = append(out, cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SeqEnd < out[j].SeqEnd })
	return out, nil
}

// MockNotary is an offline stand-in that models a real notary's essential
// property — only the holder of a secret can produce a proof for a given id —
// using HMAC-SHA256. It lets the no-dependency demo and tests exercise the same
// verification path the RFC 3161 and OpenTimestamps notaries use.
type MockNotary struct {
	name   string
	secret []byte
}

func NewMockNotary(name, secret string) *MockNotary {
	return &MockNotary{name: name, secret: []byte(secret)}
}

func (n *MockNotary) Name() string { return n.name }

func (n *MockNotary) mac(checkpointID []byte) []byte {
	m := hmac.New(sha256.New, n.secret)
	m.Write(checkpointID)
	return m.Sum(nil)
}

func (n *MockNotary) Stamp(checkpointID []byte) (Proof, error) {
	return Proof{Notary: n.name, Format: "mock-hmac", Token: n.mac(checkpointID)}, nil
}

func (n *MockNotary) Verify(p Proof, checkpointID []byte) error {
	if !hmac.Equal(p.Token, n.mac(checkpointID)) {
		return fmt.Errorf("witness: proof from %q does not attest this checkpoint id", n.name)
	}
	return nil
}

// Hex shortens a hash for compact display.
func Hex(b []byte) string {
	s := hex.EncodeToString(b)
	if len(s) > 16 {
		return s[:16]
	}
	return s
}
