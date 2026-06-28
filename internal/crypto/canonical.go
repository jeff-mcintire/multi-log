// Package crypto is the keystone of multi-log's tamper-evidence: it defines the
// one canonical, versioned serialization that every component (sealer, anchorer,
// verifier, and the standalone customer CLI) must agree on byte-for-byte.
//
// If two components disagree on how a log entry or checkpoint is encoded, every
// hash diverges and verification fails on benign changes. So canonicalization is
// deliberately explicit and length-prefixed here, never reliant on map ordering
// or struct-tag accidents.
package crypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
)

// CanonVersion is stamped into every entry leaf and checkpoint. Bumping it lets
// us evolve the encoding without breaking verification of historical data: old
// records are verified with the rules of the version they were written under.
const CanonVersion = 1

// Domain-separation tags. Hashing distinct structures under distinct prefixes
// stops a value valid in one context from being replayed in another.
const (
	domainEntry      = "mlog/entry/v1"
	domainGenesis    = "mlog/genesis/v1"
	domainCheckpoint = "mlog/checkpoint/v1"
)

// Hash is the single hash primitive used everywhere (SHA-256).
func Hash(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

// Encoder builds a deterministic, length-prefixed byte string under a domain
// tag. Every field is prefixed with its length so no two distinct field
// sequences can ever collide into the same encoding.
type Encoder struct {
	buf bytes.Buffer
}

func NewEncoder(domain string) *Encoder {
	e := &Encoder{}
	e.field([]byte(domain))
	return e
}

func (e *Encoder) field(b []byte) {
	var l [8]byte
	binary.BigEndian.PutUint64(l[:], uint64(len(b)))
	e.buf.Write(l[:])
	e.buf.Write(b)
}

func (e *Encoder) Bytes(b []byte) *Encoder { e.field(b); return e }
func (e *Encoder) Str(s string) *Encoder   { e.field([]byte(s)); return e }

func (e *Encoder) Uint(n uint64) *Encoder {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], n)
	e.field(b[:])
	return e
}

func (e *Encoder) Int(n int64) *Encoder { return e.Uint(uint64(n)) }

// Raw returns the accumulated canonical bytes.
func (e *Encoder) Raw() []byte { return e.buf.Bytes() }

// Sum returns SHA-256 of the accumulated canonical bytes.
func (e *Encoder) Sum() []byte { return Hash(e.buf.Bytes()) }

// Genesis is the synthetic "previous hash" that seeds a tenant's chain. It is
// derived from the tenant id so chains can never be confused across tenants.
func Genesis(tenantID string) []byte {
	return NewEncoder(domainGenesis).Str(tenantID).Sum()
}

// EntryLeaf returns SHA-256 over the canonical, immutable fields of a log entry.
// This is the per-entry commitment; it deliberately covers only the fields we
// contractually promise are immutable (identity, position, timestamps, source,
// and the original raw line) and excludes any later enrichment.
func EntryLeaf(tenantID string, seq uint64, eventTime, ingestTime int64, source, raw string) []byte {
	return NewEncoder(domainEntry).
		Uint(uint64(CanonVersion)).
		Str(tenantID).
		Uint(seq).
		Int(eventTime).
		Int(ingestTime).
		Str(source).
		Str(raw).
		Sum()
}

// ChainHash links an entry to its predecessor: entry_hash = H(prev_hash || leaf).
// Altering any past entry breaks this entry's hash and every hash after it.
func ChainHash(prevHash, leaf []byte) []byte {
	combined := make([]byte, 0, len(prevHash)+len(leaf))
	combined = append(combined, prevHash...)
	combined = append(combined, leaf...)
	return Hash(combined)
}

// CheckpointID returns the canonical identifier of a checkpoint. It commits to
// the sequence window and entry count (not just the Merkle root) so that silent
// deletion or tail-truncation is detectable, and to the previous checkpoint hash
// so the sequence of checkpoints is itself a chain.
func CheckpointID(
	tenantID string,
	seqStart, seqEnd, entryCount uint64,
	headHash, merkleRoot, prevCheckpointHash []byte,
	anchoredAt int64,
) []byte {
	return NewEncoder(domainCheckpoint).
		Uint(uint64(CanonVersion)).
		Str(tenantID).
		Uint(seqStart).
		Uint(seqEnd).
		Uint(entryCount).
		Bytes(headHash).
		Bytes(merkleRoot).
		Bytes(prevCheckpointHash).
		Int(anchoredAt).
		Sum()
}
