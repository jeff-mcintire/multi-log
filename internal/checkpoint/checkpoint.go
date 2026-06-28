// Package checkpoint builds the periodic, per-tenant commitments that get
// anchored to independent witnesses. A checkpoint commits to a contiguous window
// of entries by Merkle root, head hash, AND entry count + sequence range, so
// that both edits (root/head change) and deletions/truncation (count/range
// change) are detectable.
package checkpoint

import (
	"github.com/mythforge/multi-log/internal/chain"
	"github.com/mythforge/multi-log/internal/crypto"
)

// Checkpoint is the unit anchored to WORM storage, a timestamp authority, and a
// public chain. Checkpoints are themselves chained via PrevCheckpointHash.
type Checkpoint struct {
	TenantID           string
	SeqStart           uint64
	SeqEnd             uint64
	EntryCount         uint64
	HeadHash           []byte
	MerkleRoot         []byte
	PrevCheckpointHash []byte
	AnchoredAt         int64
	CanonVersion       int
	CheckpointID       []byte
}

// Build constructs a checkpoint over a contiguous, in-order slice of entries.
// prevCheckpointID links this checkpoint to the previous one for the tenant
// (nil for the first). anchoredAt must come from a trusted server clock.
func Build(tenantID string, entries []*chain.Entry, prevCheckpointID []byte, anchoredAt int64) Checkpoint {
	hashes := make([][]byte, len(entries))
	for i, e := range entries {
		hashes[i] = e.EntryHash
	}

	seqStart := entries[0].Seq
	seqEnd := entries[len(entries)-1].Seq
	headHash := entries[len(entries)-1].EntryHash
	merkleRoot := MerkleRoot(hashes)
	count := uint64(len(entries))

	id := crypto.CheckpointID(
		tenantID, seqStart, seqEnd, count,
		headHash, merkleRoot, prevCheckpointID, anchoredAt,
	)

	return Checkpoint{
		TenantID:           tenantID,
		SeqStart:           seqStart,
		SeqEnd:             seqEnd,
		EntryCount:         count,
		HeadHash:           headHash,
		MerkleRoot:         merkleRoot,
		PrevCheckpointHash: prevCheckpointID,
		AnchoredAt:         anchoredAt,
		CanonVersion:       crypto.CanonVersion,
		CheckpointID:       id,
	}
}
