package checkpoint

import (
	"encoding/hex"
	"encoding/json"
)

// wireCheckpoint is the JSON shape written to durable witnesses (S3 objects,
// the control-plane DB, customer-delivered copies). Hashes are hex so the
// document is human-readable and diff-friendly.
type wireCheckpoint struct {
	TenantID           string `json:"tenant_id"`
	SeqStart           uint64 `json:"seq_start"`
	SeqEnd             uint64 `json:"seq_end"`
	EntryCount         uint64 `json:"entry_count"`
	HeadHash           string `json:"head_hash"`
	MerkleRoot         string `json:"merkle_root"`
	PrevCheckpointHash string `json:"prev_checkpoint_hash"`
	AnchoredAt         int64  `json:"anchored_at"`
	CanonVersion       int    `json:"canon_version"`
	CheckpointID       string `json:"checkpoint_id"`
}

// Marshal serializes a checkpoint to canonical JSON bytes for storage.
func Marshal(cp Checkpoint) ([]byte, error) {
	return json.MarshalIndent(wireCheckpoint{
		TenantID:           cp.TenantID,
		SeqStart:           cp.SeqStart,
		SeqEnd:             cp.SeqEnd,
		EntryCount:         cp.EntryCount,
		HeadHash:           hex.EncodeToString(cp.HeadHash),
		MerkleRoot:         hex.EncodeToString(cp.MerkleRoot),
		PrevCheckpointHash: hex.EncodeToString(cp.PrevCheckpointHash),
		AnchoredAt:         cp.AnchoredAt,
		CanonVersion:       cp.CanonVersion,
		CheckpointID:       hex.EncodeToString(cp.CheckpointID),
	}, "", "  ")
}

// Unmarshal parses a stored checkpoint document.
func Unmarshal(b []byte) (Checkpoint, error) {
	var w wireCheckpoint
	if err := json.Unmarshal(b, &w); err != nil {
		return Checkpoint{}, err
	}
	dec := func(s string) ([]byte, error) {
		if s == "" {
			return nil, nil
		}
		return hex.DecodeString(s)
	}
	head, err := dec(w.HeadHash)
	if err != nil {
		return Checkpoint{}, err
	}
	root, err := dec(w.MerkleRoot)
	if err != nil {
		return Checkpoint{}, err
	}
	prev, err := dec(w.PrevCheckpointHash)
	if err != nil {
		return Checkpoint{}, err
	}
	id, err := dec(w.CheckpointID)
	if err != nil {
		return Checkpoint{}, err
	}
	return Checkpoint{
		TenantID:           w.TenantID,
		SeqStart:           w.SeqStart,
		SeqEnd:             w.SeqEnd,
		EntryCount:         w.EntryCount,
		HeadHash:           head,
		MerkleRoot:         root,
		PrevCheckpointHash: prev,
		AnchoredAt:         w.AnchoredAt,
		CanonVersion:       w.CanonVersion,
		CheckpointID:       id,
	}, nil
}
