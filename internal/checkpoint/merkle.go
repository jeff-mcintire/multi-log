package checkpoint

import "github.com/mythforge/multi-log/internal/crypto"

// Merkle leaf/internal domain separators prevent a leaf hash from being
// reinterpreted as an internal node (a classic second-preimage attack).
var (
	leafPrefix = []byte{0x00}
	nodePrefix = []byte{0x01}
)

// MerkleRoot computes a binary Merkle root over the given entry hashes. Odd
// nodes at a level are promoted by duplication. An empty set hashes to a fixed
// empty-tree value so an empty window still has a well-defined root.
func MerkleRoot(entryHashes [][]byte) []byte {
	if len(entryHashes) == 0 {
		return crypto.Hash(leafPrefix)
	}

	level := make([][]byte, len(entryHashes))
	for i, h := range entryHashes {
		level[i] = crypto.Hash(append(append([]byte{}, leafPrefix...), h...))
	}

	for len(level) > 1 {
		next := make([][]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			left := level[i]
			right := left // duplicate the last node if the level is odd
			if i+1 < len(level) {
				right = level[i+1]
			}
			combined := append(append([]byte{}, nodePrefix...), left...)
			combined = append(combined, right...)
			next = append(next, crypto.Hash(combined))
		}
		level = next
	}
	return level[0]
}
