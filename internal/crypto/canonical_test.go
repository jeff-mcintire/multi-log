package crypto

import "testing"

// canonical encoding must be deterministic: same inputs -> identical bytes.
func TestEntryLeafDeterministic(t *testing.T) {
	a := EntryLeaf("t1", 5, 100, 200, "api", "hello")
	b := EntryLeaf("t1", 5, 100, 200, "api", "hello")
	if string(a) != string(b) {
		t.Fatal("EntryLeaf is not deterministic")
	}
}

// any change to any field must change the leaf hash.
func TestEntryLeafSensitivity(t *testing.T) {
	base := EntryLeaf("t1", 5, 100, 200, "api", "hello")
	cases := map[string][]byte{
		"tenant": EntryLeaf("t2", 5, 100, 200, "api", "hello"),
		"seq":    EntryLeaf("t1", 6, 100, 200, "api", "hello"),
		"event":  EntryLeaf("t1", 5, 101, 200, "api", "hello"),
		"ingest": EntryLeaf("t1", 5, 100, 201, "api", "hello"),
		"source": EntryLeaf("t1", 5, 100, 200, "web", "hello"),
		"raw":    EntryLeaf("t1", 5, 100, 200, "api", "hellp"),
	}
	for name, got := range cases {
		if string(got) == string(base) {
			t.Errorf("changing %s did not change the leaf hash", name)
		}
	}
}

// length-prefixing must prevent field-boundary collisions: "ab"+"c" != "a"+"bc".
func TestEncoderNoFieldCollision(t *testing.T) {
	x := NewEncoder("d").Str("ab").Str("c").Sum()
	y := NewEncoder("d").Str("a").Str("bc").Sum()
	if string(x) == string(y) {
		t.Fatal("encoder allowed a field-boundary collision")
	}
}

// genesis must be tenant-specific so chains can't be confused across tenants.
func TestGenesisPerTenant(t *testing.T) {
	if string(Genesis("a")) == string(Genesis("b")) {
		t.Fatal("genesis must differ per tenant")
	}
}

// editing the window must change the checkpoint id even if the root is reused.
func TestCheckpointIDCommitsToCount(t *testing.T) {
	head := Hash([]byte("head"))
	root := Hash([]byte("root"))
	full := CheckpointID("t", 0, 9, 10, head, root, nil, 42)
	truncated := CheckpointID("t", 0, 9, 9, head, root, nil, 42)
	if string(full) == string(truncated) {
		t.Fatal("checkpoint id must commit to entry count")
	}
}
