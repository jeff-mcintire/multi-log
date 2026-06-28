package verify

import (
	"testing"

	"github.com/mythforge/multi-log/internal/chain"
	"github.com/mythforge/multi-log/internal/checkpoint"
	"github.com/mythforge/multi-log/internal/crypto"
	"github.com/mythforge/multi-log/internal/witness"
)

// harness builds a small honest, anchored system for one tenant: a WORM store
// plus two notaries, all in-memory.
func harness(t *testing.T) (*chain.Store, witness.CheckpointStore, *witness.ProofLedger, []witness.Notary) {
	t.Helper()
	store := chain.NewStore()
	sealer := chain.NewSealer(store)
	for i := 0; i < 10; i++ {
		sealer.Seal("acme", "api", "line", int64(i), int64(i))
	}
	worm := witness.NewMemStore("WORM")
	notaries := []witness.Notary{
		witness.NewMockNotary("TSA", "k1"),
		witness.NewMockNotary("OTS", "k2"),
	}
	ledger := witness.NewProofLedger()

	entries := store.Tenant("acme")
	var prev []byte
	for start := 0; start < len(entries); start += 5 {
		cp := checkpoint.Build("acme", entries[start:start+5], prev, 1)
		if err := worm.Put(cp); err != nil {
			t.Fatal(err)
		}
		for _, n := range notaries {
			p, err := n.Stamp(cp.CheckpointID)
			if err != nil {
				t.Fatal(err)
			}
			ledger.Add("acme", cp.SeqEnd, p)
		}
		prev = cp.CheckpointID
	}
	return store, worm, ledger, notaries
}

func reseal(store *chain.Store, tenant string) {
	prev := crypto.Genesis(tenant)
	for _, e := range store.Tenant(tenant) {
		e.PrevHash = prev
		leaf := crypto.EntryLeaf(tenant, e.Seq, e.EventTime, e.IngestTime, e.Source, e.Raw)
		e.EntryHash = crypto.ChainHash(prev, leaf)
		prev = e.EntryHash
	}
}

func hasKind(r Report, kind string) bool {
	for _, iss := range r.Issues {
		if iss.Kind == kind {
			return true
		}
	}
	return false
}

func TestHonestVerifies(t *testing.T) {
	store, worm, ledger, notaries := harness(t)
	rep := Verify(store, worm, ledger, notaries)
	if !rep.OK() {
		t.Fatalf("honest system should verify, got: %v", rep.Issues)
	}
	if rep.ProofsChecked == 0 {
		t.Fatal("expected notary proofs to be checked")
	}
}

func TestNaiveEditCaughtByChain(t *testing.T) {
	store, worm, ledger, notaries := harness(t)
	store.Tenant("acme")[3].Raw = "tampered"
	rep := Verify(store, worm, ledger, notaries)
	if !hasKind(rep, "entry-tamper") {
		t.Fatalf("expected entry-tamper, got: %v", rep.Issues)
	}
}

func TestSophisticatedEditCaughtByWitnesses(t *testing.T) {
	store, worm, ledger, notaries := harness(t)
	store.Tenant("acme")[7].Raw = "tampered" // window 2 (seq 5..9)
	reseal(store, "acme")                    // chain now self-consistent
	rep := Verify(store, worm, ledger, notaries)
	if rep.OK() {
		t.Fatal("expected detection via the witnesses")
	}
	if !hasKind(rep, "checkpoint-mismatch") {
		t.Fatalf("expected WORM checkpoint-mismatch, got: %v", rep.Issues)
	}
	if !hasKind(rep, "notary-mismatch") {
		t.Fatalf("expected independent notary-mismatch, got: %v", rep.Issues)
	}
}

func TestTailTruncationCaughtByCount(t *testing.T) {
	store, worm, ledger, notaries := harness(t)
	store.Delete("acme", 9) // delete the tail; no sequence gap remains
	reseal(store, "acme")
	rep := Verify(store, worm, ledger, notaries)
	if !hasKind(rep, "truncation") {
		t.Fatalf("expected truncation, got: %v", rep.Issues)
	}
}
