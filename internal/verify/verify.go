// Package verify recomputes the entire chain and every checkpoint straight from
// the stored entries, then matches the results against the independent witnesses:
// the WORM CheckpointStore (the trusted record of what was committed) and the
// notary proofs we hold (which independently attest each checkpoint id). It
// trusts neither the log database nor the proof ledger — only the witnesses.
// This is exactly what a customer's standalone CLI does.
package verify

import (
	"bytes"
	"fmt"

	"github.com/mythforge/multi-log/internal/chain"
	"github.com/mythforge/multi-log/internal/checkpoint"
	"github.com/mythforge/multi-log/internal/crypto"
	"github.com/mythforge/multi-log/internal/witness"
)

// Issue is a single detected problem, pinpointed to a tenant and (where
// possible) a sequence number.
type Issue struct {
	Tenant string
	Seq    uint64
	HasSeq bool
	Kind   string
	Detail string
}

func (i Issue) String() string {
	loc := ""
	if i.HasSeq {
		loc = fmt.Sprintf(" @ seq %d", i.Seq)
	}
	return fmt.Sprintf("[%s] tenant=%s%s: %s", i.Kind, i.Tenant, loc, i.Detail)
}

// Report is the outcome of a verification run.
type Report struct {
	Issues          []Issue
	EntriesChecked  int
	CheckpointsSeen int
	ProofsChecked   int
}

func (r Report) OK() bool { return len(r.Issues) == 0 }

// Verify checks every tenant's chain and checkpoints against the WORM store and
// the notary proofs held in the ledger.
func Verify(store *chain.Store, worm witness.CheckpointStore, ledger *witness.ProofLedger, notaries []witness.Notary) Report {
	var r Report
	byName := map[string]witness.Notary{}
	for _, n := range notaries {
		byName[n.Name()] = n
	}
	for _, tenant := range store.Tenants() {
		verifyChain(store, tenant, &r)
		verifyCheckpoints(store, worm, ledger, byName, tenant, &r)
	}
	return r
}

// verifyChain replays the per-tenant hash chain from genesis and confirms each
// stored entry hash, plus a gap-free sequence. This catches a naive edit (one
// that didn't recompute the chain) and any deletion in the body.
func verifyChain(store *chain.Store, tenant string, r *Report) {
	prev := crypto.Genesis(tenant)
	want := uint64(0)
	for _, e := range store.Tenant(tenant) {
		r.EntriesChecked++

		if e.Seq != want {
			r.Issues = append(r.Issues, Issue{
				Tenant: tenant, Seq: want, HasSeq: true, Kind: "sequence-gap",
				Detail: fmt.Sprintf("expected seq %d, found %d (entry deleted or reordered)", want, e.Seq),
			})
			return
		}
		if !bytes.Equal(e.PrevHash, prev) {
			r.Issues = append(r.Issues, Issue{
				Tenant: tenant, Seq: e.Seq, HasSeq: true, Kind: "chain-break",
				Detail: "prev_hash does not link to the previous entry",
			})
			return
		}

		leaf := crypto.EntryLeaf(tenant, e.Seq, e.EventTime, e.IngestTime, e.Source, e.Raw)
		recomputed := crypto.ChainHash(prev, leaf)
		if !bytes.Equal(e.EntryHash, recomputed) {
			r.Issues = append(r.Issues, Issue{
				Tenant: tenant, Seq: e.Seq, HasSeq: true, Kind: "entry-tamper",
				Detail: "stored entry_hash does not match the entry contents",
			})
			return
		}

		prev = e.EntryHash
		want++
	}
}

// verifyCheckpoints rebuilds each anchored checkpoint from the stored entries
// and matches it against the WORM record and the notary proofs. This is the step
// that defeats the sophisticated insider who edited a row AND recomputed the
// chain: the rebuilt checkpoint id will not equal the one anchored to WORM nor
// the one the notaries attested, and the committed count exposes truncation.
func verifyCheckpoints(
	store *chain.Store,
	worm witness.CheckpointStore,
	ledger *witness.ProofLedger,
	notaries map[string]witness.Notary,
	tenant string,
	r *Report,
) {
	anchored, err := worm.All(tenant)
	if err != nil {
		r.Issues = append(r.Issues, Issue{
			Tenant: tenant, Kind: "worm-error",
			Detail: fmt.Sprintf("could not read WORM store: %v", err),
		})
		return
	}

	var prevID []byte
	for _, cp := range anchored {
		r.CheckpointsSeen++

		// 1. Are all committed entries still present? (deletion / truncation)
		entries, complete := store.Range(tenant, cp.SeqStart, cp.SeqEnd)
		if !complete {
			firstMissing := cp.SeqStart + uint64(len(entries))
			r.Issues = append(r.Issues, Issue{
				Tenant: tenant, Seq: firstMissing, HasSeq: true, Kind: "truncation",
				Detail: fmt.Sprintf("checkpoint committed entries %d..%d (%d total) but seq %d is missing from the store",
					cp.SeqStart, cp.SeqEnd, cp.EntryCount, firstMissing),
			})
			prevID = cp.CheckpointID
			continue
		}

		// 2. Does the data still produce the anchored checkpoint id? (edits)
		rebuilt := checkpoint.Build(tenant, entries, prevID, cp.AnchoredAt)
		if !bytes.Equal(rebuilt.CheckpointID, cp.CheckpointID) {
			r.Issues = append(r.Issues, Issue{
				Tenant: tenant, Seq: cp.SeqEnd, HasSeq: true, Kind: "checkpoint-mismatch",
				Detail: fmt.Sprintf("entries in window %d..%d no longer match the checkpoint anchored to WORM",
					cp.SeqStart, cp.SeqEnd),
			})
		}

		// 3. Do the independent notary proofs attest the rebuilt id? Even if WORM
		//    were somehow compromised, the notaries are a separate trust domain.
		for _, p := range ledger.Get(tenant, cp.SeqEnd) {
			nt, ok := notaries[p.Notary]
			if !ok {
				continue
			}
			r.ProofsChecked++
			if err := nt.Verify(p, rebuilt.CheckpointID); err != nil {
				r.Issues = append(r.Issues, Issue{
					Tenant: tenant, Seq: cp.SeqEnd, HasSeq: true, Kind: "notary-mismatch",
					Detail: fmt.Sprintf("%s: %v", p.Notary, err),
				})
			}
		}

		prevID = cp.CheckpointID
	}
}
