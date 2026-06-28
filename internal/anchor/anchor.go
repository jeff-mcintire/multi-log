// Package anchor turns newly-sealed log entries into checkpoints anchored to the
// independent witnesses. Each run, per tenant, it reads entries sealed since the
// last checkpoint, batches them into windows, and for each window writes the
// checkpoint to the WORM store + the Postgres working copy, and stamps its id
// with every notary (storing the proofs). Checkpoints chain via prev id, and
// each commits to its entry count so deletion/truncation is detectable.
package anchor

import (
	"context"
	"errors"
	"time"

	"github.com/mythforge/multi-log/internal/anchorstore"
	"github.com/mythforge/multi-log/internal/checkpoint"
	"github.com/mythforge/multi-log/internal/logstore"
	"github.com/mythforge/multi-log/internal/witness"
)

// Anchorer anchors checkpoints for all tenants.
type Anchorer struct {
	Logs      *logstore.Store
	CPs       *anchorstore.Store
	WORM      witness.CheckpointStore
	Notaries  []witness.Notary
	WindowMax int              // max entries per checkpoint
	Now       func() time.Time // trusted clock; defaults to time.Now
}

func (a *Anchorer) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

func (a *Anchorer) windowMax() int {
	if a.WindowMax > 0 {
		return a.WindowMax
	}
	return 1000
}

// AnchorAll anchors pending entries for every tenant and returns the number of
// checkpoints written.
func (a *Anchorer) AnchorAll(ctx context.Context) (int, error) {
	tenants, err := a.Logs.Tenants(ctx)
	if err != nil {
		return 0, err
	}
	total := 0
	for _, t := range tenants {
		n, err := a.AnchorTenant(ctx, t)
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// AnchorTenant anchors all entries sealed since the tenant's last checkpoint.
func (a *Anchorer) AnchorTenant(ctx context.Context, tenant string) (int, error) {
	lastEnd, prevID, found, err := a.CPs.LastCheckpoint(ctx, tenant)
	if err != nil {
		return 0, err
	}
	start := uint64(0)
	if found {
		start = lastEnd + 1
	}

	entries, err := a.Logs.EntriesAsc(ctx, tenant, start, 0)
	if err != nil {
		return 0, err
	}
	if len(entries) == 0 {
		return 0, nil
	}

	anchored := 0
	for i := 0; i < len(entries); i += a.windowMax() {
		end := i + a.windowMax()
		if end > len(entries) {
			end = len(entries)
		}
		cp := checkpoint.Build(tenant, entries[i:end], prevID, a.now().UnixNano())

		// WORM first (the authoritative, immutable anchor). An immutable-overwrite
		// error means this window was already anchored — treat as done.
		if err := a.WORM.Put(cp); err != nil && !errors.Is(err, witness.ErrImmutable) {
			return anchored, err
		}
		if err := a.CPs.PutCheckpoint(ctx, cp, true); err != nil {
			return anchored, err
		}
		for _, nt := range a.Notaries {
			p, err := nt.Stamp(cp.CheckpointID)
			if err != nil {
				return anchored, err
			}
			if err := a.CPs.PutProof(ctx, tenant, cp.SeqEnd, p); err != nil {
				return anchored, err
			}
		}

		prevID = cp.CheckpointID
		anchored++
	}
	return anchored, nil
}
