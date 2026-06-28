// Package verifylive runs verification against the live data plane. It reloads
// every tenant's chain from ClickHouse, loads the notary proofs we hold from
// Postgres, and matches both against the WORM store and the notaries using the
// same verify logic the offline demo and the customer CLI use. It trusts only
// the witnesses — never the ClickHouse rows or the proof ledger.
package verifylive

import (
	"context"

	"github.com/mythforge/multi-log/internal/anchorstore"
	"github.com/mythforge/multi-log/internal/chain"
	"github.com/mythforge/multi-log/internal/logstore"
	"github.com/mythforge/multi-log/internal/verify"
	"github.com/mythforge/multi-log/internal/witness"
)

// Load rebuilds an in-memory chain.Store from all ClickHouse entries.
func Load(ctx context.Context, logs *logstore.Store) (*chain.Store, []string, error) {
	tenants, err := logs.Tenants(ctx)
	if err != nil {
		return nil, nil, err
	}
	store := chain.NewStore()
	for _, t := range tenants {
		entries, err := logs.EntriesAsc(ctx, t, 0, 0)
		if err != nil {
			return nil, nil, err
		}
		for _, e := range entries {
			store.Append(e)
		}
	}
	return store, tenants, nil
}

// Run reloads the whole data plane and verifies it against the witnesses.
func Run(
	ctx context.Context,
	logs *logstore.Store,
	cps *anchorstore.Store,
	worm witness.CheckpointStore,
	notaries []witness.Notary,
) (verify.Report, error) {
	_, tenants, err := Load(ctx, logs)
	if err != nil {
		return verify.Report{}, err
	}
	return verifyTenants(ctx, logs, cps, worm, notaries, tenants)
}

// RunTenant verifies a single tenant against the witnesses.
func RunTenant(
	ctx context.Context,
	logs *logstore.Store,
	cps *anchorstore.Store,
	worm witness.CheckpointStore,
	notaries []witness.Notary,
	tenant string,
) (verify.Report, error) {
	return verifyTenants(ctx, logs, cps, worm, notaries, []string{tenant})
}

func verifyTenants(
	ctx context.Context,
	logs *logstore.Store,
	cps *anchorstore.Store,
	worm witness.CheckpointStore,
	notaries []witness.Notary,
	tenants []string,
) (verify.Report, error) {
	store := chain.NewStore()
	ledger := witness.NewProofLedger()
	for _, t := range tenants {
		entries, err := logs.EntriesAsc(ctx, t, 0, 0)
		if err != nil {
			return verify.Report{}, err
		}
		for _, e := range entries {
			store.Append(e)
		}
		if err := cps.LoadLedger(ctx, t, ledger); err != nil {
			return verify.Report{}, err
		}
	}
	return verify.Verify(store, worm, ledger, notaries), nil
}
