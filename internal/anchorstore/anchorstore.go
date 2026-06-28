// Package anchorstore is the Postgres working copy of checkpoints and the notary
// proofs we hold. It is the operator's fast, queryable record of what has been
// anchored — NOT the source of truth for verification. Verification trusts the
// WORM store (S3 Object Lock) and the self-verifying notary proofs; this table
// is mutable convenience state (e.g. to know where to resume anchoring).
package anchorstore

import (
	"context"
	"encoding/hex"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mythforge/multi-log/internal/checkpoint"
	"github.com/mythforge/multi-log/internal/witness"
)

// Store is the Postgres-backed checkpoint + proof working copy.
type Store struct {
	pool *pgxpool.Pool
}

func New(ctx context.Context, dsn string) (*Store, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, err
	}
	return &Store{pool: pool}, nil
}

func (s *Store) Close()                         { s.pool.Close() }
func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

// InitSchema creates the checkpoint and proof tables if absent.
func (s *Store) InitSchema(ctx context.Context) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS checkpoints (
			tenant_id     text   NOT NULL,
			seq_start     bigint NOT NULL,
			seq_end       bigint NOT NULL,
			entry_count   bigint NOT NULL,
			checkpoint_id text   NOT NULL,
			anchored_at   bigint NOT NULL,
			document      jsonb  NOT NULL,
			worm_stored   boolean NOT NULL DEFAULT false,
			created_at    timestamptz NOT NULL DEFAULT now(),
			PRIMARY KEY (tenant_id, seq_end)
		)`,
		`CREATE TABLE IF NOT EXISTS checkpoint_proofs (
			tenant_id  text  NOT NULL,
			seq_end    bigint NOT NULL,
			notary     text  NOT NULL,
			format     text  NOT NULL,
			token      bytea NOT NULL,
			created_at timestamptz NOT NULL DEFAULT now(),
			PRIMARY KEY (tenant_id, seq_end, notary)
		)`,
	}
	for _, q := range stmts {
		if _, err := s.pool.Exec(ctx, q); err != nil {
			return err
		}
	}
	return nil
}

// LastCheckpoint returns the highest-seq checkpoint recorded for a tenant, so
// the anchorer knows where to resume and what to chain from.
func (s *Store) LastCheckpoint(ctx context.Context, tenantID string) (seqEnd uint64, checkpointID []byte, found bool, err error) {
	var (
		end uint64
		idH string
	)
	err = s.pool.QueryRow(ctx,
		"SELECT seq_end, checkpoint_id FROM checkpoints WHERE tenant_id = $1 ORDER BY seq_end DESC LIMIT 1", tenantID).
		Scan(&end, &idH)
	if err == pgx.ErrNoRows {
		return 0, nil, false, nil
	}
	if err != nil {
		return 0, nil, false, err
	}
	id, err := hex.DecodeString(idH)
	if err != nil {
		return 0, nil, false, err
	}
	return end, id, true, nil
}

// PutCheckpoint records a checkpoint's working copy (the full document is the
// same JSON written to WORM).
func (s *Store) PutCheckpoint(ctx context.Context, cp checkpoint.Checkpoint, wormStored bool) error {
	doc, err := checkpoint.Marshal(cp)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx,
		`INSERT INTO checkpoints (tenant_id, seq_start, seq_end, entry_count, checkpoint_id, anchored_at, document, worm_stored)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		 ON CONFLICT (tenant_id, seq_end) DO NOTHING`,
		cp.TenantID, cp.SeqStart, cp.SeqEnd, cp.EntryCount,
		hex.EncodeToString(cp.CheckpointID), cp.AnchoredAt, doc, wormStored)
	return err
}

// PutProof records a notary proof we hold for a checkpoint.
func (s *Store) PutProof(ctx context.Context, tenantID string, seqEnd uint64, p witness.Proof) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO checkpoint_proofs (tenant_id, seq_end, notary, format, token)
		 VALUES ($1,$2,$3,$4,$5)
		 ON CONFLICT (tenant_id, seq_end, notary) DO NOTHING`,
		tenantID, seqEnd, p.Notary, p.Format, p.Token)
	return err
}

// LoadLedger loads all proofs for a tenant into an in-memory ProofLedger for the
// verifier to check.
func (s *Store) LoadLedger(ctx context.Context, tenantID string, ledger *witness.ProofLedger) error {
	rows, err := s.pool.Query(ctx,
		"SELECT seq_end, notary, format, token FROM checkpoint_proofs WHERE tenant_id = $1", tenantID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			seqEnd uint64
			p      witness.Proof
		)
		if err := rows.Scan(&seqEnd, &p.Notary, &p.Format, &p.Token); err != nil {
			return err
		}
		ledger.Add(tenantID, seqEnd, p)
	}
	return rows.Err()
}
