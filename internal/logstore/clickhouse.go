// Package logstore is the ClickHouse-backed log store: the durable, searchable
// home for sealed log entries. Entries are ordered by (tenant_id, seq) so each
// tenant's chain is contiguous and per-tenant scans are cheap, and partitioned
// by tenant and ingest day for efficient retention and pruning.
package logstore

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"github.com/mythforge/multi-log/internal/chain"
	"github.com/mythforge/multi-log/internal/crypto"
)

// Config points at a ClickHouse server.
type Config struct {
	Addr     string // host:port of the native protocol (e.g. localhost:9009)
	Database string
	Username string
	Password string
}

// Store reads and writes log entries in ClickHouse.
type Store struct {
	conn driver.Conn
	db   string
}

// New opens a connection. Call InitSchema once before use.
func New(cfg Config) (*Store, error) {
	if cfg.Database == "" {
		cfg.Database = "multilog"
	}
	if cfg.Username == "" {
		cfg.Username = "default"
	}
	conn, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{cfg.Addr},
		Auth: clickhouse.Auth{
			Database: cfg.Database,
			Username: cfg.Username,
			Password: cfg.Password,
		},
	})
	if err != nil {
		return nil, err
	}
	return &Store{conn: conn, db: cfg.Database}, nil
}

func (s *Store) Ping(ctx context.Context) error { return s.conn.Ping(ctx) }
func (s *Store) Close() error                   { return s.conn.Close() }

func (s *Store) table() string { return s.db + ".logs" }

// InitSchema creates the database and logs table if they do not exist.
func (s *Store) InitSchema(ctx context.Context) error {
	if err := s.conn.Exec(ctx, "CREATE DATABASE IF NOT EXISTS "+s.db); err != nil {
		return err
	}
	ddl := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
		tenant_id    String,
		seq          UInt64,
		event_time   DateTime64(9, 'UTC'),
		ingest_time  DateTime64(9, 'UTC'),
		source       String,
		raw          String,
		prev_hash    String,
		entry_hash   String
	) ENGINE = MergeTree
	PARTITION BY (tenant_id, toYYYYMMDD(ingest_time))
	ORDER BY (tenant_id, seq)`, s.table())
	return s.conn.Exec(ctx, ddl)
}

// Append batch-inserts sealed entries. Hashes are stored hex-encoded.
func (s *Store) Append(ctx context.Context, entries []*chain.Entry) error {
	if len(entries) == 0 {
		return nil
	}
	batch, err := s.conn.PrepareBatch(ctx, "INSERT INTO "+s.table())
	if err != nil {
		return err
	}
	for _, e := range entries {
		if err := batch.Append(
			e.TenantID,
			e.Seq,
			time.Unix(0, e.EventTime).UTC(),
			time.Unix(0, e.IngestTime).UTC(),
			e.Source,
			e.Raw,
			hex.EncodeToString(e.PrevHash),
			hex.EncodeToString(e.EntryHash),
		); err != nil {
			return err
		}
	}
	return batch.Send()
}

// Head returns the next sequence number and previous hash for a tenant, so the
// sealer can resume the chain after a restart. For an empty tenant it returns
// seq 0 and the genesis hash.
func (s *Store) Head(ctx context.Context, tenantID string) (nextSeq uint64, prevHash []byte, err error) {
	var (
		seq     uint64
		hashHex string
		found   bool
	)
	rows, err := s.conn.Query(ctx,
		"SELECT seq, entry_hash FROM "+s.table()+" WHERE tenant_id = ? ORDER BY seq DESC LIMIT 1", tenantID)
	if err != nil {
		return 0, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		if err := rows.Scan(&seq, &hashHex); err != nil {
			return 0, nil, err
		}
		found = true
	}
	if err := rows.Err(); err != nil {
		return 0, nil, err
	}
	if !found {
		return 0, crypto.Genesis(tenantID), nil
	}
	prev, err := hex.DecodeString(hashHex)
	if err != nil {
		return 0, nil, err
	}
	return seq + 1, prev, nil
}

// SearchParams scopes a query. Zero-valued fields are ignored, except that the
// caller MUST always supply a tenant id to Search — there is no cross-tenant read.
type SearchParams struct {
	Start  time.Time
	End    time.Time
	Text   string // case-insensitive substring of raw
	Source string
	Limit  int
}

// Search returns matching entries for exactly one tenant, newest first. The
// tenant_id predicate is always applied; it is never optional.
func (s *Store) Search(ctx context.Context, tenantID string, p SearchParams) ([]*chain.Entry, error) {
	where := []string{"tenant_id = ?"}
	args := []any{tenantID}
	if !p.Start.IsZero() {
		where = append(where, "ingest_time >= ?")
		args = append(args, p.Start.UTC())
	}
	if !p.End.IsZero() {
		where = append(where, "ingest_time <= ?")
		args = append(args, p.End.UTC())
	}
	if p.Text != "" {
		where = append(where, "positionCaseInsensitive(raw, ?) > 0")
		args = append(args, p.Text)
	}
	if p.Source != "" {
		where = append(where, "source = ?")
		args = append(args, p.Source)
	}
	limit := p.Limit
	if limit <= 0 || limit > 10000 {
		limit = 1000
	}
	q := fmt.Sprintf(
		"SELECT tenant_id, seq, event_time, ingest_time, source, raw, prev_hash, entry_hash FROM %s WHERE %s ORDER BY seq DESC LIMIT %d",
		s.table(), strings.Join(where, " AND "), limit)

	rows, err := s.conn.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*chain.Entry
	for rows.Next() {
		var (
			e                 chain.Entry
			eventT, ingestT   time.Time
			prevHex, entryHex string
		)
		if err := rows.Scan(&e.TenantID, &e.Seq, &eventT, &ingestT, &e.Source, &e.Raw, &prevHex, &entryHex); err != nil {
			return nil, err
		}
		e.EventTime = eventT.UnixNano()
		e.IngestTime = ingestT.UnixNano()
		if e.PrevHash, err = hex.DecodeString(prevHex); err != nil {
			return nil, err
		}
		if e.EntryHash, err = hex.DecodeString(entryHex); err != nil {
			return nil, err
		}
		out = append(out, &e)
	}
	return out, rows.Err()
}
