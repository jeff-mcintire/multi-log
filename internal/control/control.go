// Package control is the Postgres-backed control plane: tenants and their API
// keys. It is the mutable, transactional side of the system (in contrast to the
// append-only log store). API keys are stored only as SHA-256 hashes; the
// plaintext is returned once at creation and never persisted.
package control

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrUnauthorized is returned when an API key is unknown or revoked.
var ErrUnauthorized = errors.New("control: unauthorized")

// Store is the control-plane database.
type Store struct {
	pool *pgxpool.Pool
}

// Tenant is a customer of the logging system.
type Tenant struct {
	ID        string
	Name      string
	CreatedAt time.Time
}

// New connects to Postgres. dsn e.g. postgres://user:pass@host:5432/multilog.
func New(ctx context.Context, dsn string) (*Store, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, err
	}
	return &Store{pool: pool}, nil
}

func (s *Store) Close() { s.pool.Close() }

func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

// InitSchema creates the control-plane tables if they do not exist.
func (s *Store) InitSchema(ctx context.Context) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS tenants (
			id         text PRIMARY KEY,
			name       text NOT NULL,
			created_at timestamptz NOT NULL DEFAULT now()
		)`,
		`CREATE TABLE IF NOT EXISTS api_keys (
			key_hash   text PRIMARY KEY,
			key_prefix text NOT NULL,
			tenant_id  text NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
			created_at timestamptz NOT NULL DEFAULT now(),
			revoked    boolean NOT NULL DEFAULT false
		)`,
		`CREATE INDEX IF NOT EXISTS api_keys_tenant_idx ON api_keys(tenant_id)`,
	}
	for _, q := range stmts {
		if _, err := s.pool.Exec(ctx, q); err != nil {
			return err
		}
	}
	return nil
}

// CreateTenant inserts a tenant. The id is caller-chosen (e.g. "acme-corp").
func (s *Store) CreateTenant(ctx context.Context, id, name string) error {
	if id == "" || name == "" {
		return errors.New("control: tenant id and name are required")
	}
	_, err := s.pool.Exec(ctx,
		"INSERT INTO tenants (id, name) VALUES ($1, $2)", id, name)
	return err
}

// ListTenants returns all tenants, oldest first.
func (s *Store) ListTenants(ctx context.Context) ([]Tenant, error) {
	rows, err := s.pool.Query(ctx, "SELECT id, name, created_at FROM tenants ORDER BY created_at")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Tenant
	for rows.Next() {
		var t Tenant
		if err := rows.Scan(&t.ID, &t.Name, &t.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// IssueAPIKey creates a new API key for a tenant and returns the plaintext key
// exactly once. Only its hash is stored.
func (s *Store) IssueAPIKey(ctx context.Context, tenantID string) (string, error) {
	var exists bool
	if err := s.pool.QueryRow(ctx, "SELECT true FROM tenants WHERE id = $1", tenantID).Scan(&exists); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", fmt.Errorf("control: unknown tenant %q", tenantID)
		}
		return "", err
	}

	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	key := "mlog_" + base64.RawURLEncoding.EncodeToString(raw)
	hash := hashKey(key)
	prefix := key[:12]

	if _, err := s.pool.Exec(ctx,
		"INSERT INTO api_keys (key_hash, key_prefix, tenant_id) VALUES ($1, $2, $3)",
		hash, prefix, tenantID); err != nil {
		return "", err
	}
	return key, nil
}

// Authenticate resolves an API key to its tenant id, or ErrUnauthorized.
func (s *Store) Authenticate(ctx context.Context, key string) (string, error) {
	var (
		tenantID string
		revoked  bool
	)
	err := s.pool.QueryRow(ctx,
		"SELECT tenant_id, revoked FROM api_keys WHERE key_hash = $1", hashKey(key)).
		Scan(&tenantID, &revoked)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrUnauthorized
	}
	if err != nil {
		return "", err
	}
	if revoked {
		return "", ErrUnauthorized
	}
	return tenantID, nil
}

func hashKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}
