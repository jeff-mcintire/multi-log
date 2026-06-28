//go:build integration

// Phase 2 end-to-end: seal -> anchor to the real witnesses -> verify, then tamper
// the actual ClickHouse rows and prove the verifier catches it.
//
//	docker compose -f deploy/docker-compose.yml up -d clickhouse postgres minio
//	go test -tags integration -run TestPhase2 ./internal/dataplane/...
//
// Witnesses: S3 Object Lock via MinIO (WORM) + two mock notaries (deterministic,
// offline). The same notary objects are used to stamp and to verify.
package dataplane

import (
	"context"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"github.com/mythforge/multi-log/internal/anchor"
	"github.com/mythforge/multi-log/internal/anchorstore"
	"github.com/mythforge/multi-log/internal/chain"
	"github.com/mythforge/multi-log/internal/crypto"
	"github.com/mythforge/multi-log/internal/ingest"
	"github.com/mythforge/multi-log/internal/logstore"
	"github.com/mythforge/multi-log/internal/verify"
	"github.com/mythforge/multi-log/internal/witness"
	"github.com/mythforge/multi-log/internal/witness/s3worm"
)

type harness struct {
	logs     *logstore.Store
	cps      *anchorstore.Store
	worm     witness.CheckpointStore
	notaries []witness.Notary
	admin    driver.Conn
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	ctx := context.Background()

	logs, err := logstore.New(logstore.Config{
		Addr: env("CH_ADDR", "localhost:9009"), Database: "multilog",
		Username: env("CH_USER", "multilog"), Password: env("CH_PASSWORD", "multilog"),
	})
	if err != nil {
		t.Fatalf("clickhouse: %v", err)
	}
	if err := logs.InitSchema(ctx); err != nil {
		t.Fatalf("clickhouse schema (is it up?): %v", err)
	}

	cps, err := anchorstore.New(ctx, env("PG_DSN", "postgres://postgres:postgres@localhost:5434/multilog"))
	if err != nil {
		t.Fatalf("postgres: %v", err)
	}
	if err := cps.InitSchema(ctx); err != nil {
		t.Fatalf("anchorstore schema: %v", err)
	}

	worm := s3worm.New(s3worm.Config{
		Region: "us-east-1", Bucket: env("S3_BUCKET", "multilog-worm"),
		AccessKey: "minioadmin", SecretKey: "minioadmin",
		Endpoint: env("S3_ENDPOINT", "http://localhost:9100"), UsePathStyle: true,
		RetainFor: time.Hour,
	})
	if err := worm.EnsureBucket(ctx); err != nil {
		t.Fatalf("minio bucket (is minio up?): %v", err)
	}

	admin, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{env("CH_ADDR", "localhost:9009")},
		Auth: clickhouse.Auth{Database: "multilog", Username: env("CH_USER", "multilog"), Password: env("CH_PASSWORD", "multilog")},
	})
	if err != nil {
		t.Fatalf("clickhouse admin: %v", err)
	}

	return &harness{
		logs: logs, cps: cps, worm: worm, admin: admin,
		notaries: []witness.Notary{
			witness.NewMockNotary("RFC 3161 TSA", "tsa-demo-secret"),
			witness.NewMockNotary("OpenTimestamps (Bitcoin)", "ots-demo-secret"),
		},
	}
}

// sealAndAnchor seals n records for a fresh tenant and anchors them in windows.
func (h *harness) sealAndAnchor(t *testing.T, tenant string, n int) {
	t.Helper()
	ctx := context.Background()
	sealer := ingest.NewSealer(h.logs)
	recs := make([]ingest.Record, n)
	base := time.Now().UnixNano()
	for i := 0; i < n; i++ {
		recs[i] = ingest.Record{
			Source: "api", Raw: fmt.Sprintf(`{"msg":"event %d","tenant":%q}`, i, tenant),
			EventTime: base + int64(i), IngestTime: base + int64(i),
		}
	}
	if _, err := sealer.SealBatch(ctx, tenant, recs); err != nil {
		t.Fatalf("seal: %v", err)
	}
	a := &anchor.Anchorer{Logs: h.logs, CPs: h.cps, WORM: h.worm, Notaries: h.notaries, WindowMax: 5}
	got, err := a.AnchorTenant(ctx, tenant)
	if err != nil {
		t.Fatalf("anchor: %v", err)
	}
	if got == 0 {
		t.Fatal("expected at least one checkpoint to be anchored")
	}
}

// verifyTenant verifies exactly one tenant against the witnesses.
func (h *harness) verifyTenant(t *testing.T, tenant string) verify.Report {
	t.Helper()
	ctx := context.Background()
	store := chain.NewStore()
	entries, err := h.logs.EntriesAsc(ctx, tenant, 0, 0)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	for _, e := range entries {
		store.Append(e)
	}
	ledger := witness.NewProofLedger()
	if err := h.cps.LoadLedger(ctx, tenant, ledger); err != nil {
		t.Fatalf("load ledger: %v", err)
	}
	return verify.Verify(store, h.worm, ledger, h.notaries)
}

// runSQL executes an admin statement against ClickHouse (used to simulate an
// insider tampering with stored rows).
func (h *harness) runSQL(t *testing.T, sql string, args ...any) {
	t.Helper()
	if err := h.admin.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("clickhouse statement failed: %v\n%s", err, sql)
	}
}

func hasKind(r verify.Report, kind string) bool {
	for _, i := range r.Issues {
		if i.Kind == kind {
			return true
		}
	}
	return false
}

func uniqueTenant(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
}

func TestPhase2HonestVerifies(t *testing.T) {
	h := newHarness(t)
	tenant := uniqueTenant("p2-honest")
	h.sealAndAnchor(t, tenant, 12)
	rep := h.verifyTenant(t, tenant)
	if !rep.OK() {
		t.Fatalf("honest data should verify, got: %v", rep.Issues)
	}
	if rep.ProofsChecked == 0 {
		t.Fatal("expected notary proofs to be checked")
	}
	t.Logf("OK: %d entries, %d checkpoints, %d proofs verified against WORM + notaries",
		rep.EntriesChecked, rep.CheckpointsSeen, rep.ProofsChecked)
}

func TestPhase2NaiveEditCaught(t *testing.T) {
	h := newHarness(t)
	tenant := uniqueTenant("p2-naive")
	h.sealAndAnchor(t, tenant, 12)
	if rep := h.verifyTenant(t, tenant); !rep.OK() {
		t.Fatalf("should verify before tampering: %v", rep.Issues)
	}
	// Insider edits a row but forgets to fix the chain.
	h.runSQL(t, "ALTER TABLE multilog.logs UPDATE raw = 'tampered' WHERE tenant_id = ? AND seq = 3 SETTINGS mutations_sync = 2", tenant)
	rep := h.verifyTenant(t, tenant)
	if !hasKind(rep, "entry-tamper") {
		t.Fatalf("expected entry-tamper, got: %v", rep.Issues)
	}
	t.Logf("caught naive edit: %v", rep.Issues)
}

func TestPhase2SophisticatedEditCaught(t *testing.T) {
	h := newHarness(t)
	tenant := uniqueTenant("p2-sophisticated")
	h.sealAndAnchor(t, tenant, 12)
	if rep := h.verifyTenant(t, tenant); !rep.OK() {
		t.Fatalf("should verify before tampering: %v", rep.Issues)
	}

	// Insider edits a row AND recomputes the entire chain in ClickHouse so it is
	// internally consistent — chain replay will pass, but the witnesses won't.
	h.resealWithEdit(t, tenant, 8, `{"msg":"forged","tenant":"`+tenant+`"}`)

	rep := h.verifyTenant(t, tenant)
	if rep.OK() {
		t.Fatal("expected tampering to be detected by the witnesses")
	}
	if !hasKind(rep, "checkpoint-mismatch") {
		t.Fatalf("expected WORM checkpoint-mismatch, got: %v", rep.Issues)
	}
	if !hasKind(rep, "notary-mismatch") {
		t.Fatalf("expected independent notary-mismatch, got: %v", rep.Issues)
	}
	t.Logf("caught sophisticated edit via WORM + notaries: %v", rep.Issues)
}

func TestPhase2TruncationCaught(t *testing.T) {
	h := newHarness(t)
	tenant := uniqueTenant("p2-truncate")
	h.sealAndAnchor(t, tenant, 12)
	if rep := h.verifyTenant(t, tenant); !rep.OK() {
		t.Fatalf("should verify before tampering: %v", rep.Issues)
	}
	// Delete the most recent entry (seq 11). No sequence gap remains, but the
	// checkpoint committed an entry count.
	h.runSQL(t, "ALTER TABLE multilog.logs DELETE WHERE tenant_id = ? AND seq = 11 SETTINGS mutations_sync = 2", tenant)
	rep := h.verifyTenant(t, tenant)
	if !hasKind(rep, "truncation") {
		t.Fatalf("expected truncation, got: %v", rep.Issues)
	}
	t.Logf("caught tail truncation via committed count: %v", rep.Issues)
}

// resealWithEdit rewrites the tenant's rows in ClickHouse so that, after editing
// one entry's raw, the entire hash chain is recomputed and internally consistent
// — exactly what a determined insider with DB access would do.
func (h *harness) resealWithEdit(t *testing.T, tenant string, editSeq uint64, newRaw string) {
	t.Helper()
	ctx := context.Background()
	entries, err := h.logs.EntriesAsc(ctx, tenant, 0, 0)
	if err != nil {
		t.Fatalf("reload for reseal: %v", err)
	}
	prev := crypto.Genesis(tenant)
	for _, e := range entries {
		raw := e.Raw
		if e.Seq == editSeq {
			raw = newRaw
		}
		leaf := crypto.EntryLeaf(tenant, e.Seq, e.EventTime, e.IngestTime, e.Source, raw)
		entryHash := crypto.ChainHash(prev, leaf)
		h.runSQL(t,
			"ALTER TABLE multilog.logs UPDATE raw = ?, prev_hash = ?, entry_hash = ? WHERE tenant_id = ? AND seq = ? SETTINGS mutations_sync = 2",
			raw, hex.EncodeToString(prev), hex.EncodeToString(entryHash), tenant, e.Seq)
		prev = entryHash
	}
}
