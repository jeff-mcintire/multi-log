//go:build integration

// End-to-end test of the Phase 1 data plane against real ClickHouse + Postgres.
//
//	docker compose -f deploy/docker-compose.yml up -d clickhouse postgres
//	go test -tags integration ./internal/dataplane/...
//
// Override endpoints with PG_DSN / CH_ADDR if not using the compose defaults.
package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/mythforge/multi-log/internal/control"
	"github.com/mythforge/multi-log/internal/ingest"
	"github.com/mythforge/multi-log/internal/logstore"
	"github.com/mythforge/multi-log/internal/queryapi"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func TestDataPlaneEndToEnd(t *testing.T) {
	ctx := context.Background()

	ctrl, err := control.New(ctx, env("PG_DSN", "postgres://postgres:postgres@localhost:5434/multilog"))
	if err != nil {
		t.Fatalf("postgres connect (is it up?): %v", err)
	}
	defer ctrl.Close()
	if err := ctrl.InitSchema(ctx); err != nil {
		t.Fatalf("control schema: %v", err)
	}

	store, err := logstore.New(logstore.Config{
		Addr:     env("CH_ADDR", "localhost:9009"),
		Database: "multilog",
		Username: env("CH_USER", "multilog"),
		Password: env("CH_PASSWORD", "multilog"),
	})
	if err != nil {
		t.Fatalf("clickhouse connect: %v", err)
	}
	defer store.Close()
	if err := store.InitSchema(ctx); err != nil {
		t.Fatalf("clickhouse schema (is it up?): %v", err)
	}

	// Two tenants with unique ids so repeated runs stay isolated.
	suffix := time.Now().UnixNano()
	acme := fmt.Sprintf("acme-%d", suffix)
	globex := fmt.Sprintf("globex-%d", suffix)
	for _, id := range []string{acme, globex} {
		if err := ctrl.CreateTenant(ctx, id, id); err != nil {
			t.Fatalf("create tenant %s: %v", id, err)
		}
	}
	acmeKey, err := ctrl.IssueAPIKey(ctx, acme)
	if err != nil {
		t.Fatal(err)
	}
	globexKey, err := ctrl.IssueAPIKey(ctx, globex)
	if err != nil {
		t.Fatal(err)
	}

	gw := httptest.NewServer(ingest.NewHandler(ctrl, ingest.NewSealer(store)))
	defer gw.Close()
	qp := httptest.NewServer(queryapi.NewHandler(ctrl, store))
	defer qp.Close()

	// Ingest distinct logs for each tenant.
	ingestLogs(t, gw.URL, acmeKey, `[
		{"source":"api","message":"user alice login"},
		{"source":"authz","message":"permission denied for bob"},
		{"source":"api","message":"invoice INV-1001 created"}
	]`)
	ingestLogs(t, gw.URL, globexKey, `[
		{"source":"app","message":"order G-501 placed"},
		{"source":"host","message":"disk usage high on /var"}
	]`)

	// Each tenant sees only its own logs.
	acmeLogs := queryLogs(t, qp.URL, acmeKey, "")
	if acmeLogs.Count != 3 {
		t.Fatalf("acme expected 3 logs, got %d", acmeLogs.Count)
	}
	globexLogs := queryLogs(t, qp.URL, globexKey, "")
	if globexLogs.Count != 2 {
		t.Fatalf("globex expected 2 logs, got %d", globexLogs.Count)
	}

	// Isolation: acme must never see globex content.
	for _, l := range acmeLogs.Logs {
		if bytesContains(l.Raw, "order G-501") || bytesContains(l.Raw, "disk usage") {
			t.Fatalf("ISOLATION BREACH: acme saw globex log: %q", l.Raw)
		}
	}

	// Search filter (substring).
	if got := queryLogs(t, qp.URL, acmeKey, "?q=permission"); got.Count != 1 {
		t.Fatalf("text search expected 1, got %d", got.Count)
	}
	// Source filter scoped per tenant: acme has no "app" source, globex has one.
	if got := queryLogs(t, qp.URL, acmeKey, "?source=app"); got.Count != 0 {
		t.Fatalf("acme source=app expected 0, got %d", got.Count)
	}
	if got := queryLogs(t, qp.URL, globexKey, "?source=app"); got.Count != 1 {
		t.Fatalf("globex source=app expected 1, got %d", got.Count)
	}

	// Sequence + chain present: seqs are 0..2 and entry hashes are populated.
	seen := map[uint64]bool{}
	for _, l := range acmeLogs.Logs {
		seen[l.Seq] = true
		if l.EntryHash == "" {
			t.Fatal("expected entry_hash to be populated")
		}
	}
	for s := uint64(0); s < 3; s++ {
		if !seen[s] {
			t.Fatalf("missing seq %d in acme logs", s)
		}
	}

	// AuthZ: no key and a bogus key are rejected.
	if code := rawStatus(t, http.MethodGet, qp.URL+"/logs", ""); code != http.StatusUnauthorized {
		t.Fatalf("missing key: expected 401, got %d", code)
	}
	if code := rawStatus(t, http.MethodGet, qp.URL+"/logs", "mlog_bogus"); code != http.StatusUnauthorized {
		t.Fatalf("bogus key: expected 401, got %d", code)
	}

	t.Logf("OK: acme=%d globex=%d logs, isolation + search + authz verified", acmeLogs.Count, globexLogs.Count)
}

type logResp struct {
	Tenant string `json:"tenant"`
	Count  int    `json:"count"`
	Logs   []struct {
		Seq       uint64 `json:"seq"`
		Source    string `json:"source"`
		Raw       string `json:"raw"`
		EntryHash string `json:"entry_hash"`
	} `json:"logs"`
}

func ingestLogs(t *testing.T, baseURL, key, body string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, baseURL+"/ingest", bytes.NewReader([]byte(body)))
	req.Header.Set("X-API-Key", key)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("ingest status %d: %s", resp.StatusCode, b)
	}
}

func queryLogs(t *testing.T, baseURL, key, query string) logResp {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, baseURL+"/logs"+query, nil)
	req.Header.Set("X-API-Key", key)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("query status %d: %s", resp.StatusCode, b)
	}
	var lr logResp
	if err := json.NewDecoder(resp.Body).Decode(&lr); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return lr
}

func rawStatus(t *testing.T, method, url, key string) int {
	t.Helper()
	req, _ := http.NewRequest(method, url, nil)
	if key != "" {
		req.Header.Set("X-API-Key", key)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func bytesContains(haystack, needle string) bool {
	return bytes.Contains([]byte(haystack), []byte(needle))
}
