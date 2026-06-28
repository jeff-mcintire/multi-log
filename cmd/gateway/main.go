// Command gateway is the ingest gateway: authenticated, tenant-tagging log
// intake that seals each entry and writes it to ClickHouse.
//
//	POST /ingest   (header X-API-Key)   body: JSON array or NDJSON of log objects
//
// Phase 1 runs a single instance so the sealer is the sole writer per tenant.
package main

import (
	"context"
	"log"
	"net/http"

	"github.com/mythforge/multi-log/internal/config"
	"github.com/mythforge/multi-log/internal/control"
	"github.com/mythforge/multi-log/internal/ingest"
	"github.com/mythforge/multi-log/internal/logstore"
)

func main() {
	addr := config.Env("ADDR", ":8080")
	ctx := context.Background()

	ctrl, err := control.New(ctx, config.Env("PG_DSN", config.DefaultPGDSN))
	if err != nil {
		log.Fatalf("gateway: connect postgres: %v", err)
	}
	defer ctrl.Close()
	// The control-plane schema is owned and created by the controlplane service;
	// the gateway only reads it (for auth), so it does not init it here. This
	// avoids concurrent CREATE TABLE races across services.

	store, err := logstore.New(logstore.Config{
		Addr:     config.Env("CH_ADDR", config.DefaultCHAddr),
		Database: config.Env("CH_DB", config.DefaultCHDB),
		Username: config.Env("CH_USER", config.DefaultCHUser),
		Password: config.Env("CH_PASSWORD", config.DefaultCHPassword),
	})
	if err != nil {
		log.Fatalf("gateway: connect clickhouse: %v", err)
	}
	defer store.Close()
	if err := store.InitSchema(ctx); err != nil {
		log.Fatalf("gateway: init clickhouse schema: %v", err)
	}

	handler := ingest.NewHandler(ctrl, ingest.NewSealer(store))

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	mux.Handle("POST /ingest", handler)

	log.Printf("gateway listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
