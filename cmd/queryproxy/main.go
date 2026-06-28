// Command queryproxy is the tenant-scoped read API. Every query is bound to the
// tenant resolved from the API key.
//
//	GET /logs?q=&source=&limit=&start=&end=   (header X-API-Key)
package main

import (
	"context"
	"log"
	"net/http"

	"github.com/mythforge/multi-log/internal/config"
	"github.com/mythforge/multi-log/internal/control"
	"github.com/mythforge/multi-log/internal/logstore"
	"github.com/mythforge/multi-log/internal/queryapi"
)

func main() {
	addr := config.Env("ADDR", ":8082")
	ctx := context.Background()

	ctrl, err := control.New(ctx, config.Env("PG_DSN", config.DefaultPGDSN))
	if err != nil {
		log.Fatalf("queryproxy: connect postgres: %v", err)
	}
	defer ctrl.Close()

	store, err := logstore.New(logstore.Config{
		Addr:     config.Env("CH_ADDR", config.DefaultCHAddr),
		Database: config.Env("CH_DB", config.DefaultCHDB),
		Username: config.Env("CH_USER", config.DefaultCHUser),
		Password: config.Env("CH_PASSWORD", config.DefaultCHPassword),
	})
	if err != nil {
		log.Fatalf("queryproxy: connect clickhouse: %v", err)
	}
	defer store.Close()

	handler := queryapi.NewHandler(ctrl, store)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	mux.Handle("GET /logs", handler)

	log.Printf("queryproxy listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
