// Command anchorer periodically checkpoints newly-sealed log entries to the
// independent witnesses (S3 Object Lock WORM + notaries), with a Postgres
// working copy. It runs on a cadence and also exposes POST /anchor to force a
// run on demand (handy for demos).
package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/mythforge/multi-log/internal/anchor"
	"github.com/mythforge/multi-log/internal/anchorstore"
	"github.com/mythforge/multi-log/internal/config"
	"github.com/mythforge/multi-log/internal/logstore"
	"github.com/mythforge/multi-log/internal/witnessbuild"
)

func main() {
	addr := config.Env("ADDR", ":8083")
	interval := durationEnv("ANCHOR_INTERVAL", 10*time.Second)
	window, _ := strconv.Atoi(config.Env("ANCHOR_WINDOW", "1000"))
	ctx := context.Background()

	logs, err := logstore.New(logstore.Config{
		Addr: config.Env("CH_ADDR", config.DefaultCHAddr), Database: config.Env("CH_DB", config.DefaultCHDB),
		Username: config.Env("CH_USER", config.DefaultCHUser), Password: config.Env("CH_PASSWORD", config.DefaultCHPassword),
	})
	if err != nil {
		log.Fatalf("anchorer: clickhouse: %v", err)
	}
	defer logs.Close()

	cps, err := anchorstore.New(ctx, config.Env("PG_DSN", config.DefaultPGDSN))
	if err != nil {
		log.Fatalf("anchorer: postgres: %v", err)
	}
	defer cps.Close()
	if err := cps.InitSchema(ctx); err != nil {
		log.Fatalf("anchorer: init checkpoint schema: %v", err)
	}

	worm, err := witnessbuild.WORM(ctx)
	if err != nil {
		log.Fatalf("anchorer: worm: %v", err)
	}

	a := &anchor.Anchorer{Logs: logs, CPs: cps, WORM: worm, Notaries: witnessbuild.Notaries(), WindowMax: window}

	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			runAnchor(ctx, a)
			<-t.C
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("POST /anchor", func(w http.ResponseWriter, r *http.Request) {
		n, err := a.AnchorAll(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"anchored": n})
	})

	log.Printf("anchorer listening on %s (interval %s, window %d, notaries %s)", addr, interval, window, config.Env("NOTARY_MODE", "mock"))
	log.Fatal(http.ListenAndServe(addr, mux))
}

func runAnchor(ctx context.Context, a *anchor.Anchorer) {
	n, err := a.AnchorAll(ctx)
	if err != nil {
		log.Printf("anchor run error: %v", err)
		return
	}
	if n > 0 {
		log.Printf("anchored %d checkpoint(s)", n)
	}
}

func durationEnv(key string, def time.Duration) time.Duration {
	if d, err := time.ParseDuration(config.Env(key, "")); err == nil && d > 0 {
		return d
	}
	return def
}
