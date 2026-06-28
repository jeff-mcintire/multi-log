// Command verifier continuously re-verifies the data plane against the witnesses
// and exposes GET /verify for on-demand checks. Any mismatch is logged as an
// alert and returned in the report, pinpointed to a tenant and sequence number.
package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/mythforge/multi-log/internal/anchorstore"
	"github.com/mythforge/multi-log/internal/config"
	"github.com/mythforge/multi-log/internal/logstore"
	"github.com/mythforge/multi-log/internal/verify"
	"github.com/mythforge/multi-log/internal/verifylive"
	"github.com/mythforge/multi-log/internal/witnessbuild"
)

func main() {
	addr := config.Env("ADDR", ":8084")
	interval := durationEnv("VERIFY_INTERVAL", 30*time.Second)
	ctx := context.Background()

	logs, err := logstore.New(logstore.Config{
		Addr: config.Env("CH_ADDR", config.DefaultCHAddr), Database: config.Env("CH_DB", config.DefaultCHDB),
		Username: config.Env("CH_USER", config.DefaultCHUser), Password: config.Env("CH_PASSWORD", config.DefaultCHPassword),
	})
	if err != nil {
		log.Fatalf("verifier: clickhouse: %v", err)
	}
	defer logs.Close()

	cps, err := anchorstore.New(ctx, config.Env("PG_DSN", config.DefaultPGDSN))
	if err != nil {
		log.Fatalf("verifier: postgres: %v", err)
	}
	defer cps.Close()

	worm, err := witnessbuild.WORM(ctx)
	if err != nil {
		log.Fatalf("verifier: worm: %v", err)
	}
	notaries := witnessbuild.Notaries()

	run := func(ctx context.Context) (verify.Report, error) {
		return verifylive.Run(ctx, logs, cps, worm, notaries)
	}

	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			<-t.C
			rep, err := run(ctx)
			if err != nil {
				log.Printf("verify sweep error: %v", err)
				continue
			}
			if rep.OK() {
				log.Printf("verify sweep OK: %d entries, %d checkpoints, %d proofs", rep.EntriesChecked, rep.CheckpointsSeen, rep.ProofsChecked)
			} else {
				log.Printf("ALERT: verification failed with %d issue(s):", len(rep.Issues))
				for _, iss := range rep.Issues {
					log.Printf("  - %s", iss)
				}
			}
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("GET /verify", func(w http.ResponseWriter, r *http.Request) {
		var (
			rep verify.Report
			err error
		)
		if tenant := r.URL.Query().Get("tenant"); tenant != "" {
			rep, err = verifylive.RunTenant(r.Context(), logs, cps, worm, notaries, tenant)
		} else {
			rep, err = run(r.Context())
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeReport(w, rep)
	})

	log.Printf("verifier listening on %s (sweep %s)", addr, interval)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func writeReport(w http.ResponseWriter, rep verify.Report) {
	type issue struct {
		Tenant string `json:"tenant"`
		Seq    uint64 `json:"seq,omitempty"`
		Kind   string `json:"kind"`
		Detail string `json:"detail"`
	}
	issues := make([]issue, 0, len(rep.Issues))
	for _, i := range rep.Issues {
		issues = append(issues, issue{Tenant: i.Tenant, Seq: i.Seq, Kind: i.Kind, Detail: i.Detail})
	}
	w.Header().Set("Content-Type", "application/json")
	status := http.StatusOK
	if !rep.OK() {
		status = http.StatusConflict // 409: tampering detected
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":               rep.OK(),
		"entries_checked":  rep.EntriesChecked,
		"checkpoints_seen": rep.CheckpointsSeen,
		"proofs_checked":   rep.ProofsChecked,
		"issues":           issues,
	})
}

func durationEnv(key string, def time.Duration) time.Duration {
	if d, err := time.ParseDuration(config.Env(key, "")); err == nil && d > 0 {
		return d
	}
	return def
}
