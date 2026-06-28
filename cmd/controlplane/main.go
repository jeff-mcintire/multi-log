// Command controlplane is the tenant + API-key admin API.
//
//	POST /tenants            {"id":"acme-corp","name":"Acme Corp"}
//	GET  /tenants
//	POST /tenants/{id}/keys  -> {"api_key":"mlog_..."}  (shown once)
package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"

	"github.com/mythforge/multi-log/internal/config"
	"github.com/mythforge/multi-log/internal/control"
)

func main() {
	addr := config.Env("ADDR", ":8081")
	ctx := context.Background()

	store, err := control.New(ctx, config.Env("PG_DSN", config.DefaultPGDSN))
	if err != nil {
		log.Fatalf("controlplane: connect postgres: %v", err)
	}
	defer store.Close()
	if err := store.InitSchema(ctx); err != nil {
		log.Fatalf("controlplane: init schema: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })

	mux.HandleFunc("POST /tenants", func(w http.ResponseWriter, r *http.Request) {
		var body struct{ ID, Name string }
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		if err := store.CreateTenant(r.Context(), body.ID, body.Name); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusCreated, map[string]string{"id": body.ID, "name": body.Name})
	})

	mux.HandleFunc("GET /tenants", func(w http.ResponseWriter, r *http.Request) {
		tenants, err := store.ListTenants(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, tenants)
	})

	mux.HandleFunc("POST /tenants/{id}/keys", func(w http.ResponseWriter, r *http.Request) {
		key, err := store.IssueAPIKey(r.Context(), r.PathValue("id"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusCreated, map[string]string{"api_key": key})
	})

	log.Printf("controlplane listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
