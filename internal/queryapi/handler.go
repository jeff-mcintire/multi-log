// Package queryapi is the tenant-scoped read API. Every query is bound to the
// tenant resolved from the API key; there is no code path that reads across
// tenants. This is the enforcement point the design relies on — never let a
// caller reach the log store without a tenant filter.
package queryapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/mythforge/multi-log/internal/chain"
	"github.com/mythforge/multi-log/internal/control"
	"github.com/mythforge/multi-log/internal/logstore"
)

// Searcher runs a tenant-scoped search.
type Searcher interface {
	Search(ctx context.Context, tenantID string, p logstore.SearchParams) ([]*chain.Entry, error)
}

// Authenticator resolves an API key to a tenant id.
type Authenticator interface {
	Authenticate(ctx context.Context, key string) (string, error)
}

// Handler serves GET /logs.
type Handler struct {
	auth  Authenticator
	store Searcher
}

func NewHandler(auth Authenticator, store Searcher) *Handler {
	return &Handler{auth: auth, store: store}
}

type logView struct {
	Seq        uint64 `json:"seq"`
	EventTime  string `json:"event_time"`
	IngestTime string `json:"ingest_time"`
	Source     string `json:"source"`
	Raw        string `json:"raw"`
	EntryHash  string `json:"entry_hash"`
}

// ServeHTTP handles GET /logs. Query params: q (substring), source, limit,
// start, end (RFC3339 or unix seconds). Auth via the X-API-Key header.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	key := r.Header.Get("X-API-Key")
	if key == "" {
		http.Error(w, "missing X-API-Key", http.StatusUnauthorized)
		return
	}
	tenant, err := h.auth.Authenticate(r.Context(), key)
	if errors.Is(err, control.ErrUnauthorized) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if err != nil {
		http.Error(w, "auth error", http.StatusInternalServerError)
		return
	}

	q := r.URL.Query()
	p := logstore.SearchParams{
		Text:   q.Get("q"),
		Source: q.Get("source"),
	}
	if l := q.Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil {
			p.Limit = n
		}
	}
	if s := q.Get("start"); s != "" {
		p.Start = parseTime(s)
	}
	if e := q.Get("end"); e != "" {
		p.End = parseTime(e)
	}

	entries, err := h.store.Search(r.Context(), tenant, p)
	if err != nil {
		http.Error(w, "query failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	views := make([]logView, 0, len(entries))
	for _, e := range entries {
		views = append(views, logView{
			Seq:        e.Seq,
			EventTime:  time.Unix(0, e.EventTime).UTC().Format(time.RFC3339Nano),
			IngestTime: time.Unix(0, e.IngestTime).UTC().Format(time.RFC3339Nano),
			Source:     e.Source,
			Raw:        e.Raw,
			EntryHash:  hexShort(e.EntryHash),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"tenant": tenant,
		"count":  len(views),
		"logs":   views,
	})
}

func parseTime(s string) time.Time {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t
	}
	if sec, err := strconv.ParseInt(s, 10, 64); err == nil {
		return time.Unix(sec, 0).UTC()
	}
	return time.Time{}
}

func hexShort(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, hexdigits[c>>4], hexdigits[c&0x0f])
	}
	return string(out)
}
