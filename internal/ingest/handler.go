package ingest

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/mythforge/multi-log/internal/control"
)

// Authenticator resolves an API key to a tenant id.
type Authenticator interface {
	Authenticate(ctx context.Context, key string) (string, error)
}

// Handler is the ingest gateway HTTP handler.
type Handler struct {
	auth   Authenticator
	sealer *Sealer
	now    func() time.Time
}

func NewHandler(auth Authenticator, sealer *Sealer) *Handler {
	return &Handler{auth: auth, sealer: sealer, now: time.Now}
}

// ServeHTTP handles POST /ingest. Authentication is via the X-API-Key header.
// The body may be a JSON array of log objects or newline-delimited JSON (as
// Vector's http sink sends). Each object's log text is taken from a "message"
// or "raw" field, falling back to the whole object; "source" comes from the
// object, then the X-Source header, then "unknown".
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
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

	body, err := io.ReadAll(io.LimitReader(r.Body, 16<<20))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	objs, err := parseLogObjects(body)
	if err != nil {
		http.Error(w, "invalid body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if len(objs) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"accepted": 0, "tenant": tenant})
		return
	}

	defaultSource := r.Header.Get("X-Source")
	ingest := h.now().UnixNano()
	recs := make([]Record, 0, len(objs))
	for _, o := range objs {
		recs = append(recs, recordFromObject(o, defaultSource, ingest))
	}

	entries, err := h.sealer.SealBatch(r.Context(), tenant, recs)
	if err != nil {
		http.Error(w, "ingest failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"accepted":  len(entries),
		"tenant":    tenant,
		"first_seq": entries[0].Seq,
		"last_seq":  entries[len(entries)-1].Seq,
	})
}

// parseLogObjects accepts a JSON array of objects or newline-delimited JSON.
func parseLogObjects(body []byte) ([]map[string]any, error) {
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return nil, nil
	}
	if trimmed[0] == '[' {
		var arr []map[string]any
		if err := json.Unmarshal([]byte(trimmed), &arr); err != nil {
			return nil, err
		}
		return arr, nil
	}
	var out []map[string]any
	sc := bufio.NewScanner(strings.NewReader(trimmed))
	sc.Buffer(make([]byte, 0, 64*1024), 8<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var o map[string]any
		if err := json.Unmarshal([]byte(line), &o); err != nil {
			// Not JSON: treat the raw line as the message.
			o = map[string]any{"message": line}
		}
		out = append(out, o)
	}
	return out, sc.Err()
}

func recordFromObject(o map[string]any, defaultSource string, ingest int64) Record {
	raw := ""
	switch {
	case strVal(o["message"]) != "":
		raw = strVal(o["message"])
	case strVal(o["raw"]) != "":
		raw = strVal(o["raw"])
	default:
		if b, err := json.Marshal(o); err == nil {
			raw = string(b)
		}
	}

	source := strVal(o["source"])
	if source == "" {
		source = defaultSource
	}
	if source == "" {
		source = "unknown"
	}

	event := ingest
	if t := parseTime(o["timestamp"]); t != 0 {
		event = t
	} else if t := parseTime(o["time"]); t != 0 {
		event = t
	}
	return Record{Source: source, Raw: raw, EventTime: event, IngestTime: ingest}
}

func strVal(v any) string {
	s, _ := v.(string)
	return s
}

func parseTime(v any) int64 {
	s, ok := v.(string)
	if !ok || s == "" {
		return 0
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t.UnixNano()
	}
	return 0
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
