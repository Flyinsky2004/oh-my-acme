package agent

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// writeJSON writes v as a JSON response.
func writeJSON(w http.ResponseWriter, v any) {
	if w == nil {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// decodeJSON reads a request body into v, enforcing a size cap to avoid
// memory exhaustion from a large push.
func decodeJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20)) // 1 MiB
	if err := dec.Decode(v); err != nil {
		return err
	}
	return nil
}

func decodeStrictJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 4<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return strings.TrimSpace(s)
}
