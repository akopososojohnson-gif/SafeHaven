package handlers

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/akopososojohnson-gif/safehaven/api/db"
	"github.com/akopososojohnson-gif/safehaven/api/middleware"
)

// HIBPHandler holds HIBP endpoint dependencies.
type HIBPHandler struct {
	DB     *db.DB
	Client *http.Client
}

// HIBPCheckResponse matches the API spec.
type HIBPCheckResponse struct {
	Prefix   string       `json:"prefix"`
	Suffixes []HIBPSuffix `json:"suffixes"`
	Cached   bool         `json:"cached"`
	CachedAt *time.Time   `json:"cached_at,omitempty"`
}

// HIBPSuffix represents a single suffix entry.
type HIBPSuffix struct {
	Suffix string `json:"suffix"`
	Count  int    `json:"count"`
}

// NewHIBPHandler creates a new HIBP handler with a default HTTP client.
func NewHIBPHandler(db *db.DB) *HIBPHandler {
	return &HIBPHandler{
		DB: db,
		Client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Check proxies a k-Anonymity HIBP request.
func (h *HIBPHandler) Check(w http.ResponseWriter, r *http.Request) {
	_, ok := middleware.UserIDFromContext(r.Context())
	if !ok {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	prefix := r.URL.Query().Get("prefix")
	if len(prefix) != 5 {
		http.Error(w, `{"error":"prefix must be 5 hex characters"}`, http.StatusBadRequest)
		return
	}
	prefix = strings.ToUpper(prefix)
	for _, c := range prefix {
		if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F')) {
			http.Error(w, `{"error":"prefix must be hexadecimal"}`, http.StatusBadRequest)
			return
		}
	}

	ctx := r.Context()

	// Check Redis cache
	cached, err := h.DB.Redis.Get(ctx, "hibp:"+prefix).Result()
	if err == nil && cached != "" {
		var resp HIBPCheckResponse
		if json.Unmarshal([]byte(cached), &resp) == nil {
			resp.Cached = true
			now := time.Now()
			resp.CachedAt = &now
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			return
		}
	}

	// Proxy to HIBP
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("https://api.pwnedpasswords.com/range/%s", prefix), nil)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	req.Header.Set("Add-Padding", "true")
	req.Header.Set("User-Agent", "SafeHaven/1.0")

	respHTTP, err := h.Client.Do(req)
	if err != nil {
		http.Error(w, `{"error":"hibp unavailable"}`, http.StatusBadGateway)
		return
	}
	defer respHTTP.Body.Close()

	if respHTTP.StatusCode != http.StatusOK {
		http.Error(w, `{"error":"hibp unavailable"}`, http.StatusBadGateway)
		return
	}

	var suffixes []HIBPSuffix
	scanner := bufio.NewScanner(respHTTP.Body)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		count, _ := strconv.Atoi(parts[1])
		suffixes = append(suffixes, HIBPSuffix{
			Suffix: parts[0],
			Count:  count,
		})
	}

	result := HIBPCheckResponse{
		Prefix:   prefix,
		Suffixes: suffixes,
		Cached:   false,
	}

	// Cache in Redis
	cacheData, _ := json.Marshal(result)
	h.DB.Redis.Set(ctx, "hibp:"+prefix, cacheData, time.Hour)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}
