package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/akopososojohnson-gif/safehaven/api/config"
	"github.com/akopososojohnson-gif/safehaven/api/db"
	"github.com/akopososojohnson-gif/safehaven/api/middleware"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// mockTransport intercepts HIBP requests for testing.
type mockTransport struct {
	response string
	status   int
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	rec.WriteHeader(m.status)
	rec.WriteString(m.response)
	return rec.Result(), nil
}

func setupTestHIBPHandler(t *testing.T) (*HIBPHandler, *chi.Mux, string, *db.DB) {
	os.Setenv("JWT_SIGNING_KEY", "test-signing-key-32-bytes-long!!!")
	os.Setenv("SHARE_SERVER_SECRET", "test-share-secret-32-bytes-long!!")
	t.Cleanup(func() {
		os.Unsetenv("JWT_SIGNING_KEY")
		os.Unsetenv("SHARE_SERVER_SECRET")
	})

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config load: %v", err)
	}

	database, err := db.New(cfg)
	if err != nil {
		t.Fatalf("db connect: %v", err)
	}
	t.Cleanup(func() { database.Close() })

	ctx := t.Context()
	database.Postgres.Exec(ctx, "DELETE FROM sessions")
	database.Postgres.Exec(ctx, "DELETE FROM users")
	database.Redis.FlushDB(ctx)

	userID := uuid.Must(uuid.NewRandom())
	salt := make([]byte, 32)
	for i := range salt { salt[i] = byte(i) }
	wrap := make([]byte, 60)
	for i := range wrap { wrap[i] = byte(i) }
	_, err = database.Postgres.Exec(ctx, `
		INSERT INTO users (id, email, zkp_public_key, argon2_salt, argon2_memory, argon2_iterations, argon2_parallelism, vault_key_wrap)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`, userID, "hibp@test.com", []byte{1, 2, 3}, salt, 65536, 3, 4, wrap)
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}

	sessionID := uuid.Must(uuid.NewRandom())
	accessToken, err := middleware.GenerateAccessToken(userID, sessionID, []byte(cfg.Auth.JWTSigningKey), time.Hour)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	hh := NewHIBPHandler(database)
	// Override HTTP client with mock
	mockResp := "001F4E:1\n00A3B2:5\nABCD12:0\n"
	hh.Client = &http.Client{
		Transport: &mockTransport{response: mockResp, status: http.StatusOK},
	}

	r := chi.NewRouter()
	r.Use(middleware.JWTAuth([]byte(cfg.Auth.JWTSigningKey)))
	r.Get("/check", hh.Check)

	return hh, r, accessToken, database
}

func TestHIBPCheck(t *testing.T) {
	_, r, token, _ := setupTestHIBPHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/check?prefix=ABCDE", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("hibp check failed: %d %s", rec.Code, rec.Body.String())
	}

	var resp HIBPCheckResponse
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Prefix != "ABCDE" {
		t.Fatalf("expected prefix ABCDE, got %s", resp.Prefix)
	}
	if resp.Cached {
		t.Fatal("expected first request not cached")
	}
	if len(resp.Suffixes) != 3 {
		t.Fatalf("expected 3 suffixes, got %d", len(resp.Suffixes))
	}

	// Second request should be cached
	req = httptest.NewRequest(http.MethodGet, "/check?prefix=ABCDE", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("hibp cached check failed: %d %s", rec.Code, rec.Body.String())
	}

	var cachedResp HIBPCheckResponse
	json.Unmarshal(rec.Body.Bytes(), &cachedResp)
	if !cachedResp.Cached {
		t.Fatal("expected second request to be cached")
	}
}

func TestHIBPCheckInvalidPrefix(t *testing.T) {
	_, r, token, _ := setupTestHIBPHandler(t)

	// Too short
	req := httptest.NewRequest(http.MethodGet, "/check?prefix=ABC", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for short prefix, got %d", rec.Code)
	}

	// Non-hex
	req = httptest.NewRequest(http.MethodGet, "/check?prefix=ABCGH", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for non-hex prefix, got %d", rec.Code)
	}
}

func TestHIBPCheckUnauthenticated(t *testing.T) {
	_, r, _, _ := setupTestHIBPHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/check?prefix=ABCDE", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", rec.Code)
	}
}
