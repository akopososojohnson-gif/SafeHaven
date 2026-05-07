package handlers

import (
	"bytes"
	"encoding/base64"
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

func setupTestShareHandler(t *testing.T) (*ShareHandler, *chi.Mux, string, *db.DB) {
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
	database.Postgres.Exec(ctx, "DELETE FROM share_links")
	database.Postgres.Exec(ctx, "DELETE FROM vault_blobs")
	database.Postgres.Exec(ctx, "DELETE FROM vault_items")
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
	`, userID, "share@test.com", []byte{1, 2, 3}, salt, 65536, 3, 4, wrap)
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}

	sessionID := uuid.Must(uuid.NewRandom())
	accessToken, err := middleware.GenerateAccessToken(userID, sessionID, []byte(cfg.Auth.JWTSigningKey), time.Hour)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	sh := &ShareHandler{DB: database, Config: cfg}
	// Separate routers for authenticated and unauthenticated routes
	authR := chi.NewRouter()
	authR.Use(middleware.JWTAuth([]byte(cfg.Auth.JWTSigningKey)))
	authR.Post("/", sh.CreateShare)
	authR.Delete("/{share_id}", sh.RevokeShare)
	authR.Get("/", sh.ListShares)

	publicR := chi.NewRouter()
	publicR.Get("/{share_id}", sh.RedeemShare)

	return sh, authR, accessToken, database
}

func TestShareCreateAndRedeem(t *testing.T) {
	_, authR, token, _ := setupTestShareHandler(t)

	// We also need the public router for redeeming
	os.Setenv("JWT_SIGNING_KEY", "test-signing-key-32-bytes-long!!!")
	os.Setenv("SHARE_SERVER_SECRET", "test-share-secret-32-bytes-long!!")
	cfg, _ := config.Load()
	database, _ := db.New(cfg)
	defer database.Close()
	sh := &ShareHandler{DB: database, Config: cfg}
	publicR := chi.NewRouter()
	publicR.Get("/{share_id}", sh.RedeemShare)

	blob := []byte("shared-encrypted-data")
	reqBody, _ := json.Marshal(CreateShareRequest{
		Blob:              base64.StdEncoding.EncodeToString(blob),
		BlobSize:          len(blob),
		ExpiryHours:       24,
		MaxUses:           2,
		PasswordProtected: false,
	})

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(reqBody))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	authR.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create share failed: %d %s", rec.Code, rec.Body.String())
	}

	var createResp CreateShareResponse
	json.Unmarshal(rec.Body.Bytes(), &createResp)
	if createResp.ShareID == uuid.Nil {
		t.Fatal("missing share_id in response")
	}

	// Redeem (unauthenticated)
	req = httptest.NewRequest(http.MethodGet, "/"+createResp.ShareID.String(), nil)
	rec = httptest.NewRecorder()
	publicR.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("redeem share failed: %d %s", rec.Code, rec.Body.String())
	}

	var redeemResp ShareResponse
	json.Unmarshal(rec.Body.Bytes(), &redeemResp)
	if redeemResp.Blob != base64.StdEncoding.EncodeToString(blob) {
		t.Fatal("blob mismatch in redeem response")
	}
	if redeemResp.RemainingUses != 1 {
		t.Fatalf("expected remaining uses 1, got %d", redeemResp.RemainingUses)
	}

	// Second redeem should work
	req = httptest.NewRequest(http.MethodGet, "/"+createResp.ShareID.String(), nil)
	rec = httptest.NewRecorder()
	publicR.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("second redeem failed: %d %s", rec.Code, rec.Body.String())
	}

	// Third redeem should be exhausted
	req = httptest.NewRequest(http.MethodGet, "/"+createResp.ShareID.String(), nil)
	rec = httptest.NewRecorder()
	publicR.ServeHTTP(rec, req)
	if rec.Code != http.StatusGone {
		t.Fatalf("expected 410 for exhausted share, got %d", rec.Code)
	}
}

func TestShareRevoke(t *testing.T) {
	_, authR, token, _ := setupTestShareHandler(t)

	blob := []byte("revoke-me")
	reqBody, _ := json.Marshal(CreateShareRequest{
		Blob:        base64.StdEncoding.EncodeToString(blob),
		BlobSize:    len(blob),
		ExpiryHours: 24,
		MaxUses:     1,
	})

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(reqBody))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	authR.ServeHTTP(rec, req)

	var createResp CreateShareResponse
	json.Unmarshal(rec.Body.Bytes(), &createResp)

	// Revoke
	req = httptest.NewRequest(http.MethodDelete, "/"+createResp.ShareID.String(), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	authR.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("revoke failed: %d %s", rec.Code, rec.Body.String())
	}
}
