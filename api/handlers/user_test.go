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

func setupTestUserHandler(t *testing.T) (*UserHandler, *chi.Mux, string, *db.DB) {
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
		INSERT INTO users (id, email, zkp_public_key, argon2_salt, argon2_memory, argon2_iterations, argon2_parallelism, vault_key_wrap,
		                   storage_used_bytes, storage_quota_bytes, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())
	`, userID, "user@test.com", []byte{1, 2, 3}, salt, 65536, 3, 4, wrap, 1024, 1073741824)
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}

	sessionID := uuid.Must(uuid.NewRandom())
	accessToken, err := middleware.GenerateAccessToken(userID, sessionID, []byte(cfg.Auth.JWTSigningKey), time.Hour)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	uh := &UserHandler{DB: database}
	r := chi.NewRouter()
	r.Use(middleware.JWTAuth([]byte(cfg.Auth.JWTSigningKey)))
	uh.Routes(r)

	return uh, r, accessToken, database
}

func TestUserGetMe(t *testing.T) {
	_, r, token, _ := setupTestUserHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("get me failed: %d %s", rec.Code, rec.Body.String())
	}

	var resp UserMeResponse
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Email != "user@test.com" {
		t.Fatalf("expected user@test.com, got %s", resp.Email)
	}
	if resp.StorageUsedBytes != 1024 {
		t.Fatalf("expected storage_used_bytes 1024, got %d", resp.StorageUsedBytes)
	}
	if resp.StorageQuotaBytes != 1073741824 {
		t.Fatalf("expected storage_quota_bytes 1073741824, got %d", resp.StorageQuotaBytes)
	}
}

func TestUserUpdatePassword(t *testing.T) {
	_, r, token, _ := setupTestUserHandler(t)

	zkpPK := base64.StdEncoding.EncodeToString(make([]byte, 32))
	wrap := base64.StdEncoding.EncodeToString(make([]byte, 60))
	salt := base64.StdEncoding.EncodeToString(make([]byte, 32))
	reqBody, _ := json.Marshal(UpdatePasswordRequest{
		NewZkpPublicKey: zkpPK,
		NewVaultKeyWrap: wrap,
		NewArgon2Salt:   salt,
	})

	req := httptest.NewRequest(http.MethodPut, "/password", bytes.NewReader(reqBody))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("update password failed: %d %s", rec.Code, rec.Body.String())
	}
}

func TestUserDeleteAccount(t *testing.T) {
	_, r, token, database := setupTestUserHandler(t)

	reqBody, _ := json.Marshal(DeleteAccountRequest{
		Confirmation: "DELETE MY ACCOUNT",
	})

	req := httptest.NewRequest(http.MethodDelete, "/", bytes.NewReader(reqBody))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete account failed: %d %s", rec.Code, rec.Body.String())
	}

	// Verify soft delete
	ctx := t.Context()
	var deletedAt interface{}
	err := database.Postgres.QueryRow(ctx, "SELECT deleted_at FROM users WHERE email LIKE '%.deleted'").Scan(&deletedAt)
	if err != nil || deletedAt == nil {
		t.Fatal("expected user to be soft deleted")
	}
}

func TestUserDeleteAccountWrongConfirmation(t *testing.T) {
	_, r, token, _ := setupTestUserHandler(t)

	reqBody, _ := json.Marshal(DeleteAccountRequest{
		Confirmation: "wrong",
	})

	req := httptest.NewRequest(http.MethodDelete, "/", bytes.NewReader(reqBody))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for wrong confirmation, got %d", rec.Code)
	}
}
