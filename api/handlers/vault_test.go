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

func setupTestVaultHandler(t *testing.T) (*VaultHandler, *chi.Mux, string, *db.DB) {
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
	database.Postgres.Exec(ctx, "DELETE FROM vault_blobs")
	database.Postgres.Exec(ctx, "DELETE FROM vault_items")
	database.Postgres.Exec(ctx, "DELETE FROM sessions")
	database.Postgres.Exec(ctx, "DELETE FROM users")
	database.Redis.FlushDB(ctx)

	// Insert a test user
	userID := uuid.Must(uuid.NewRandom())
	salt := make([]byte, 32)
	for i := range salt { salt[i] = byte(i) }
	wrap := make([]byte, 60)
	for i := range wrap { wrap[i] = byte(i) }
	_, err = database.Postgres.Exec(ctx, `
		INSERT INTO users (id, email, zkp_public_key, argon2_salt, argon2_memory, argon2_iterations, argon2_parallelism, vault_key_wrap)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`, userID, "vault@test.com", []byte{1, 2, 3}, salt, 65536, 3, 4, wrap)
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}

	// Generate JWT
	sessionID := uuid.Must(uuid.NewRandom())
	accessToken, err := middleware.GenerateAccessToken(userID, sessionID, []byte(cfg.Auth.JWTSigningKey), time.Hour)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	vh := &VaultHandler{DB: database}
	r := chi.NewRouter()
	r.Use(middleware.JWTAuth([]byte(cfg.Auth.JWTSigningKey)))
	vh.Routes(r)

	return vh, r, accessToken, database
}

func TestVaultCreateAndGetBlob(t *testing.T) {
	_, r, token, _ := setupTestVaultHandler(t)

	blob := []byte("encrypted-test-data")
	reqBody, _ := json.Marshal(VaultItemRequest{
		ItemType: "password",
		Blob:     base64.StdEncoding.EncodeToString(blob),
		BlobSize: len(blob),
		NameHash: base64.StdEncoding.EncodeToString([]byte("name-hash")),
		Tags:     []string{"test", "demo"},
		Favorite: true,
	})

	req := httptest.NewRequest(http.MethodPost, "/items", bytes.NewReader(reqBody))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create item failed: %d %s", rec.Code, rec.Body.String())
	}

	var createResp VaultItemResponse
	json.Unmarshal(rec.Body.Bytes(), &createResp)
	if createResp.ID == uuid.Nil || createResp.BlobID == uuid.Nil {
		t.Fatal("missing id or blob_id in response")
	}

	// Get blob
	req = httptest.NewRequest(http.MethodGet, "/blobs/"+createResp.BlobID.String(), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("get blob failed: %d %s", rec.Code, rec.Body.String())
	}
	if string(rec.Body.Bytes()) != string(blob) {
		t.Fatal("blob data mismatch")
	}
}

func TestVaultUpdateItem(t *testing.T) {
	_, r, token, _ := setupTestVaultHandler(t)

	// Create item
	blob := []byte("encrypted-v1")
	reqBody, _ := json.Marshal(VaultItemRequest{
		ItemType: "password",
		Blob:     base64.StdEncoding.EncodeToString(blob),
		BlobSize: len(blob),
	})
	req := httptest.NewRequest(http.MethodPost, "/items", bytes.NewReader(reqBody))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create item failed: %d %s", rec.Code, rec.Body.String())
	}

	var createResp VaultItemResponse
	json.Unmarshal(rec.Body.Bytes(), &createResp)

	// Update item
	newBlob := []byte("encrypted-v2")
	updateBody, _ := json.Marshal(VaultItemRequest{
		ItemType: "password",
		Blob:     base64.StdEncoding.EncodeToString(newBlob),
		BlobSize: len(newBlob),
	})
	req = httptest.NewRequest(http.MethodPut, "/items/"+createResp.ID.String()+"?expected_version=1", bytes.NewReader(updateBody))
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("update item failed: %d %s", rec.Code, rec.Body.String())
	}

	var updateResp VaultItemResponse
	json.Unmarshal(rec.Body.Bytes(), &updateResp)
	if updateResp.Version != 2 {
		t.Fatalf("expected version 2, got %d", updateResp.Version)
	}

	// Update with wrong version should conflict
	req = httptest.NewRequest(http.MethodPut, "/items/"+createResp.ID.String()+"?expected_version=1", bytes.NewReader(updateBody))
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409 for version conflict, got %d", rec.Code)
	}
}

func TestVaultDeleteAndSync(t *testing.T) {
	_, r, token, _ := setupTestVaultHandler(t)

	// Create item
	blob := []byte("encrypted-delete-me")
	reqBody, _ := json.Marshal(VaultItemRequest{
		ItemType: "secure_note",
		Blob:     base64.StdEncoding.EncodeToString(blob),
		BlobSize: len(blob),
	})
	req := httptest.NewRequest(http.MethodPost, "/items", bytes.NewReader(reqBody))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create item failed: %d %s", rec.Code, rec.Body.String())
	}

	var createResp VaultItemResponse
	json.Unmarshal(rec.Body.Bytes(), &createResp)

	// Delete item
	req = httptest.NewRequest(http.MethodDelete, "/items/"+createResp.ID.String(), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete item failed: %d %s", rec.Code, rec.Body.String())
	}

	// Sync should show deleted item
	req = httptest.NewRequest(http.MethodGet, "/sync?include_deleted=true", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("sync failed: %d %s", rec.Code, rec.Body.String())
	}

	var syncResp SyncResponse
	json.Unmarshal(rec.Body.Bytes(), &syncResp)
	if len(syncResp.DeletedIDs) != 1 {
		t.Fatalf("expected 1 deleted id, got %d", len(syncResp.DeletedIDs))
	}
	if syncResp.DeletedIDs[0] != createResp.ID {
		t.Fatal("deleted id mismatch")
	}
}
