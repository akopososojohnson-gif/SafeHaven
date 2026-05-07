package handlers

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"

	"github.com/akopososojohnson-gif/safehaven/api/db"
	"github.com/akopososojohnson-gif/safehaven/api/middleware"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// UserHandler holds user endpoint dependencies.
type UserHandler struct {
	DB *db.DB
}

// UserMeResponse matches the API spec.
type UserMeResponse struct {
	ID                 uuid.UUID  `json:"id"`
	Email              string     `json:"email"`
	MFAEnabled         bool       `json:"mfa_enabled"`
	MFAType            *string    `json:"mfa_type,omitempty"`
	StorageUsedBytes   int64      `json:"storage_used_bytes"`
	StorageQuotaBytes  int64      `json:"storage_quota_bytes"`
	CreatedAt          time.Time  `json:"created_at"`
	LastLoginAt        *time.Time `json:"last_login_at,omitempty"`
}

// UpdatePasswordRequest matches the API spec.
type UpdatePasswordRequest struct {
	NewZkpPublicKey string `json:"new_zkp_public_key"`
	NewVaultKeyWrap string `json:"new_vault_key_wrap"`
	NewArgon2Salt   string `json:"new_argon2_salt"`
}

// DeleteAccountRequest matches the API spec.
type DeleteAccountRequest struct {
	Confirmation string `json:"confirmation"`
}

// Routes mounts user endpoints.
func (h *UserHandler) Routes(r chi.Router) {
	r.Get("/me", h.GetMe)
	r.Put("/password", h.UpdatePassword)
	r.Delete("/", h.DeleteAccount)
}

// GetMe returns the current user's profile.
func (h *UserHandler) GetMe(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.UserIDFromContext(r.Context())
	if !ok {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	ctx := r.Context()
	var resp UserMeResponse
	var lastLogin *time.Time

	err := h.DB.Postgres.QueryRow(ctx, `
		SELECT id, email, mfa_enabled, mfa_type, storage_used_bytes, storage_quota_bytes, created_at, last_login_at
		FROM users WHERE id = $1 AND deleted_at IS NULL
	`, userID).Scan(&resp.ID, &resp.Email, &resp.MFAEnabled, &resp.MFAType, &resp.StorageUsedBytes, &resp.StorageQuotaBytes, &resp.CreatedAt, &lastLogin)
	if err != nil {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}
	resp.LastLoginAt = lastLogin

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// UpdatePassword updates the user's auth parameters after password change.
func (h *UserHandler) UpdatePassword(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.UserIDFromContext(r.Context())
	if !ok {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	var req UpdatePasswordRequest
	if err := middleware.StrictJSONDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}

	zkpPK, err := base64.StdEncoding.DecodeString(req.NewZkpPublicKey)
	if err != nil || len(zkpPK) != 32 {
		http.Error(w, `{"error":"invalid parameters"}`, http.StatusBadRequest)
		return
	}
	salt, err := base64.StdEncoding.DecodeString(req.NewArgon2Salt)
	if err != nil || len(salt) != 32 {
		http.Error(w, `{"error":"invalid parameters"}`, http.StatusBadRequest)
		return
	}
	wrap, err := base64.StdEncoding.DecodeString(req.NewVaultKeyWrap)
	if err != nil || len(wrap) != 60 {
		http.Error(w, `{"error":"invalid parameters"}`, http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	_, err = h.DB.Postgres.Exec(ctx, `
		UPDATE users
		SET zkp_public_key = $1, argon2_salt = $2, vault_key_wrap = $3, updated_at = NOW(), version = version + 1
		WHERE id = $4 AND deleted_at IS NULL
	`, zkpPK, salt, wrap, userID)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// DeleteAccount performs a soft delete.
func (h *UserHandler) DeleteAccount(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.UserIDFromContext(r.Context())
	if !ok {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	var req DeleteAccountRequest
	if err := middleware.StrictJSONDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}

	if req.Confirmation != "DELETE MY ACCOUNT" {
		http.Error(w, `{"error":"invalid confirmation"}`, http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	_, err := h.DB.Postgres.Exec(ctx, `
		UPDATE users SET deleted_at = NOW(), updated_at = NOW(), email = CONCAT(email, '.', EXTRACT(EPOCH FROM NOW())::bigint, '.deleted')
		WHERE id = $1 AND deleted_at IS NULL
	`, userID)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	// Revoke all sessions
	_, _ = h.DB.Postgres.Exec(ctx, `
		UPDATE sessions SET revoked = true, revoked_at = NOW()
		WHERE user_id = $1 AND revoked = false
	`, userID)

	w.WriteHeader(http.StatusNoContent)
}
