package handlers

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"time"

	"github.com/akopososojohnson-gif/safehaven/api/config"
	"github.com/akopososojohnson-gif/safehaven/api/db"
	"github.com/akopososojohnson-gif/safehaven/api/middleware"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// ShareHandler holds share endpoint dependencies.
type ShareHandler struct {
	DB     *db.DB
	Config *config.Config
}

// CreateShareRequest matches the API spec.
type CreateShareRequest struct {
	Blob              string `json:"blob"`
	BlobSize          int    `json:"blob_size"`
	ExpiryHours       int    `json:"expiry_hours"`
	MaxUses           int    `json:"max_uses"`
	PasswordProtected bool   `json:"password_protected"`
	PasswordHint      string `json:"password_hint,omitempty"`
}

// CreateShareResponse matches the API spec.
type CreateShareResponse struct {
	ShareID   uuid.UUID `json:"share_id"`
	CreatedAt time.Time `json:"created_at"`
}

// ShareResponse matches the API spec for redemption.
type ShareResponse struct {
	Blob               string     `json:"blob"`
	Expiry             time.Time  `json:"expiry"`
	RemainingUses      int        `json:"remaining_uses"`
	PasswordProtected  bool       `json:"password_protected"`
	PasswordHint       *string    `json:"password_hint,omitempty"`
}

// ListSharesResponse matches the API spec.
type ListSharesResponse struct {
	Shares []ShareMeta `json:"shares"`
}

// ShareMeta represents share metadata.
type ShareMeta struct {
	ShareID   uuid.UUID `json:"share_id"`
	ItemType  string    `json:"item_type"`
	Expiry    time.Time `json:"expiry"`
	MaxUses   int       `json:"max_uses"`
	UsedCount int       `json:"used_count"`
	Revoked   bool      `json:"revoked"`
	CreatedAt time.Time `json:"created_at"`
}

// Routes mounts share endpoints.
func (h *ShareHandler) Routes(r chi.Router) {
	r.Post("/", h.CreateShare)
	r.Get("/{share_id}", h.RedeemShare)
	r.Delete("/{share_id}", h.RevokeShare)
	r.Get("/", h.ListShares)
}

// CreateShare creates a time-bounded share link.
func (h *ShareHandler) CreateShare(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.UserIDFromContext(r.Context())
	if !ok {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	var req CreateShareRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}

	if req.ExpiryHours < 1 || req.ExpiryHours > 720 {
		req.ExpiryHours = 24
	}
	if req.MaxUses < 1 || req.MaxUses > 100 {
		req.MaxUses = 1
	}

	blob, err := base64.StdEncoding.DecodeString(req.Blob)
	if err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}

	blobID := uuid.Must(uuid.NewRandom())
	expiry := time.Now().Add(time.Duration(req.ExpiryHours) * time.Hour)
	shareID := uuid.Must(uuid.NewRandom())

	ctx := r.Context()

	// Store blob
	_, err = h.DB.Postgres.Exec(ctx, `
		INSERT INTO vault_blobs (blob_id, user_id, data) VALUES ($1, $2, $3)
	`, blobID, userID, blob)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	// Compute HMAC
	hmacVal := computeShareHMAC(h.Config.Share.ServerSecretKey, shareID, expiry, req.MaxUses)

	var hint *string
	if req.PasswordHint != "" {
		hint = &req.PasswordHint
	}

	var createdAt time.Time
	err = h.DB.Postgres.QueryRow(ctx, `
		INSERT INTO share_links (id, creator_id, blob_id, expiry, max_uses, hmac, password_protected, password_hint)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING created_at
	`, shareID, userID, blobID, expiry, req.MaxUses, hmacVal, req.PasswordProtected, hint).Scan(&createdAt)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(CreateShareResponse{ShareID: shareID, CreatedAt: createdAt})
}

// RedeemShare allows a recipient to retrieve a shared encrypted blob.
func (h *ShareHandler) RedeemShare(w http.ResponseWriter, r *http.Request) {
	shareIDStr := chi.URLParam(r, "share_id")
	shareID, err := uuid.Parse(shareIDStr)
	if err != nil {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}

	ctx := r.Context()
	var creatorID uuid.UUID
	var blobID uuid.UUID
	var expiry time.Time
	var maxUses, usedCount int
	var hmacVal []byte
	var revoked bool
	var passwordProtected bool
	var passwordHint *string

	err = h.DB.Postgres.QueryRow(ctx, `
		SELECT creator_id, blob_id, expiry, max_uses, used_count, hmac, revoked, password_protected, password_hint
		FROM share_links WHERE id = $1
	`, shareID).Scan(&creatorID, &blobID, &expiry, &maxUses, &usedCount, &hmacVal, &revoked, &passwordProtected, &passwordHint)
	if err != nil {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}

	if revoked {
		http.Error(w, `{"error":"share revoked"}`, http.StatusGone)
		return
	}
	if expiry.Before(time.Now()) {
		http.Error(w, `{"error":"share expired"}`, http.StatusGone)
		return
	}
	if usedCount >= maxUses {
		http.Error(w, `{"error":"share exhausted"}`, http.StatusGone)
		return
	}

	// Verify HMAC (constant-time)
	expectedHMAC := computeShareHMAC(h.Config.Share.ServerSecretKey, shareID, expiry, maxUses)
	if !hmac.Equal(hmacVal, expectedHMAC) {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}

	// Atomically increment used_count
	_, err = h.DB.Postgres.Exec(ctx, `
		UPDATE share_links SET used_count = used_count + 1, last_used_at = NOW(), last_used_ip = $1
		WHERE id = $2 AND used_count < max_uses
	`, clientIP(r), shareID)
	if err != nil {
		http.Error(w, `{"error":"share exhausted"}`, http.StatusGone)
		return
	}

	// Fetch blob
	var data []byte
	err = h.DB.Postgres.QueryRow(ctx, `
		SELECT data FROM vault_blobs WHERE blob_id = $1
	`, blobID).Scan(&data)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ShareResponse{
		Blob:              base64.StdEncoding.EncodeToString(data),
		Expiry:            expiry,
		RemainingUses:     maxUses - usedCount - 1,
		PasswordProtected: passwordProtected,
		PasswordHint:      passwordHint,
	})
}

// RevokeShare allows the creator to revoke a share.
func (h *ShareHandler) RevokeShare(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.UserIDFromContext(r.Context())
	if !ok {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	shareIDStr := chi.URLParam(r, "share_id")
	shareID, err := uuid.Parse(shareIDStr)
	if err != nil {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}

	ctx := r.Context()
	_, err = h.DB.Postgres.Exec(ctx, `
		UPDATE share_links SET revoked = true, revoked_at = NOW(), revoked_by = $1
		WHERE id = $2 AND creator_id = $3
	`, userID, shareID, userID)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ListShares returns all shares created by the authenticated user.
func (h *ShareHandler) ListShares(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.UserIDFromContext(r.Context())
	if !ok {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	ctx := r.Context()
	rows, err := h.DB.Postgres.Query(ctx, `
		SELECT id, 'password', expiry, max_uses, used_count, revoked, created_at
		FROM share_links WHERE creator_id = $1
		ORDER BY created_at DESC
	`, userID)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var shares []ShareMeta
	for rows.Next() {
		var s ShareMeta
		if err := rows.Scan(&s.ShareID, &s.ItemType, &s.Expiry, &s.MaxUses, &s.UsedCount, &s.Revoked, &s.CreatedAt); err != nil {
			continue
		}
		shares = append(shares, s)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ListSharesResponse{Shares: shares})
}

func computeShareHMAC(secretKey string, shareID uuid.UUID, expiry time.Time, maxUses int) []byte {
	mac := hmac.New(sha256.New, []byte(secretKey))
	mac.Write(shareID[:])
	bs := make([]byte, 8)
	binary.BigEndian.PutUint64(bs, uint64(expiry.Unix()))
	mac.Write(bs)
	mac.Write([]byte{byte(maxUses)})
	return mac.Sum(nil)
}
