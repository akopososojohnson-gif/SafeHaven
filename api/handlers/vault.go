
package handlers

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/akopososojohnson-gif/safehaven/api/db"
	"github.com/akopososojohnson-gif/safehaven/api/middleware"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// VaultHandler holds vault endpoint dependencies.
type VaultHandler struct {
	DB *db.DB
}

// VaultItemRequest represents a create/update request.
type VaultItemRequest struct {
	ItemType   string   `json:"item_type"`
	Blob       string   `json:"blob"`
	BlobSize   int      `json:"blob_size"`
	NameHash   string   `json:"name_hash,omitempty"`
	ParentID   *string  `json:"parent_id,omitempty"`
	Tags       []string `json:"tags,omitempty"`
	Favorite   bool     `json:"favorite,omitempty"`
}

// VaultItemResponse represents the created/updated item.
type VaultItemResponse struct {
	ID        uuid.UUID `json:"id"`
	BlobID    uuid.UUID `json:"blob_id"`
	Version   int       `json:"version"`
	CreatedAt time.Time `json:"created_at,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

// SyncResponse represents the sync payload.
type SyncResponse struct {
	Items           []VaultItemSync `json:"items"`
	DeletedIDs      []uuid.UUID     `json:"deleted_ids"`
	ServerTimestamp time.Time       `json:"server_timestamp"`
	HasMore         bool            `json:"has_more"`
}

// VaultItemSync is a lightweight item for sync.
type VaultItemSync struct {
	ID          uuid.UUID  `json:"id"`
	BlobID      uuid.UUID  `json:"blob_id"`
	ItemType    string     `json:"item_type"`
	Version     int        `json:"version"`
	UpdatedAt   time.Time  `json:"updated_at"`
	Deleted     bool       `json:"deleted"`
	NameHash    []byte     `json:"name_hash,omitempty"`
	ParentID    *uuid.UUID `json:"parent_id,omitempty"`
	Tags        []string   `json:"tags"`
	Favorite    bool       `json:"favorite"`
}

// Routes mounts vault endpoints.
func (h *VaultHandler) Routes(r chi.Router) {
	r.Get("/sync", h.Sync)
	r.Post("/items", h.CreateItem)
	r.Put("/items/{id}", h.UpdateItem)
	r.Delete("/items/{id}", h.DeleteItem)
	r.Get("/blobs/{blob_id}", h.GetBlob)
}

// Sync returns items changed since the provided timestamp.
func (h *VaultHandler) Sync(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.UserIDFromContext(r.Context())
	if !ok {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	since := r.URL.Query().Get("since")
	includeDeleted := r.URL.Query().Get("include_deleted") == "true"

	ctx := r.Context()
	var items []VaultItemSync
	var deletedIDs []uuid.UUID

	query := `
		SELECT id, blob_id, item_type, version, updated_at, deleted_at IS NOT NULL, name_hash, parent_id, tags, favorite
		FROM vault_items
		WHERE user_id = $1
	`
	var args []interface{}
	args = append(args, userID)

	if since != "" {
		query += ` AND updated_at > $2`
		args = append(args, since)
	}

	if !includeDeleted {
		query += ` AND deleted_at IS NULL`
	}
	query += ` ORDER BY updated_at LIMIT 1000`

	rows, err := h.DB.Postgres.Query(ctx, query, args...)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var item VaultItemSync
		var parentID *uuid.UUID
		if err := rows.Scan(&item.ID, &item.BlobID, &item.ItemType, &item.Version, &item.UpdatedAt, &item.Deleted, &item.NameHash, &parentID, &item.Tags, &item.Favorite); err != nil {
			continue
		}
		item.ParentID = parentID
		if item.Deleted {
			deletedIDs = append(deletedIDs, item.ID)
		} else {
			items = append(items, item)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(SyncResponse{
		Items:           items,
		DeletedIDs:      deletedIDs,
		ServerTimestamp: time.Now().UTC(),
		HasMore:         false,
	})
}

// CreateItem stores a new encrypted vault item.
func (h *VaultHandler) CreateItem(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.UserIDFromContext(r.Context())
	if !ok {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	var req VaultItemRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}

	blob, err := base64.StdEncoding.DecodeString(req.Blob)
	if err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}

	var nameHash []byte
	if req.NameHash != "" {
		nameHash, _ = base64.StdEncoding.DecodeString(req.NameHash)
	}

	var parentID *uuid.UUID
	if req.ParentID != nil {
		pid, err := uuid.Parse(*req.ParentID)
		if err == nil {
			parentID = &pid
		}
	}

	tags := req.Tags
	if tags == nil {
		tags = []string{}
	}

	blobID := uuid.Must(uuid.NewRandom())
	ctx := r.Context()

	// Store blob in Redis temporarily or in Postgres as bytea. For simplicity, store in a blobs table.
	// The spec mentions MinIO/S3 for blobs; for now we use a simple blobs table.
	_, err = h.DB.Postgres.Exec(ctx, `
		INSERT INTO vault_blobs (blob_id, user_id, data) VALUES ($1, $2, $3)
	`, blobID, userID, blob)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	var itemID uuid.UUID
	var version int
	var createdAt time.Time
	err = h.DB.Postgres.QueryRow(ctx, `
		INSERT INTO vault_items (user_id, blob_id, blob_size, item_type, name_hash, parent_id, tags, favorite)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id, version, created_at
	`, userID, blobID, req.BlobSize, req.ItemType, nameHash, parentID, tags, req.Favorite).Scan(&itemID, &version, &createdAt)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(VaultItemResponse{ID: itemID, BlobID: blobID, Version: version, CreatedAt: createdAt})
}

// UpdateItem updates an existing vault item with optimistic locking.
func (h *VaultHandler) UpdateItem(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.UserIDFromContext(r.Context())
	if !ok {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	idStr := chi.URLParam(r, "id")
	itemID, err := uuid.Parse(idStr)
	if err != nil {
		http.Error(w, `{"error":"invalid id"}`, http.StatusBadRequest)
		return
	}

	var req VaultItemRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}

	expectedVersionStr := r.URL.Query().Get("expected_version")
	expectedVersion, _ := strconv.Atoi(expectedVersionStr)

	blob, err := base64.StdEncoding.DecodeString(req.Blob)
	if err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}

	var nameHash []byte
	if req.NameHash != "" {
		nameHash, _ = base64.StdEncoding.DecodeString(req.NameHash)
	}

	var parentID *uuid.UUID
	if req.ParentID != nil {
		pid, err := uuid.Parse(*req.ParentID)
		if err == nil {
			parentID = &pid
		}
	}

	tags := req.Tags
	if tags == nil {
		tags = []string{}
	}

	blobID := uuid.Must(uuid.NewRandom())
	ctx := r.Context()

	_, err = h.DB.Postgres.Exec(ctx, `
		INSERT INTO vault_blobs (blob_id, user_id, data) VALUES ($1, $2, $3)
	`, blobID, userID, blob)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	var version int
	var updatedAt time.Time
	err = h.DB.Postgres.QueryRow(ctx, `
		UPDATE vault_items
		SET blob_id = $1, blob_size = $2, item_type = $3, name_hash = $4, parent_id = $5,
		    tags = $6, favorite = $7, version = version + 1, updated_at = NOW()
		WHERE id = $8 AND user_id = $9 AND version = $10 AND deleted_at IS NULL
		RETURNING version, updated_at
	`, blobID, req.BlobSize, req.ItemType, nameHash, parentID, tags, req.Favorite, itemID, userID, expectedVersion).Scan(&version, &updatedAt)
	if err != nil {
		http.Error(w, `{"error":"version conflict"}`, http.StatusConflict)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(VaultItemResponse{ID: itemID, BlobID: blobID, Version: version, UpdatedAt: updatedAt})
}

// DeleteItem performs a soft delete.
func (h *VaultHandler) DeleteItem(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.UserIDFromContext(r.Context())
	if !ok {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	idStr := chi.URLParam(r, "id")
	itemID, err := uuid.Parse(idStr)
	if err != nil {
		http.Error(w, `{"error":"invalid id"}`, http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	_, err = h.DB.Postgres.Exec(ctx, `
		UPDATE vault_items SET deleted_at = NOW(), version = version + 1, updated_at = NOW()
		WHERE id = $1 AND user_id = $2 AND deleted_at IS NULL
	`, itemID, userID)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// GetBlob returns the raw encrypted blob data.
func (h *VaultHandler) GetBlob(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.UserIDFromContext(r.Context())
	if !ok {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	blobIDStr := chi.URLParam(r, "blob_id")
	blobID, err := uuid.Parse(blobIDStr)
	if err != nil {
		http.Error(w, `{"error":"invalid id"}`, http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	var data []byte
	err = h.DB.Postgres.QueryRow(ctx, `
		SELECT data FROM vault_blobs WHERE blob_id = $1 AND user_id = $2
	`, blobID, userID).Scan(&data)
	if err != nil {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(data)
}
