package models

import (
	"time"

	"github.com/google/uuid"
)

// User represents a registered user.
type User struct {
	ID                 uuid.UUID  `json:"id" db:"id"`
	Email              string     `json:"email" db:"email"`
	ZkpPublicKey       []byte     `json:"-" db:"zkp_public_key"`
	Argon2Salt         []byte     `json:"-" db:"argon2_salt"`
	Argon2Memory       int        `json:"-" db:"argon2_memory"`
	Argon2Iterations   int        `json:"-" db:"argon2_iterations"`
	Argon2Parallelism  int        `json:"-" db:"argon2_parallelism"`
	VaultKeyWrap       []byte     `json:"-" db:"vault_key_wrap"`
	MfaEnabled         bool       `json:"mfa_enabled" db:"mfa_enabled"`
	MfaType            *string    `json:"mfa_type,omitempty" db:"mfa_type"`
	FailedLoginAttempts int       `json:"-" db:"failed_login_attempts"`
	LockedUntil        *time.Time `json:"-" db:"locked_until"`
	LastLoginAt        *time.Time `json:"last_login_at,omitempty" db:"last_login_at"`
	EmailVerified      bool       `json:"email_verified" db:"email_verified"`
	CreatedAt          time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at" db:"updated_at"`
	DeletedAt          *time.Time `json:"-" db:"deleted_at"`
	StorageUsedBytes   int64      `json:"storage_used_bytes" db:"storage_used_bytes"`
	StorageQuotaBytes  int64      `json:"storage_quota_bytes" db:"storage_quota_bytes"`
	Version            int        `json:"version" db:"version"`
}

// VaultItem represents an encrypted vault item stored on the server.
type VaultItem struct {
	ID         uuid.UUID  `json:"id" db:"id"`
	UserID     uuid.UUID  `json:"user_id" db:"user_id"`
	BlobID     uuid.UUID  `json:"blob_id" db:"blob_id"`
	BlobSize   int        `json:"blob_size" db:"blob_size"`
	ItemType   string     `json:"item_type" db:"item_type"`
	NameHash   []byte     `json:"-" db:"name_hash"`
	ParentID   *uuid.UUID `json:"parent_id,omitempty" db:"parent_id"`
	CreatedAt  time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at" db:"updated_at"`
	DeletedAt  *time.Time `json:"-" db:"deleted_at"`
	Version    int        `json:"version" db:"version"`
	Tags       []string   `json:"tags" db:"tags"`
	Favorite   bool       `json:"favorite" db:"favorite"`
}

// ShareLink represents a time-bounded share link.
type ShareLink struct {
	ID                uuid.UUID  `json:"share_id" db:"id"`
	CreatorID         uuid.UUID  `json:"creator_id" db:"creator_id"`
	BlobID            uuid.UUID  `json:"blob_id" db:"blob_id"`
	Expiry            time.Time  `json:"expiry" db:"expiry"`
	MaxUses           int        `json:"max_uses" db:"max_uses"`
	UsedCount         int        `json:"used_count" db:"used_count"`
	Hmac              []byte     `json:"-" db:"hmac"`
	Revoked           bool       `json:"revoked" db:"revoked"`
	RevokedAt         *time.Time `json:"-" db:"revoked_at"`
	RevokedBy         *uuid.UUID `json:"-" db:"revoked_by"`
	PasswordProtected bool       `json:"password_protected" db:"password_protected"`
	PasswordHint      *string    `json:"password_hint,omitempty" db:"password_hint"`
	CreatedAt         time.Time  `json:"created_at" db:"created_at"`
	LastUsedAt        *time.Time `json:"-" db:"last_used_at"`
	LastUsedIP        *string    `json:"-" db:"last_used_ip"`
}

// Session represents an authenticated user session.
type Session struct {
	ID             uuid.UUID  `json:"id" db:"id"`
	UserID         uuid.UUID  `json:"user_id" db:"user_id"`
	RefreshTokenHash []byte   `json:"-" db:"refresh_token_hash"`
	CreatedAt      time.Time  `json:"created_at" db:"created_at"`
	ExpiresAt      time.Time  `json:"expires_at" db:"expires_at"`
	LastUsedAt     *time.Time `json:"last_used_at,omitempty" db:"last_used_at"`
	LastUsedIP     *string    `json:"-" db:"last_used_ip"`
	UserAgent      *string    `json:"-" db:"user_agent"`
	Revoked        bool       `json:"-" db:"revoked"`
	RevokedAt      *time.Time `json:"-" db:"revoked_at"`
	DeviceID       *string    `json:"device_id,omitempty" db:"device_id"`
	DeviceName     *string    `json:"device_name,omitempty" db:"device_name"`
}

// AuditLogEntry represents an immutable audit log record.
type AuditLogEntry struct {
	ID           int64      `json:"id" db:"id"`
	UserID       *uuid.UUID `json:"user_id,omitempty" db:"user_id"`
	Action       string     `json:"action" db:"action"`
	IPAddress    *string    `json:"-" db:"ip_address"`
	UserAgent    *string    `json:"-" db:"user_agent"`
	SessionID    *uuid.UUID `json:"-" db:"session_id"`
	Success      bool       `json:"success" db:"success"`
	FailureReason *string   `json:"failure_reason,omitempty" db:"failure_reason"`
	Details      map[string]interface{} `json:"details,omitempty" db:"details"`
	Timestamp    time.Time  `json:"timestamp" db:"timestamp"`
}

// HIBPCacheEntry represents a cached HIBP prefix response.
type HIBPCacheEntry struct {
	Prefix     string    `json:"prefix" db:"prefix"`
	Suffixes   []byte    `json:"suffixes" db:"suffixes"`
	CachedAt   time.Time `json:"cached_at" db:"cached_at"`
	ExpiresAt  time.Time `json:"expires_at" db:"expires_at"`
}
