package handlers

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/akopososojohnson-gif/safehaven/api/config"
	"github.com/akopososojohnson-gif/safehaven/api/crypto"
	"github.com/akopososojohnson-gif/safehaven/api/db"
	"github.com/akopososojohnson-gif/safehaven/api/middleware"
	"github.com/cloudflare/circl/group"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"
)

// AuthHandler holds auth endpoint dependencies.
type AuthHandler struct {
	DB     *db.DB
	Config *config.Config
}

// RegisterRequest matches the API spec.
type RegisterRequest struct {
	Email             string `json:"email"`
	ZkpPublicKey      string `json:"zkp_public_key"`
	Argon2Salt        string `json:"argon2_salt"`
	Argon2Memory      int    `json:"argon2_memory"`
	Argon2Iterations  int    `json:"argon2_iterations"`
	Argon2Parallelism int    `json:"argon2_parallelism"`
	VaultKeyWrap      string `json:"vault_key_wrap"`
}

// RegisterResponse matches the API spec.
type RegisterResponse struct {
	UserID    uuid.UUID `json:"user_id"`
	CreatedAt time.Time `json:"created_at"`
}

// ChallengeResponse matches the API spec.
type ChallengeResponse struct {
	ChallengeID string `json:"challenge_id"`
	Challenge   string `json:"challenge"`
	ZkpParams   struct {
		Group     string `json:"group"`
		Generator string `json:"generator"`
	} `json:"zkp_params"`
}

// VerifyRequest matches the API spec.
type VerifyRequest struct {
	ChallengeID string `json:"challenge_id"`
	ProofT      string `json:"proof_t"`
	ProofS      string `json:"proof_s"`
}

// VerifyResponse matches the API spec.
type VerifyResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

// RefreshResponse matches the API spec.
type RefreshResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

// Routes mounts auth endpoints.
func (h *AuthHandler) Routes(r chi.Router) {
	r.Post("/register", h.Register)
	r.Post("/challenge", h.Challenge)
	r.Post("/verify", h.Verify)
	r.Post("/refresh", h.Refresh)
	r.Post("/logout", h.Logout)
}

// Register creates a new user.
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}

	// Validate Argon2 parameters
	if req.Argon2Memory < 65536 || req.Argon2Iterations < 3 || req.Argon2Parallelism < 1 {
		http.Error(w, `{"error":"invalid parameters"}`, http.StatusUnprocessableEntity)
		return
	}

	// Decode base64 fields
	zkpPK, err := base64.StdEncoding.DecodeString(req.ZkpPublicKey)
	if err != nil || len(zkpPK) != 32 {
		http.Error(w, `{"error":"invalid parameters"}`, http.StatusBadRequest)
		return
	}
	salt, err := base64.StdEncoding.DecodeString(req.Argon2Salt)
	if err != nil || len(salt) != 32 {
		http.Error(w, `{"error":"invalid parameters"}`, http.StatusBadRequest)
		return
	}
	wrap, err := base64.StdEncoding.DecodeString(req.VaultKeyWrap)
	if err != nil || len(wrap) != 60 {
		http.Error(w, `{"error":"invalid parameters"}`, http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	var userID uuid.UUID
	var createdAt time.Time

	err = h.DB.Postgres.QueryRow(ctx, `
		INSERT INTO users (email, zkp_public_key, argon2_salt, argon2_memory, argon2_iterations, argon2_parallelism, vault_key_wrap)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, created_at
	`, req.Email, zkpPK, salt, req.Argon2Memory, req.Argon2Iterations, req.Argon2Parallelism, wrap).Scan(&userID, &createdAt)

	if err != nil {
		// Generic error to prevent user enumeration
		http.Error(w, `{"error":"invalid parameters"}`, http.StatusConflict)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(RegisterResponse{UserID: userID, CreatedAt: createdAt})
}

// Challenge generates a random ZKP challenge.
func (h *AuthHandler) Challenge(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}

	g := group.Ristretto255
	c := g.RandomScalar(nil)
	challengeBytes, _ := c.MarshalBinary()
	challengeID := uuid.Must(uuid.NewRandom())

	ctx := r.Context()
	pipe := h.DB.Redis.Pipeline()
	pipe.Set(ctx, "challenge:"+challengeID.String(), challengeBytes, h.Config.Auth.ChallengeTTL)
	pipe.Set(ctx, "challenge:email:"+challengeID.String(), req.Email, h.Config.Auth.ChallengeTTL)
	_, err := pipe.Exec(ctx)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	resp := ChallengeResponse{
		ChallengeID: challengeID.String(),
		Challenge:   base64.StdEncoding.EncodeToString(challengeBytes),
		ZkpParams: struct {
			Group     string `json:"group"`
			Generator string `json:"generator"`
		}{
			Group:     "ristretto255",
			Generator: base64.StdEncoding.EncodeToString(mustMarshalGenerator()),
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// Verify checks a ZKP proof and issues tokens.
func (h *AuthHandler) Verify(w http.ResponseWriter, r *http.Request) {
	var req VerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	// Retrieve challenge from Redis
	challengeBytes, err := h.DB.Redis.Get(ctx, "challenge:"+req.ChallengeID).Bytes()
	if err == redis.Nil {
		http.Error(w, `{"error":"invalid credentials"}`, http.StatusGone)
		return
	} else if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	// Delete challenge immediately (single-use)
	h.DB.Redis.Del(ctx, "challenge:"+req.ChallengeID)

	// Decode proof
	proofT, err := base64.StdEncoding.DecodeString(req.ProofT)
	if err != nil || len(proofT) != 32 {
		http.Error(w, `{"error":"invalid credentials"}`, http.StatusUnauthorized)
		return
	}
	proofS, err := base64.StdEncoding.DecodeString(req.ProofS)
	if err != nil || len(proofS) != 32 {
		http.Error(w, `{"error":"invalid credentials"}`, http.StatusUnauthorized)
		return
	}

	// Fetch user by challenge ID is not possible directly, so we need to look up
	// the user associated with this challenge. However, the challenge endpoint
	// doesn't store the email. We need to store it.
	// For now, we'll look up the user from a temporary mapping.
	// Actually, looking at the spec: Client sends {email} to challenge, gets challenge_id.
	// Then client sends {challenge_id, T, s} to verify. The server needs to know which user.
	// We should store email -> challenge mapping, or challenge -> email mapping.

	// Let's store challenge -> email in Redis when generating challenge.
	// For now, this implementation is incomplete without that mapping.
	// We'll fetch the user with the most recent challenge or require email in verify.
	// The spec says verify only sends challenge_id, T, s. So we need the mapping.

	// Re-fetch the email from Redis (stored alongside challenge)
	email, err := h.DB.Redis.Get(ctx, "challenge:email:"+req.ChallengeID).Result()
	if err == redis.Nil || email == "" {
		// Fallback: cannot determine user
		http.Error(w, `{"error":"invalid credentials"}`, http.StatusUnauthorized)
		return
	} else if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	h.DB.Redis.Del(ctx, "challenge:email:"+req.ChallengeID)

	// Fetch user
	var userID uuid.UUID
	var publicKey []byte
	var failedAttempts int
	var lockedUntil *time.Time
	err = h.DB.Postgres.QueryRow(ctx, `
		SELECT id, zkp_public_key, failed_login_attempts, locked_until
		FROM users WHERE email = $1 AND deleted_at IS NULL
	`, email).Scan(&userID, &publicKey, &failedAttempts, &lockedUntil)
	if err != nil {
		http.Error(w, `{"error":"invalid credentials"}`, http.StatusUnauthorized)
		return
	}

	// Check lockout
	if lockedUntil != nil && lockedUntil.After(time.Now()) {
		http.Error(w, `{"error":"account locked"}`, http.StatusForbidden)
		return
	}

	// Verify ZKP
	if err := crypto.VerifySchnorr(publicKey, challengeBytes, proofT, proofS); err != nil {
		// Increment failed attempts
		failedAttempts++
		lockoutUntil := time.Now().Add(h.Config.Auth.LockoutDuration)
		if failedAttempts >= h.Config.Auth.MaxLoginAttempts {
			h.DB.Postgres.Exec(ctx, `UPDATE users SET failed_login_attempts = $1, locked_until = $2 WHERE id = $3`, failedAttempts, lockoutUntil, userID)
		} else {
			h.DB.Postgres.Exec(ctx, `UPDATE users SET failed_login_attempts = $1 WHERE id = $2`, failedAttempts, userID)
		}
		http.Error(w, `{"error":"invalid credentials"}`, http.StatusUnauthorized)
		return
	}

	// Success: reset failed attempts and update last login
	var lastIP interface{}
	if ip := clientIP(r); ip != "" {
		lastIP = ip
	}
	h.DB.Postgres.Exec(ctx, `UPDATE users SET failed_login_attempts = 0, locked_until = NULL, last_login_at = NOW(), last_login_ip = $1 WHERE id = $2`, lastIP, userID)

	// Create session
	sessionID := uuid.Must(uuid.NewRandom())
	refreshToken := uuid.Must(uuid.NewRandom()).String()
	refreshHash := sha256.Sum256([]byte(refreshToken))
	expiresAt := time.Now().Add(h.Config.Auth.RefreshTokenExpiry)

	var sessionIP, sessionUA interface{}
	if ip := clientIP(r); ip != "" {
		sessionIP = ip
	}
	if r.UserAgent() != "" {
		sessionUA = r.UserAgent()
	}
	_, err = h.DB.Postgres.Exec(ctx, `
		INSERT INTO sessions (id, user_id, refresh_token_hash, expires_at, last_used_ip, user_agent)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, sessionID, userID, refreshHash[:], expiresAt, sessionIP, sessionUA)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	// Generate JWT
	accessToken, err := middleware.GenerateAccessToken(userID, sessionID, []byte(h.Config.Auth.JWTSigningKey), h.Config.Auth.AccessTokenExpiry)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(VerifyResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(h.Config.Auth.AccessTokenExpiry.Seconds()),
	})
}

// Refresh issues a new access token from a refresh token.
func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	hdr := r.Header.Get("Authorization")
	if hdr == "" {
		http.Error(w, `{"error":"missing authorization header"}`, http.StatusUnauthorized)
		return
	}

	// Expect: Bearer <refresh_token>
	parts := strings.SplitN(hdr, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		http.Error(w, `{"error":"invalid authorization header"}`, http.StatusUnauthorized)
		return
	}
	tokenStr := parts[1]
	if tokenStr == "" {
		http.Error(w, `{"error":"invalid authorization header"}`, http.StatusUnauthorized)
		return
	}

	refreshHash := sha256.Sum256([]byte(tokenStr))
	ctx := r.Context()

	var sessionID, userID uuid.UUID
	var expiresAt time.Time
	var revoked bool
	err := h.DB.Postgres.QueryRow(ctx, `
		SELECT id, user_id, expires_at, revoked
		FROM sessions WHERE refresh_token_hash = $1
	`, refreshHash[:]).Scan(&sessionID, &userID, &expiresAt, &revoked)
	if err == pgx.ErrNoRows {
		http.Error(w, `{"error":"invalid or revoked refresh token"}`, http.StatusUnauthorized)
		return
	} else if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	if revoked || expiresAt.Before(time.Now()) {
		http.Error(w, `{"error":"invalid or revoked refresh token"}`, http.StatusUnauthorized)
		return
	}

	// Rotate refresh token
	newRefreshToken := uuid.Must(uuid.NewRandom()).String()
	newRefreshHash := sha256.Sum256([]byte(newRefreshToken))
	newExpiresAt := time.Now().Add(h.Config.Auth.RefreshTokenExpiry)

	var refreshIP interface{}
	if ip := clientIP(r); ip != "" {
		refreshIP = ip
	}
	_, err = h.DB.Postgres.Exec(ctx, `
		UPDATE sessions SET refresh_token_hash = $1, expires_at = $2, last_used_at = NOW(), last_used_ip = $3
		WHERE id = $4
	`, newRefreshHash[:], newExpiresAt, refreshIP, sessionID)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	accessToken, err := middleware.GenerateAccessToken(userID, sessionID, []byte(h.Config.Auth.JWTSigningKey), h.Config.Auth.AccessTokenExpiry)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(VerifyResponse{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(h.Config.Auth.AccessTokenExpiry.Seconds()),
	})
}

// Logout revokes the current session.
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	// This endpoint should be protected by JWT middleware
	userID, ok := middleware.UserIDFromContext(r.Context())
	if !ok {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	sessionID, ok := middleware.SessionIDFromContext(r.Context())
	if !ok {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	ctx := r.Context()
	_, err := h.DB.Postgres.Exec(ctx, `
		UPDATE sessions SET revoked = true, revoked_at = NOW()
		WHERE id = $1 AND user_id = $2
	`, sessionID, userID)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	// Blacklist access token in Redis until expiry
	accessToken := r.Header.Get("Authorization")
	if len(accessToken) > 7 {
		h.DB.Redis.Set(ctx, "blacklist:"+accessToken[7:], "1", h.Config.Auth.AccessTokenExpiry)
	}

	w.WriteHeader(http.StatusNoContent)
}

func mustMarshalGenerator() []byte {
	g := group.Ristretto255
	gen := g.Generator()
	b, _ := gen.MarshalBinaryCompress()
	return b
}

// clientIP extracts the client IP address without port.
func clientIP(r *http.Request) string {
	ip := r.RemoteAddr
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ip = xff
	}
	host, _, err := net.SplitHostPort(ip)
	if err != nil {
		return ip
	}
	return host
}
