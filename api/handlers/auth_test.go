package handlers

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/akopososojohnson-gif/safehaven/api/config"
	"github.com/akopososojohnson-gif/safehaven/api/db"
	"github.com/akopososojohnson-gif/safehaven/api/middleware"
	"github.com/cloudflare/circl/group"
	"github.com/go-chi/chi/v5"
)

func setupTestAuthHandler(t *testing.T) (*AuthHandler, *chi.Mux) {
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

	// Clean test data
	ctx := t.Context()
	database.Postgres.Exec(ctx, "DELETE FROM sessions")
	database.Postgres.Exec(ctx, "DELETE FROM users")
	database.Redis.FlushDB(ctx)

	ah := &AuthHandler{DB: database, Config: cfg}
	r := chi.NewRouter()
	ah.Routes(r)

	return ah, r
}

func generateZKPProof(publicKey, challenge []byte, x group.Scalar) (tBytes, sBytes []byte, err error) {
	g := group.Ristretto255

	c := g.NewScalar()
	if err := c.UnmarshalBinary(challenge); err != nil {
		return nil, nil, err
	}

	r := g.RandomScalar(rand.Reader)
	t := g.NewElement().MulGen(r)

	// s = r + C * x
	cx := g.NewScalar().Mul(c, x)
	s := g.NewScalar().Add(r, cx)

	tBytes, _ = t.MarshalBinaryCompress()
	sBytes, _ = s.MarshalBinary()
	return tBytes, sBytes, nil
}

func TestAuthFlow(t *testing.T) {
	ah, r := setupTestAuthHandler(t)
	_ = ah

	// 1. Generate keypair
	g := group.Ristretto255
	x := g.RandomScalar(rand.Reader)
	y := g.NewElement().MulGen(x)
	pkBytes, _ := y.MarshalBinaryCompress()
	salt := make([]byte, 32)
	rand.Read(salt)
	wrap := make([]byte, 60)
	rand.Read(wrap)

	// 2. Register
	regBody, _ := json.Marshal(RegisterRequest{
		Email:             "test@example.com",
		ZkpPublicKey:      base64.StdEncoding.EncodeToString(pkBytes),
		Argon2Salt:        base64.StdEncoding.EncodeToString(salt),
		Argon2Memory:      65536,
		Argon2Iterations:  3,
		Argon2Parallelism: 4,
		VaultKeyWrap:      base64.StdEncoding.EncodeToString(wrap),
	})
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(regBody))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("register failed: %d %s", rec.Code, rec.Body.String())
	}
	var regResp RegisterResponse
	json.Unmarshal(rec.Body.Bytes(), &regResp)

	// 3. Challenge
	chalBody, _ := json.Marshal(map[string]string{"email": "test@example.com"})
	req = httptest.NewRequest(http.MethodPost, "/challenge", bytes.NewReader(chalBody))
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("challenge failed: %d %s", rec.Code, rec.Body.String())
	}
	var chalResp ChallengeResponse
	json.Unmarshal(rec.Body.Bytes(), &chalResp)

	challengeBytes, _ := base64.StdEncoding.DecodeString(chalResp.Challenge)

	// 4. Verify
	proofT, proofS, err := generateZKPProof(pkBytes, challengeBytes, x)
	if err != nil {
		t.Fatalf("proof generation failed: %v", err)
	}

	verifyBody, _ := json.Marshal(VerifyRequest{
		ChallengeID: chalResp.ChallengeID,
		ProofT:      base64.StdEncoding.EncodeToString(proofT),
		ProofS:      base64.StdEncoding.EncodeToString(proofS),
	})
	req = httptest.NewRequest(http.MethodPost, "/verify", bytes.NewReader(verifyBody))
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("verify failed: %d %s", rec.Code, rec.Body.String())
	}
	var verifyResp VerifyResponse
	json.Unmarshal(rec.Body.Bytes(), &verifyResp)
	if verifyResp.AccessToken == "" || verifyResp.RefreshToken == "" {
		t.Fatal("missing tokens in verify response")
	}

	// 5. Refresh
	refreshReq := httptest.NewRequest(http.MethodPost, "/refresh", nil)
	refreshReq.Header.Set("Authorization", "Bearer "+verifyResp.RefreshToken)
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, refreshReq)
	if rec.Code != http.StatusOK {
		t.Fatalf("refresh failed: %d %s", rec.Code, rec.Body.String())
	}
	var refreshResp RefreshResponse
	json.Unmarshal(rec.Body.Bytes(), &refreshResp)
	if refreshResp.AccessToken == "" {
		t.Fatal("missing access token in refresh response")
	}

	// 6. Logout (needs JWT auth)
	logoutReq := httptest.NewRequest(http.MethodPost, "/logout", nil)
	logoutReq.Header.Set("Authorization", "Bearer "+refreshResp.AccessToken)
	rec = httptest.NewRecorder()
	// Wrap with JWT middleware for logout
	jwtHandler := middleware.JWTAuth([]byte(os.Getenv("JWT_SIGNING_KEY")))(http.HandlerFunc(ah.Logout))
	jwtHandler.ServeHTTP(rec, logoutReq)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("logout failed: %d %s", rec.Code, rec.Body.String())
	}
}

func TestRegisterDuplicateEmail(t *testing.T) {
	ah, r := setupTestAuthHandler(t)
	_ = ah

	g := group.Ristretto255
	x := g.RandomScalar(rand.Reader)
	y := g.NewElement().MulGen(x)
	pkBytes, _ := y.MarshalBinaryCompress()
	salt := make([]byte, 32)
	rand.Read(salt)
	wrap := make([]byte, 60)
	rand.Read(wrap)

	regBody, _ := json.Marshal(RegisterRequest{
		Email:             "dup@example.com",
		ZkpPublicKey:      base64.StdEncoding.EncodeToString(pkBytes),
		Argon2Salt:        base64.StdEncoding.EncodeToString(salt),
		Argon2Memory:      65536,
		Argon2Iterations:  3,
		Argon2Parallelism: 4,
		VaultKeyWrap:      base64.StdEncoding.EncodeToString(wrap),
	})

	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(regBody))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("first register failed: %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(regBody))
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409 for duplicate, got %d", rec.Code)
	}
}

func TestVerifyWrongProof(t *testing.T) {
	ah, r := setupTestAuthHandler(t)
	_ = ah

	g := group.Ristretto255
	x := g.RandomScalar(rand.Reader)
	y := g.NewElement().MulGen(x)
	pkBytes, _ := y.MarshalBinaryCompress()
	salt := make([]byte, 32)
	rand.Read(salt)
	wrap := make([]byte, 60)
	rand.Read(wrap)

	// Register
	regBody, _ := json.Marshal(RegisterRequest{
		Email:             "wrong@example.com",
		ZkpPublicKey:      base64.StdEncoding.EncodeToString(pkBytes),
		Argon2Salt:        base64.StdEncoding.EncodeToString(salt),
		Argon2Memory:      65536,
		Argon2Iterations:  3,
		Argon2Parallelism: 4,
		VaultKeyWrap:      base64.StdEncoding.EncodeToString(wrap),
	})
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(regBody))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	// Challenge
	chalBody, _ := json.Marshal(map[string]string{"email": "wrong@example.com"})
	req = httptest.NewRequest(http.MethodPost, "/challenge", bytes.NewReader(chalBody))
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	var chalResp ChallengeResponse
	json.Unmarshal(rec.Body.Bytes(), &chalResp)

	challengeBytes, _ := base64.StdEncoding.DecodeString(chalResp.Challenge)

	// Generate proof with WRONG key
	wrongX := g.RandomScalar(rand.Reader)
	proofT, proofS, _ := generateZKPProof(pkBytes, challengeBytes, wrongX)

	verifyBody, _ := json.Marshal(VerifyRequest{
		ChallengeID: chalResp.ChallengeID,
		ProofT:      base64.StdEncoding.EncodeToString(proofT),
		ProofS:      base64.StdEncoding.EncodeToString(proofS),
	})
	req = httptest.NewRequest(http.MethodPost, "/verify", bytes.NewReader(verifyBody))
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for wrong proof, got %d", rec.Code)
	}
}
