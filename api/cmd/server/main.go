package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/akopososojohnson-gif/safehaven/api/config"
	"github.com/akopososojohnson-gif/safehaven/api/db"
	"github.com/akopososojohnson-gif/safehaven/api/handlers"
	shmw "github.com/akopososojohnson-gif/safehaven/api/middleware"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	cfg, err := config.Load()
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	database, err := db.New(cfg)
	if err != nil {
		slog.Error("failed to connect to databases", "error", err)
		os.Exit(1)
	}
	defer database.Close()

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(shmw.StructuredLogger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))
	r.Use(shmw.SecurityHeaders)
	r.Use(shmw.MaxBodySize(1 << 20)) // 1 MB max body size

	// Health check (unauthenticated)
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	// Rate limiter
	rateLimiter := shmw.NewRateLimiter(database.Redis)

	// Auth routes
	authHandler := &handlers.AuthHandler{DB: database, Config: cfg}
	r.Route("/api/v1/auth", func(r chi.Router) {
		r.Post("/register", authHandler.Register)
		r.With(rateLimiter.Limit(5, time.Minute)).Post("/challenge", authHandler.Challenge)
		r.Post("/verify", authHandler.Verify)
		r.Post("/refresh", authHandler.Refresh)
		r.With(shmw.JWTAuth([]byte(cfg.Auth.JWTSigningKey))).Post("/logout", authHandler.Logout)
	})

	// Vault routes (authenticated)
	vaultHandler := &handlers.VaultHandler{DB: database}
	r.Route("/api/v1/vault", func(r chi.Router) {
		r.Use(shmw.JWTAuth([]byte(cfg.Auth.JWTSigningKey)))
		vaultHandler.Routes(r)
	})

	// Share routes (create/list authenticated, redeem unauthenticated)
	shareHandler := &handlers.ShareHandler{DB: database, Config: cfg}
	r.Route("/api/v1/shares", func(r chi.Router) {
		r.Get("/{share_id}", shareHandler.RedeemShare)
	})
	r.Route("/api/v1/shares", func(r chi.Router) {
		r.Use(shmw.JWTAuth([]byte(cfg.Auth.JWTSigningKey)))
		r.Post("/", shareHandler.CreateShare)
		r.Delete("/{share_id}", shareHandler.RevokeShare)
		r.Get("/", shareHandler.ListShares)
	})

	// HIBP routes (authenticated)
	hibpHandler := handlers.NewHIBPHandler(database)
	r.Route("/api/v1/hibp", func(r chi.Router) {
		r.Use(shmw.JWTAuth([]byte(cfg.Auth.JWTSigningKey)))
		r.Get("/check", hibpHandler.Check)
	})

	// User routes (authenticated)
	userHandler := &handlers.UserHandler{DB: database}
	r.Route("/api/v1/user", func(r chi.Router) {
		r.Use(shmw.JWTAuth([]byte(cfg.Auth.JWTSigningKey)))
		userHandler.Routes(r)
	})

	srv := &http.Server{
		Addr:         ":" + cfg.Server.Port,
		Handler:      r,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	go func() {
		slog.Info("server starting", "port", cfg.Server.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	slog.Info("server shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		slog.Error("shutdown error", "error", err)
	}
}
