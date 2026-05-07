package config

import (
	"os"
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	os.Setenv("JWT_SIGNING_KEY", "test-key-32-bytes-long-1234567890")
	defer os.Unsetenv("JWT_SIGNING_KEY")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}

	if cfg.Server.Port != "8080" {
		t.Errorf("expected port 8080, got %s", cfg.Server.Port)
	}
	if cfg.Database.Port != 5432 {
		t.Errorf("expected db port 5432, got %d", cfg.Database.Port)
	}
	if cfg.Redis.Port != 6379 {
		t.Errorf("expected redis port 6379, got %d", cfg.Redis.Port)
	}
	if cfg.Auth.AccessTokenExpiry != 15*time.Minute {
		t.Errorf("expected 15m access expiry, got %v", cfg.Auth.AccessTokenExpiry)
	}
	if cfg.Auth.RefreshTokenExpiry != 7*24*time.Hour {
		t.Errorf("expected 7d refresh expiry, got %v", cfg.Auth.RefreshTokenExpiry)
	}
}

func TestLoadMissingJWTKey(t *testing.T) {
	os.Unsetenv("JWT_SIGNING_KEY")
	_, err := Load()
	if err == nil {
		t.Fatal("expected error for missing JWT_SIGNING_KEY")
	}
}

func TestDatabaseDSN(t *testing.T) {
	db := DatabaseConfig{
		Host:     "localhost",
		Port:     5432,
		User:     "safehaven",
		Password: "secret",
		Database: "safehaven",
		SSLMode:  "disable",
	}
	expected := "host=localhost port=5432 user=safehaven password=secret dbname=safehaven sslmode=disable"
	if got := db.DSN(); got != expected {
		t.Errorf("DSN mismatch\ngot:      %s\nexpected: %s", got, expected)
	}
}

func TestRedisAddr(t *testing.T) {
	r := RedisConfig{Host: "redis", Port: 6379}
	if got := r.RedisAddr(); got != "redis:6379" {
		t.Errorf("expected redis:6379, got %s", got)
	}
}
