package db

import (
	"context"
	"testing"
	"time"

	"github.com/akopososojohnson-gif/safehaven/api/config"
)

func TestNew(t *testing.T) {
	cfg := &config.Config{
		Database: config.DatabaseConfig{
			Host:     "localhost",
			Port:     5432,
			User:     "safehaven",
			Password: "safehaven",
			Database: "safehaven",
			SSLMode:  "disable",
		},
		Redis: config.RedisConfig{
			Host:     "localhost",
			Port:     6379,
			Password: "",
			DB:       0,
		},
	}

	db, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer db.Close()

	// Verify Postgres connectivity
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var one int
	if err := db.Postgres.QueryRow(ctx, "SELECT 1").Scan(&one); err != nil {
		t.Fatalf("postgres ping failed: %v", err)
	}
	if one != 1 {
		t.Fatalf("expected 1, got %d", one)
	}

	// Verify Redis connectivity
	if err := db.Redis.Ping(ctx).Err(); err != nil {
		t.Fatalf("redis ping failed: %v", err)
	}
}
