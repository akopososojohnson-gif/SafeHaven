package db

import (
	"context"
	"fmt"
	"time"

	"github.com/akopososojohnson-gif/safehaven/api/config"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

// DB holds PostgreSQL and Redis connection pools.
type DB struct {
	Postgres *pgxpool.Pool
	Redis    *redis.Client
}

// New creates database connections based on configuration.
func New(cfg *config.Config) (*DB, error) {
	pgPool, err := newPostgres(cfg.Database)
	if err != nil {
		return nil, fmt.Errorf("postgres: %w", err)
	}

	rdb := newRedis(cfg.Redis)

	// Verify Redis connectivity
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		pgPool.Close()
		return nil, fmt.Errorf("redis: %w", err)
	}

	return &DB{
		Postgres: pgPool,
		Redis:    rdb,
	}, nil
}

// Close gracefully shuts down all connections.
func (db *DB) Close() {
	if db.Postgres != nil {
		db.Postgres.Close()
	}
	if db.Redis != nil {
		db.Redis.Close()
	}
}

func newPostgres(cfg config.DatabaseConfig) (*pgxpool.Pool, error) {
	poolConfig, err := pgxpool.ParseConfig(cfg.DSN())
	if err != nil {
		return nil, err
	}

	poolConfig.MaxConns = 25
	poolConfig.MinConns = 5
	poolConfig.MaxConnLifetime = 5 * time.Minute
	poolConfig.MaxConnIdleTime = 5 * time.Minute
	poolConfig.HealthCheckPeriod = 30 * time.Second

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, err
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}

	return pool, nil
}

func newRedis(cfg config.RedisConfig) *redis.Client {
	return redis.NewClient(&redis.Options{
		Addr:     cfg.RedisAddr(),
		Password: cfg.Password,
		DB:       cfg.DB,
		PoolSize: 20,
	})
}
