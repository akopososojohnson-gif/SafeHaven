package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config holds all application configuration.
type Config struct {
	Server   ServerConfig
	Database DatabaseConfig
	Redis    RedisConfig
	Auth     AuthConfig
	Share    ShareConfig
	HIBP     HIBPConfig
}

// ServerConfig holds HTTP server settings.
type ServerConfig struct {
	Port         string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration
}

// DatabaseConfig holds PostgreSQL settings.
type DatabaseConfig struct {
	Host     string
	Port     int
	User     string
	Password string
	Database string
	SSLMode  string
}

// RedisConfig holds Redis settings.
type RedisConfig struct {
	Host     string
	Port     int
	Password string
	DB       int
}

// AuthConfig holds authentication/JWT settings.
type AuthConfig struct {
	JWTSigningKey       string
	AccessTokenExpiry   time.Duration
	RefreshTokenExpiry  time.Duration
	MaxLoginAttempts    int
	LockoutDuration     time.Duration
	ChallengeTTL        time.Duration
}

// ShareConfig holds share link settings.
type ShareConfig struct {
	ServerSecretKey string
}

// HIBPConfig holds HIBP proxy settings.
type HIBPConfig struct {
	CacheTTL time.Duration
}

// DSN returns the PostgreSQL connection string.
func (d DatabaseConfig) DSN() string {
	return fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		d.Host, d.Port, d.User, d.Password, d.Database, d.SSLMode,
	)
}

// RedisAddr returns the Redis address.
func (r RedisConfig) RedisAddr() string {
	return fmt.Sprintf("%s:%d", r.Host, r.Port)
}

// Load reads configuration from environment variables.
func Load() (*Config, error) {
	cfg := &Config{
		Server: ServerConfig{
			Port:         getEnv("SERVER_PORT", "8080"),
			ReadTimeout:  getDuration("SERVER_READ_TIMEOUT", 10*time.Second),
			WriteTimeout: getDuration("SERVER_WRITE_TIMEOUT", 10*time.Second),
			IdleTimeout:  getDuration("SERVER_IDLE_TIMEOUT", 60*time.Second),
		},
		Database: DatabaseConfig{
			Host:     getEnv("DB_HOST", "localhost"),
			Port:     getInt("DB_PORT", 5432),
			User:     getEnv("DB_USER", "safehaven"),
			Password: getEnv("DB_PASSWORD", "safehaven"),
			Database: getEnv("DB_NAME", "safehaven"),
			SSLMode:  getEnv("DB_SSLMODE", "disable"),
		},
		Redis: RedisConfig{
			Host:     getEnv("REDIS_HOST", "localhost"),
			Port:     getInt("REDIS_PORT", 6379),
			Password: getEnv("REDIS_PASSWORD", ""),
			DB:       getInt("REDIS_DB", 0),
		},
		Auth: AuthConfig{
			JWTSigningKey:      getEnv("JWT_SIGNING_KEY", ""),
			AccessTokenExpiry:  getDuration("JWT_ACCESS_EXPIRY", 15*time.Minute),
			RefreshTokenExpiry: getDuration("JWT_REFRESH_EXPIRY", 7*24*time.Hour),
			MaxLoginAttempts:   getInt("MAX_LOGIN_ATTEMPTS", 10),
			LockoutDuration:    getDuration("LOCKOUT_DURATION", 30*time.Minute),
			ChallengeTTL:       getDuration("CHALLENGE_TTL", 5*time.Minute),
		},
		Share: ShareConfig{
			ServerSecretKey: getEnv("SHARE_SERVER_SECRET", ""),
		},
		HIBP: HIBPConfig{
			CacheTTL: getDuration("HIBP_CACHE_TTL", time.Hour),
		},
	}

	if cfg.Auth.JWTSigningKey == "" {
		return nil, fmt.Errorf("JWT_SIGNING_KEY is required")
	}
	if cfg.Share.ServerSecretKey == "" {
		return nil, fmt.Errorf("SHARE_SERVER_SECRET is required")
	}

	return cfg, nil
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	i, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return i
}

func getDuration(key string, fallback time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return d
}
