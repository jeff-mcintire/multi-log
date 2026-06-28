// Package config provides small helpers for reading service configuration from
// the environment, with sensible local-development defaults.
package config

import "os"

// Env returns the environment variable or a default.
func Env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// Defaults for local development (matching deploy/docker-compose.yml).
const (
	DefaultPGDSN      = "postgres://postgres:postgres@localhost:5434/multilog"
	DefaultCHAddr     = "localhost:9009"
	DefaultCHDB       = "multilog"
	DefaultCHUser     = "multilog"
	DefaultCHPassword = "multilog"
)
