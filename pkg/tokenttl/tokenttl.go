// Package tokenttl holds the lifetime of refresh tokens and OAuth grants.
//
// It used to be a literal 30 days repeated at every place a token or grant is
// created. Because each refresh issues a new refresh token with a fresh
// lifetime, this value is really "how long a connection may sit unused before
// the user has to sign in again", so deployments need to tune it.
package tokenttl

import (
	"log"
	"os"
	"sync"
	"time"
)

const (
	// Default matches the previous hard-coded value.
	Default = 30 * 24 * time.Hour
	// Max bounds a misconfigured value (about 10 years); "never expires" is not
	// offered because a revoked or abandoned grant should eventually die.
	Max = 10 * 365 * 24 * time.Hour

	// EnvVar is a Go duration string, e.g. "8760h" for one year.
	EnvVar = "REFRESH_TOKEN_TTL"
)

var (
	once  sync.Once
	value = Default
)

// Refresh returns the lifetime for refresh tokens and grants. Read once from
// REFRESH_TOKEN_TTL. An unparsable, non-positive or too-large value is logged
// and the default is used, so a typo cannot silently produce tokens that
// expire immediately.
func Refresh() time.Duration {
	once.Do(func() { value = parse(os.Getenv(EnvVar)) })
	return value
}

func parse(raw string) time.Duration {
	if raw == "" {
		return Default
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 || d > Max {
		log.Printf("ignoring %s=%q (want a Go duration between 1ns and %s, e.g. 8760h): using %s", EnvVar, raw, Max, Default)
		return Default
	}
	return d
}
