// Package elog wires the engine's structured logging.
//
// We use stdlib log/slog with the JSON handler, writing to stderr. The MCP
// parent process pipes our stderr into its own logger; lines parse as JSON
// and are forwarded with source: "engine".
//
// Slog's default JSON shape:
//   {"time":"2026-05-17T12:34:56Z","level":"INFO","msg":"...","key":"value"}
// matches what the MCP's forwarder expects (it discards `time` and uses
// `level` to route into our level-named methods on its side).
//
// Level filter via DT_LOG_LEVEL env var: trace | debug | info | warn | error.
// Default: info. Trace maps to slog's DEBUG (we don't have finer than that
// natively in slog).
package elog

import (
	"log/slog"
	"os"
	"strings"
	"sync"
)

var (
	once       sync.Once
	rootLogger *slog.Logger
)

// Init wires the global slog default logger to a JSON handler on stderr
// respecting DT_LOG_LEVEL. Idempotent — safe to call multiple times.
func Init() {
	once.Do(func() {
		level := parseLevel(os.Getenv("DT_LOG_LEVEL"))
		handler := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
			Level: level,
		})
		rootLogger = slog.New(handler)
		slog.SetDefault(rootLogger)
	})
}

// With returns a child logger pre-bound with the given (key,value) pairs.
// Same args as slog.With.
func With(args ...any) *slog.Logger {
	Init()
	return rootLogger.With(args...)
}

// Source returns a logger with the given source name attached, matching the
// MCP's "source" field convention.
func Source(name string) *slog.Logger {
	return With("source", name)
}

func parseLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "trace":
		return slog.LevelDebug
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error", "err":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
