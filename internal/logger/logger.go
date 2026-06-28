package logger

import (
	"log/slog"
	"os"
)

// Init sets the global slog default to a text handler on stdout.
// After calling this, use slog.Info / slog.Error / slog.Warn directly anywhere.
func Init() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})))
}
