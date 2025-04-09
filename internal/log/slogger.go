package log

import (
	"fmt"
	"io"
	"log/slog"
)

// custom slog.Level values.
const (
	LevelTrace = slog.Level(-8)
	LevelDebug = slog.LevelDebug
	LevelInfo  = slog.LevelInfo
	LevelWarn  = slog.LevelWarn
	LevelError = slog.LevelError
	LevelFatal = slog.Level(9)
)

// string representation of custom slog.Level levels; defining them as constants is
// recommended at: https://pkg.go.dev/log/slog#example-HandlerOptions-CustomLevels.
const (
	LevelTraceString = "trace"
	LevelDebugString = "debug"
	LevelInfoString  = "info"
	LevelWarnString  = "warning"
	LevelErrorString = "error"
	LevelFatalString = "fatal"
)

// NewSlogger takes an io.Writer and returns a new logger of type slog.Logger.
func NewSlogger(out io.Writer, level string) *slog.JSONHandler {
	var slevel slog.Level
	switch {
	case level == LevelTraceString:
		slevel = LevelTrace
	case level == LevelDebugString:
		slevel = LevelDebug
	case level == LevelInfoString:
		slevel = LevelInfo
	case level == LevelWarnString:
		slevel = LevelWarn
	case level == LevelErrorString:
		slevel = LevelError
	case level == LevelFatalString:
		slevel = LevelFatal
	default:
		panic(fmt.Sprintf("invalid log level: %q\n", level))
	}

	jh := slog.NewJSONHandler(out, &slog.HandlerOptions{
		Level: slevel,

		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == slog.LevelKey {
				// Handle custom values
				level, _ := a.Value.Any().(slog.Level)

				switch {
				case level < LevelDebug:
					a.Value = slog.StringValue(LevelTraceString)
				case level < LevelInfo:
					a.Value = slog.StringValue(LevelDebugString)
				case level < LevelWarn:
					a.Value = slog.StringValue(LevelInfoString)
				case level < LevelError:
					a.Value = slog.StringValue(LevelWarnString)
				case level < LevelFatal:
					a.Value = slog.StringValue(LevelErrorString)
				default:
					a.Value = slog.StringValue(LevelFatalString)
				}
			}

			if a.Key == slog.MessageKey {
				a.Key = "message"
			}
			return a
		},
	})

	return jh
}
