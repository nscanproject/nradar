package log

import (
	"nscan/common/argx"
	"os"
	"time"

	"github.com/rs/zerolog"
)

var Logger zerolog.Logger

func init() {
	// buildInfo, _ := debug.ReadBuildInfo()
	var logLevel zerolog.Level
	if argx.Verbose {
		logLevel = zerolog.DebugLevel
	} else {
		logLevel = zerolog.WarnLevel
	}
	Logger = zerolog.New(zerolog.MultiLevelWriter(
		zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.DateTime},
	)).
		Level(logLevel).
		With().
		Timestamp().
		// Caller().
		// Int("pid", os.Getpid()).
		// Str("go_version", buildInfo.GoVersion).
		Logger()
}
