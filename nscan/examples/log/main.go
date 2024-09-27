package main

import (
	"fmt"
	"os"
	"time"

	"github.com/rs/zerolog"
)

func main() {
	// buildInfo, _ := debug.ReadBuildInfo()
	logger := zerolog.New(zerolog.MultiLevelWriter(
		zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.DateTime},
	)).
		Level(zerolog.DebugLevel).
		With().
		Timestamp().
		Caller().
		// Int("pid", os.Getpid()).
		// Str("go_version", buildInfo.GoVersion).
		Logger()
	logger.Debug().Msg(fmt.Sprintf("I have a dream:%s", "have a nice life"))
	logger.Info().Msg(fmt.Sprintf("I have a dream:%s", "have a nice life2"))
	logger.Debug().Msg(fmt.Sprintf("I have a dream:%s", "have a nice life3"))
	logger.Info().Msg(fmt.Sprintf("I have a dream:%s", "have a nice life4"))
	logger.Debug().Msg(fmt.Sprintf("I have a dream:%s", "have a nice life5"))
	logger.Info().Msg(fmt.Sprintf("I have a dream:%s", "have a nice life6"))
	logger.Warn().Msg(fmt.Sprintf("I have a dream:%s", "have a nice life6"))
}
