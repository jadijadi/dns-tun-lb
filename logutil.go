package main

import (
	"log"
	"strings"
)

type logLevel int

const (
	levelError logLevel = iota
	levelInfo
	levelDebug
)

var currentLogLevel = levelInfo

func initLogger(level string) {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		currentLogLevel = levelDebug
	case "error":
		currentLogLevel = levelError
	case "info", "":
		fallthrough
	default:
		currentLogLevel = levelInfo
	}
	// Standard UTC timestamps.
	log.SetFlags(log.LstdFlags | log.LUTC)
}

func logErrorf(format string, args ...any) {
	if currentLogLevel >= levelError {
		log.Printf("[ERROR] "+format, args...)
	}
}

func logInfof(format string, args ...any) {
	if currentLogLevel >= levelInfo {
		log.Printf("[INFO] "+format, args...)
	}
}

func logDebugf(format string, args ...any) {
	if currentLogLevel >= levelDebug {
		log.Printf("[DEBUG] "+format, args...)
	}
}

