package log

import (
	"fmt"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
	"os"
	"path/filepath"
)

type Config struct {
	Dir  string `json:"dir"`
	Name string `json:"name"`

	// Size 로그 파일의 최대 사이즈로 단위는 MB(메가바이트). 기본 값은 100MB
	Size int `json:"size"`

	// Keep 최대 로그 파일 개수로 로그 파일이 설정된 개수보다 커질 경우 기존의 로그 파일들은 삭제 된다.
	// 설정 되지 않을시 로그 파일은 삭제 되지 않는다.
	Keep int `json:"Keep"`

	// MaxAge 로그 파일의 최대 유효기간으로 설정된 유효기간이 지난 로그 파일은 삭제 된다.
	// 설정 되지 않을시 로그 파일은 삭제 되지 않는다.
	MaxAge int `json:"max_age"`

	// Compress gzip 압축 여부
	Compress bool `json:"compress"`

	// Level 지정된 로그 레벨 이상만 로깅 된다. 현재 DEBUG, INFO, ERROR 세 가지 레벨을 지정 할 수 있다. 기본 값은 DEBUG
	Level string `json:"level"`
}

var logger *zap.Logger

func NewLogger(c *Config) {
	if err := os.MkdirAll(c.Dir, 0770); err != nil {
		panic(err)
	}

	lumberLogger := &lumberjack.Logger{
		Filename:   filepath.Join(c.Dir, c.Name),
		MaxSize:    c.Size,
		MaxAge:     c.MaxAge,
		MaxBackups: c.Keep,
		Compress:   c.Compress,
	}

	fileWriter := zapcore.AddSync(lumberLogger)
	consoleWriter := zapcore.AddSync(os.Stdout)

	encode := zap.NewProductionEncoderConfig()
	encode.EncodeTime = zapcore.ISO8601TimeEncoder

	lvl := classifyLevel(c.Level)

	fileCore := zapcore.NewCore(zapcore.NewJSONEncoder(encode), fileWriter, lvl)
	consoleCore := zapcore.NewCore(zapcore.NewJSONEncoder(encode), consoleWriter, lvl)

	core := zapcore.NewTee(fileCore, consoleCore)
	logger = zap.New(core)
}

func Logger() *zap.Logger {
	return logger
}

func classifyLevel(lvl string) zapcore.Level {
	switch lvl {
	case "", "DEBUG":
		return zapcore.DebugLevel
	case "INFO":
		return zapcore.InfoLevel
	case "ERROR":
		return zapcore.ErrorLevel
	default:
		panic(fmt.Sprintf("%s is unknown log level", lvl))
	}
}
