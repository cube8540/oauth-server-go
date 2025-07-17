package config

import (
	"encoding/json"
	"oauth-server-go/internal/config/db"
	"oauth-server-go/internal/config/log"
	"oauth-server-go/internal/config/redis"
	"oauth-server-go/internal/config/session"
	"os"
	"path/filepath"
)

// Config 어플리케이션에서 사용되는 설정
type Config struct {
	Port    string         `json:"port"`
	DB      db.Config      `json:"db"`
	Redis   redis.Config   `json:"redis"`
	Session session.Config `json:"session"`
	Logger  log.Config     `json:"logger"`
}

// Read /config 폴더의 config.<profile>.json 파일을 읽어 어플리케이션 설정 인스턴스를 생성한다.
// profile은 환경변수 "profile"을 사용한다. 환경 변수가 설정되어 있지 않을 경우(빈 텍스트도 포함) 패닉이 발생한다.
func Read() *Config {
	profile := os.Getenv("profile")
	if profile == "" {
		panic("profile is not set")
	}

	path := filepath.Join("config", "config."+profile+".json")
	return ReadFile(path)
}

// ReadFile 지정된 경록의 파일을 읽어 새 어플리케이션 설정 인스턴스를 생성한다.
// 파일은 .json 포멧으로 작성되어 있어야 하며 그러지 않을 경우 패닉이 발생한다.
func ReadFile(path string) *Config {
	file, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	defer func() {
		_ = file.Close()
	}()

	var c Config
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&c)
	if err != nil {
		panic(err)
	}
	return &c
}
