package conf

import (
	"encoding/json"
	"oauth-server-go/conf/db"
	"oauth-server-go/conf/redis"
	"oauth-server-go/conf/session"
	"os"
	"path/filepath"
	"runtime"
)

type Config struct {
	Port    string         `json:"port"`
	DB      db.Config      `json:"db"`
	Redis   redis.Config   `json:"redis"`
	Session session.Config `json:"session"`
}

func Read() *Config {
	_, b, _, _ := runtime.Caller(0)
	projectRoot := filepath.Join(filepath.Dir(b))

	profile := os.Getenv("profile")
	file, err := os.Open(projectRoot + "/config." + profile + ".json")
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
