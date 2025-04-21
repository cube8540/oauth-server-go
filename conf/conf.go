package conf

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
)

type configuration struct {
	Port    string        `json:"port"`
	DB      dbConfig      `json:"db"`
	Redis   redisConfig   `json:"redis"`
	Session sessionConfig `json:"session"`
}

var config configuration

func InitAll() {
	initConfig()
	initGorm(&config.DB)
	initSessionStore(&config.Redis, &config.Session)
}

func initConfig() {
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

	decoder := json.NewDecoder(file)
	err = decoder.Decode(&config)
	if err != nil {
		panic(err)
	}
}

func GetServerPort() string {
	return config.Port
}

func Close() {
	closeDB()
}
