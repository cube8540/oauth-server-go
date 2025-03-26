package conf

import (
	"encoding/json"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
)

type (
	DB struct {
		Host     string `json:"host"`
		Port     int    `json:"port"`
		Username string `json:"username"`
		Password string `json:"password"`
		Dbname   string `json:"dbname"`
	}

	Redis struct {
		Host string `json:"host"`
		Port int    `json:"port"`
	}

	Configuration struct {
		Port  string `json:"port"`
		DB    DB     `json:"db"`
		Redis Redis  `json:"redis"`
	}
)

var config Configuration
var db *gorm.DB

func Init() {
	initConfig()
	initDB()
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

func initDB() {
	cfg := config.DB
	dsn := "host=" + cfg.Host + " user=" + cfg.Username + " password=" + cfg.Password + " dbname=" + cfg.Dbname + " port=" + strconv.Itoa(cfg.Port) + " sslmode=disable TimeZone=Asia/Shanghai"

	conn, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		panic(err)
	}

	db = conn
}

func GetDB() *gorm.DB {
	return db
}

func GetServerPort() string {
	return config.Port
}
