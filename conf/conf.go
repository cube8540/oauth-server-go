package conf

import (
	"encoding/json"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/redis"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
)

type (
	DB struct {
		Host        string `json:"host"`
		Port        int    `json:"port"`
		Username    string `json:"username"`
		Password    string `json:"password"`
		Dbname      string `json:"dbname"`
		MaxIdleSize int    `json:"max_idle_size"`
		MaxOpenSize int    `json:"max_open_size"`
	}

	Redis struct {
		Host        string `json:"host"`
		Port        int    `json:"port"`
		MaxIdleSize int    `json:"max_idle_size"`
	}

	Session struct {
		Secret    string `json:"secret"`
		MaxAgeSec int    `json:"max_age_sec"`
	}

	Configuration struct {
		Port    string  `json:"port"`
		DB      DB      `json:"db"`
		Redis   Redis   `json:"redis"`
		Session Session `json:"session"`
	}
)

var config Configuration

var (
	db    *gorm.DB
	store sessions.Store
)

func init() {
	initConfig()
	initDB()
	initSessionStore()
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

	conn, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		PrepareStmt: true,
	})
	if err != nil {
		panic(err)
	}

	sqlDB, err := conn.DB()
	if err != nil {
		panic(err)
	}
	sqlDB.SetMaxIdleConns(cfg.MaxIdleSize)
	sqlDB.SetMaxOpenConns(cfg.MaxOpenSize)

	db = conn
}

func initSessionStore() {
	redisOpt := config.Redis
	sessionOpt := config.Session

	address := redisOpt.Host + ":" + strconv.Itoa(redisOpt.Port)
	s, err := redis.NewStore(redisOpt.MaxIdleSize, "tcp", address, "", []byte(sessionOpt.Secret))
	if err != nil {
		panic(err)
	}

	s.Options(sessions.Options{
		Path:     "/",
		MaxAge:   sessionOpt.MaxAgeSec,
		HttpOnly: true,
		Secure:   true,
	})
	store = s
}

func GetDB() *gorm.DB {
	return db
}

func GetServerPort() string {
	return config.Port
}

func GetStore() sessions.Store {
	return store
}
