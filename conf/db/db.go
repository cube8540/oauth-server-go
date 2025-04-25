package db

import (
	"fmt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"log"
	"os"
	"strconv"
	"time"
)

type Config struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	Dbname      string `json:"dbname"`
	MaxIdleSize int    `json:"max_idle_size"`
	MaxOpenSize int    `json:"max_open_size"`
}

func Connect(c *Config) *gorm.DB {
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=disable Timezone=Asia/Seoul",
		c.Host, c.Username, c.Password, c.Dbname, strconv.Itoa(c.Port))

	newLogger := logger.New(
		log.New(os.Stdout, "\r\n", log.LstdFlags), // io writer
		logger.Config{
			SlowThreshold:             time.Second, // Slow SQL threshold
			LogLevel:                  logger.Info, // Log level
			IgnoreRecordNotFoundError: false,       // Ignore ErrRecordNotFound error for logger
			ParameterizedQueries:      false,       // Don't include params in the SQL log
			Colorful:                  true,        // Disable color
		},
	)

	connection, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		PrepareStmt: true,
		Logger:      newLogger,
	})
	if err != nil {
		panic(err)
	}
	sql, err := connection.DB()
	if err != nil {
		panic(err)
	}
	sql.SetMaxIdleConns(c.MaxIdleSize)
	sql.SetMaxOpenConns(c.MaxOpenSize)

	return connection
}
