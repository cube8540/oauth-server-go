package conf

import (
	"fmt"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/redis"
	"strconv"
)

type (
	redisConfig struct {
		Host        string `json:"host"`
		Port        int    `json:"port"`
		MaxIdleSize int    `json:"max_idle_size"`
	}

	sessionConfig struct {
		Secret    string `json:"secret"`
		MaxAgeSec int    `json:"max_age_sec"`
	}
)

var sessionStore sessions.Store

func initSessionStore(r *redisConfig, s *sessionConfig) {
	addr := fmt.Sprintf("%s:%s", r.Host, strconv.Itoa(r.Port))
	redisStore, err := redis.NewStore(r.MaxIdleSize, "tcp", addr, "", []byte(s.Secret))
	if err != nil {
		panic(err)
	}
	redisStore.Options(sessions.Options{
		Path:     "/",
		MaxAge:   s.MaxAgeSec,
		HttpOnly: true,
		Secure:   true,
	})
	sessionStore = redisStore
}

func GetSessionStore() sessions.Store {
	return sessionStore
}
