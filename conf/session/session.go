package session

import (
	"fmt"
	"github.com/gin-contrib/sessions"
	ginredis "github.com/gin-contrib/sessions/redis"
	appredis "oauth-server-go/conf/redis"
	"strconv"
)

type Config struct {
	Secret    string `json:"secret"`
	MaxAgeSec int    `json:"max_age_sec"`
}

func NewRedisStore(r *appredis.Config, c *Config) sessions.Store {
	addr := fmt.Sprintf("%s:%s", r.Host, strconv.Itoa(r.Port))
	store, err := ginredis.NewStore(r.MaxIdleSize, "tcp", addr, "", []byte(c.Secret))
	if err != nil {
		panic(err)
	}
	store.Options(sessions.Options{
		Path:     "/",
		MaxAge:   c.MaxAgeSec,
		HttpOnly: true,
		Secure:   true,
	})
	return store
}
