package session

import (
	"fmt"
	"github.com/gin-contrib/sessions"
	ginRedis "github.com/gin-contrib/sessions/redis"
	appRedis "oauth-server-go/internal/config/redis"
	"strconv"
)

// Config 세션 설정
//
//	TODO: 아래의 설정 옵션들을 추가
//	- Path
//	- HttpOnly
//	- Secure
type Config struct {
	// Secret 인증키
	// 세션의 데이터 무결성을 보장하기 위한 인증키
	//
	//	Note: 세션 설정 시 인증키와 암화화 키를 설정할 수 있는데, 현제는 인증키만 설정하도록 한다.
	//	TODO: 암호화키를 설정 할 수 있도록 수정 필요
	Secret string `json:"secret"`

	// MaxAgeSec 세션의 최대 유지 시간. 초단위로 설정된다.
	MaxAgeSec int `json:"max_age_sec"`
}

// NewRedisStore 새 레디스 세션 스토어의 인스턴스를 생성한다.
func NewRedisStore(rc *appRedis.Config, c *Config) sessions.Store {
	addr := fmt.Sprintf("%s:%s", rc.Host, strconv.Itoa(rc.Port))
	store, err := ginRedis.NewStore(rc.MaxIdleSize, "tcp", addr, "", []byte(c.Secret))
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
