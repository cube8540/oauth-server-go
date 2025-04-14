package session

import (
	"encoding/json"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"oauth-server-go/security"
)

// loginKey 세션에 저장할 로그인 키
const loginKey = "sessions/login"

// store security.Store 를 구현한 구조체
// 세션을 이용해 로그인 정보를 저장한다.
type store struct {
	session sessions.Session
}

// Set 로그인 정보를 세션에 저장한다.
// 저장되는 로그인은 Json으로 직렬화 되어 저장된다.
func (s *store) Set(v *security.Login) error {
	serial, err := json.Marshal(v)
	if err != nil {
		return err
	}
	s.session.Set(loginKey, serial)
	return s.session.Save()
}

// Get 세션에서 로그인 정보를 가져온다.
func (s *store) Get() (*security.Login, bool) {
	v := s.session.Get(loginKey)
	if serial, ok := v.([]byte); ok {
		var login security.Login
		_ = json.Unmarshal(serial, &login)
		return &login, true
	}
	return nil, false
}

// SecurityStore 세션 기반 스토어를 Gin 컨텍스트에 설정하는 미들웨어를 반환한다.
// 이 미들웨어는 요청마다 세션에서 security.Store 인터페이스를 구현한 store 객체를 생성하여 컨텍스트에 설정한다.
func SecurityStore() gin.HandlerFunc {
	return func(c *gin.Context) {
		s := sessions.Default(c)
		c.Set(security.StoreKey, &store{session: s})
		c.Next()
	}
}
