package security

import (
	"encoding/json"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

const SessionKeyLogin = "sessions/login"

type SessionLogin struct {
	Username string
}

func StoreLogin(c *gin.Context, sl *SessionLogin) error {
	serial, err := json.Marshal(sl)
	if err != nil {
		return err
	}
	s := sessions.Default(c)
	s.Set(SessionKeyLogin, serial)
	return s.Save()
}

func Authentication(c *gin.Context) {
	session := sessions.Default(c)
	v := session.Get(SessionKeyLogin)
	if serial, ok := v.([]byte); ok {
		var login SessionLogin
		_ = json.Unmarshal(serial, &login)
		c.Set(SessionKeyLogin, &login)
	}
	c.Next()
}

type AccessDeniedHandler func(c *gin.Context)

func Authenticated(h AccessDeniedHandler) gin.HandlerFunc {
	return func(c *gin.Context) {
		_, exists := c.Get(SessionKeyLogin)
		if !exists {
			h(c)
			c.Abort()
		} else {
			c.Next()
		}
	}
}
