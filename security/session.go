package security

import (
	"encoding/json"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

const ShareKeyLogin = "login"

type Login struct {
	Username string
}

func LoginContext() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		v := session.Get(ShareKeyLogin)
		if serial, ok := v.([]byte); ok {
			var login Login
			_ = json.Unmarshal(serial, &login)
			c.Set(ShareKeyLogin, &login)
		}
		c.Next()
	}
}
