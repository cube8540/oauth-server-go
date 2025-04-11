package handler

import (
	"github.com/gin-gonic/gin"
	"oauth-server-go/oauth/entity"
)

const oauth2ShareKeyAuthClient = "oauth2/security/authClient"

type ClientAuthManager func(id, secret string) (*entity.Client, error)

func clientBasicAuthManage(m ClientAuthManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		_, exists := c.Get(oauth2ShareKeyAuthClient)
		if !exists {
			id, secret, ok := c.Request.BasicAuth()
			if ok {
				client, err := m(id, secret)
				if err != nil {
					_ = c.Error(err)
					c.Abort()
					return
				}
				c.Set(oauth2ShareKeyAuthClient, client)
			}
		}
		c.Next()
	}
}

type clientAuthForm struct {
	ID     string `form:"client_id"`
	Secret string `form:"secret"`
}

func clientFormAuthManage(m ClientAuthManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		_, exists := c.Get(oauth2ShareKeyAuthClient)
		if !exists {
			var r clientAuthForm
			if err := c.Bind(&r); err != nil {
				_ = c.Error(err)
				c.Abort()
				return
			}
			if r.ID != "" {
				client, err := m(r.ID, r.Secret)
				if err != nil {
					_ = c.Error(err)
					c.Abort()
					return
				}
				c.Set(oauth2ShareKeyAuthClient, client)
			}
		}
		c.Next()
	}
}
