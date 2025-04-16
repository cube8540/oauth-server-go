package oauth

import (
	"github.com/gin-gonic/gin"
	"oauth-server-go/oauth/client"
)

// oauth2ShareKeyAuthClient 인증된 클라이언트 정보를 Gin 컨텍스트에서 공유하는 키
const oauth2ShareKeyAuthClient = "oauth2/security/authClient"

type ClientAuthManager func(id, secret string) (*client.Client, error)

func clientBasicAuthManage(m ClientAuthManager) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		_, exists := ctx.Get(oauth2ShareKeyAuthClient)
		if !exists {
			id, secret, ok := ctx.Request.BasicAuth()
			if ok {
				c, err := m(id, secret)
				if err != nil {
					_ = ctx.Error(err)
					ctx.Abort()
					return
				}
				ctx.Set(oauth2ShareKeyAuthClient, c)
			}
		}
		ctx.Next()
	}
}

type clientAuthForm struct {
	ID     string `form:"client_id"`
	Secret string `form:"secret"`
}

func clientFormAuthManage(m ClientAuthManager) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		_, exists := ctx.Get(oauth2ShareKeyAuthClient)
		if !exists {
			var r clientAuthForm
			if err := ctx.Bind(&r); err != nil {
				_ = ctx.Error(err)
				ctx.Abort()
				return
			}
			if r.ID != "" {
				c, err := m(r.ID, r.Secret)
				if err != nil {
					_ = ctx.Error(err)
					ctx.Abort()
					return
				}
				ctx.Set(oauth2ShareKeyAuthClient, c)
			}
		}
		ctx.Next()
	}
}
