package security

import (
	"context"
	"github.com/gin-gonic/gin"
	"oauth-server-go/internal/config/log"
	"oauth-server-go/internal/oauth/client"
	oautherr "oauth-server-go/internal/oauth/errors"
)

// oauth2ShareKeyAuthClient 인증된 클라이언트 정보를 Gin 컨텍스트에서 공유하는 키
const oauth2ShareKeyAuthClient = "oauth2/security/authClient"

// ClientAuthenticate 클라이언트의 아이디와 패스워드를 통해 클라이언트의 인증을 진행한다.
// 인증 완료시 인증된 클라이언트를 반환하며 실패시 에러를 반환한다.
type ClientAuthenticate func(ctx context.Context, id, secret string) (*client.Client, error)

// ClientBasicAuthenticateHandler HTTP Basic Authentication을 이용하여
// OAuth2 클라이언트을 인증하는 Gin 미들웨어 함수를 생성한다.
func ClientBasicAuthenticateHandler(authenticate ClientAuthenticate) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		_, exists := ctx.Get(oauth2ShareKeyAuthClient)
		if !exists {
			id, secret, ok := ctx.Request.BasicAuth()
			if ok {
				c, err := authenticate(ctx.Request.Context(), id, secret)
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

// ClientAuthRequest 클라이언트 인증요청 폼
type ClientAuthRequest struct {
	ID     string `form:"client_id"`
	Secret string `form:"client_secret"`
}

// ClientFormAuthenticationHandler 클라이언트 인증 요청을 받아 OAuth2 클라이언트를 인증하는 Gin 미들웨어 함수를 생성한다.
func ClientFormAuthenticationHandler(authenticate ClientAuthenticate) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		_, exists := ctx.Get(oauth2ShareKeyAuthClient)
		if !exists {
			var r ClientAuthRequest
			if err := ctx.Bind(&r); err != nil {
				_ = ctx.Error(err)
				ctx.Abort()
				return
			}
			if r.ID != "" {
				c, err := authenticate(ctx.Request.Context(), r.ID, r.Secret)
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

// RetrieveClientAuthentication Gin 컨텍스트에서 인증된 클라이언트의 정보를 조회한다.
//
// 이전 미들웨어에서 성공적으로 인증되어 저장된 클라이언트 정보를 조회하여 반환한다.
// 만약 컨텍스트에 저장된 클라이언트가 없는 경우 nil과 false를 반환한다.
//
// Returns:
//   - *client.Client: 인증된 클라이언트
//   - bool: 조회 성공 여부
func RetrieveClientAuthentication(c *gin.Context) (*client.Client, bool) {
	v, exists := c.Get(oauth2ShareKeyAuthClient)
	if !exists {
		return nil, false
	}

	if auth, ok := v.(*client.Client); ok {
		return auth, true
	} else {
		log.Sugared().Warnf("invalid type of client authentication: %T", v)
		return nil, false
	}
}

// ClientRequiredAuthenticationHandler 클라이언트 인증 필수 엔드포인트s
func ClientRequiredAuthenticationHandler(c *gin.Context) {
	_, exists := c.Get(oauth2ShareKeyAuthClient)
	if !exists {
		_ = c.Error(oautherr.ErrUnauthorizedClient)
		c.Abort()
	} else {
		c.Next()
	}
}
