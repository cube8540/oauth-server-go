package web

import (
	"encoding/json"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"net/http"
)

// gin 컨텍스트에 등록할 키 상수
const (
	// KeyAuthentication 인증 정보를 등록할 때 사용할 키
	KeyAuthentication = "middleware/security/Authenticate"
)

// Authentication 인증 정보
//
// 요청자의 인증 정보를 저장한다.
type Authentication struct {
	Username string
}

// Authorization 인자로 받은 컨텍스트의 세션에 인증 정보를 저장한다.
//
//	Note: 사전에 컨텍스트에 세션이 등록 되어 있어야 한다. 만약 세션이 등록 되어 있지 않은 경우 패닉이 발생하니 주의
func Authorization(c *gin.Context, auth *Authentication) error {
	session := sessions.Default(c)
	if session == nil {
		panic("session is not registered in context")
	}

	serial, err := json.Marshal(auth)
	if err != nil {
		return err
	}

	session.Set(KeyAuthentication, serial)
	return session.Save()
}

// SessionAuthenticationHandler 요청자의 인증을 처리하는 핸들러 함수
//
// 세션에 저장된 인증 정보를 얻어와 컨텍스트에 등록한다. 만약 세션에 인증 정보가 없을 경우 아무 값도 저장 되지 않는다.
//
//	Note: 사전에 컨텍스트에 세션이 등록 되어 있어야 한다. 만약 세션이 등록 되어 있지 않은 경우 패닉이 발생하니 주의
func SessionAuthenticationHandler(c *gin.Context) {
	session := sessions.Default(c)
	if session == nil {
		panic("session is not registered in context")
	}

	v := session.Get(KeyAuthentication)
	if serial, ok := v.([]byte); ok {
		var auth Authentication
		if err := json.Unmarshal(serial, &auth); err != nil {
			panic(err)
		}
		c.Set(KeyAuthentication, &auth)
	}

	c.Next()
}

// RetrieveAuthentication 컨텍스트에 등록된 인증 정보를 가져온다.
// 인증 정보가 등록 되어 있지 않거나 `web.Authentication` 타입이 아닌 경우 NIL과 false가 반환된다.
func RetrieveAuthentication(c *gin.Context) (*Authentication, bool) {
	v, exists := c.Get(KeyAuthentication)
	if !exists {
		return nil, false
	}
	auth, ok := v.(*Authentication)
	return auth, ok
}

// AccessDeniedRedirectHandler 인증 거부시 지정된 경로로 리다이렉트 하는 헨들러 함수를 생성한다.
func AccessDeniedRedirectHandler(dest string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Redirect(http.StatusFound, dest)
	}
}

// RequestProtect 인증된 사용자만 다음 프로세스를 진행 할 수 있도록 인증 검수 함수를 생성한다.
//
// gin 컨텍스트에서 인증 정보를 얻어와 인증 정보가 있을 경우 다음 프로세스를 진행한다.
// 만약 컨텍스트에 인증 정보가 없을 경우 인자로 받은 handler를 통해 요청 거부에 대한 처리를 하고 이후 컨텍스트를 종료한다.
func RequestProtect(handler gin.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		if _, exists := c.Get(KeyAuthentication); !exists {
			handler(c)
			c.Abort()
		} else {
			c.Next()
		}
	}
}
