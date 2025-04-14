package security

import (
	"github.com/gin-gonic/gin"
	"net/http"
)

// 켄텍스에서 사용할 상수 키
const (
	StoreKey          = "security/Store"
	AuthenticationKey = "security/authentication"
)

// Login 사용자 로그인 정보
type Login struct {
	Username string
}

// Store 로그인 정보를 저장과 조회를 하는 인터페이스
type Store interface {
	// Set 로그인 정보를 받아 저장한다
	Set(v *Login) error

	// Get 저장되어 있는 로그인 정보를 반환한다
	Get() (*Login, bool)
}

// AccessDeniedHandler 접근 거부 시 처리할 함수
type AccessDeniedHandler func(c *gin.Context)

// Authentication 컨텍스트에 로그인된 사용자의 정보를 저장하는 미들웨어 함수
//
//	NOTE: 로그인 정보를 가져오기 위해 컨텍스트에 저장된 스토으를 사용한다. 스토어가 컨텍스트에 저장되어 있지 않은 경우 panic이 발생함으로 주의
func Authentication(c *gin.Context) {
	storeV, exists := c.Get(StoreKey)
	if !exists {
		panic("store is not saved in context")
	}
	store, ok := storeV.(Store)
	if !ok {
		panic("store must be implemented security.Store")
	}
	login, exists := store.Get()
	if exists {
		c.Set(AuthenticationKey, login)
	}
	c.Next()
}

// Retrieve 컨텍스트에서 스토어를 꺼내 반환한다.
//
//	NOTE: 컨텍스트에 스토어가 저장되어 있지 않은 경우 panic이 발생한다.
func Retrieve(c *gin.Context) Store {
	v, exists := c.Get(StoreKey)
	if !exists {
		panic("store is not contained in context")
	}
	store, ok := v.(Store)
	if !ok {
		panic("store must be implemented security.Context")
	}
	return store
}

// Protected 컨텍스트에 로그인된 사용자 정보가 있는지 확인하고 없을 경우 입력 받은 헨들러로 처리한다.
func Protected(h AccessDeniedHandler) gin.HandlerFunc {
	return func(c *gin.Context) {
		_, exists := c.Get(AuthenticationKey)
		if exists {
			c.Next()
		} else {
			h(c)
			c.Abort()
		}
	}
}

// AccessDeniedRedirect 인증 되지 않은 요청을 to로 리다이렉트 하는 AccessDeniedHandler
func AccessDeniedRedirect(to string) AccessDeniedHandler {
	return func(c *gin.Context) {
		c.Redirect(http.StatusFound, to)
	}
}
