package handler

import (
	"errors"
	"github.com/gin-gonic/gin"
	"net/http"
	"oauth-server-go/internal/user/codes"
	"oauth-server-go/internal/user/service"
	"oauth-server-go/protocol"
	"oauth-server-go/security"
)

// AuthenticationManager 인증 프로세스 제공 인터페이스
type AuthenticationManager interface {

	// Auth 입력 받은 인증 요청 정보로 인증 프로세스를 실행하고 인증된 사용자 인스턴스를 생성한다.
	Auth(request *service.AuthenticationRequest) (*service.Principal, error)
}

// API 회원에 관련된 HTTP API 요청을 처리하는 함수를 모아둔 헨들러 인스턴스
type API struct {
	auth AuthenticationManager
}

// NewAPI 새 회원 HTTP API 핸들러 인스턴스를 생성한다.
func NewAPI(auth AuthenticationManager) *API {
	return &API{auth: auth}
}

// Auth 로그인 요청 HTTP 핸들러
// 사용자의 로그인 요청을 처리하고 옳바른 인증인 경우 세션에 사용자 정보를 저장한다.
func (h *API) Auth(c *gin.Context) error {
	var request service.AuthenticationRequest
	if err := c.ShouldBindBodyWithJSON(&request); err != nil {
		return wrap(err)
	}

	principal, err := h.auth.Auth(&request)
	if err != nil {
		return wrap(err)
	}

	login := &security.Login{Username: principal.Username}
	if err = security.Retrieve(c).Set(login); err != nil {
		return wrap(err)
	}

	c.JSON(http.StatusOK, protocol.NewOK(protocol.MsgOK))
	return nil
}

// Static 회원에 관련된 HTTP 정적 요청을 처리하는 함수를 모아둔 핸들러 인스턴스
type Static struct {
}

// NewStatic 새 정적 요청 핸들러 인스턴스를 생성한다.
func NewStatic() *Static {
	return &Static{}
}

// LoginPage `gin.Context`를 이용해 사용자에게 보여줄 로그인 페이지를 지정한다.
func (h *Static) LoginPage(c *gin.Context) error {
	c.HTML(http.StatusOK, "login.html", nil)
	return nil
}

// wrap 인자로 받은 err을 사전에 정의된 에러로 랩핑한다.
func wrap(err error) error {
	if errors.Is(err, codes.ErrRequireParamsMissing) {
		return protocol.Wrap(err, protocol.ErrCodeBadRequest, "require parameter is missing")
	} else if errors.Is(err, codes.ErrAccountNotFound) || errors.Is(err, codes.ErrPasswordNotMatched) {
		return protocol.Wrap(err, protocol.ErrCodeBadRequest, "id/password is not matched")
	} else if errors.Is(err, codes.ErrAccountLocked) {
		return protocol.Wrap(err, protocol.ErrCodeBadRequest, "account is locked")
	} else {
		return protocol.Wrap(err, protocol.ErrCodeUnknown, "internal server codes")
	}
}
