package handler

import (
	"errors"
	"github.com/gin-gonic/gin"
	"net/http"
	"net/url"
	"oauth-server-go/internal/oauth/authorization"
	oautherr "oauth-server-go/internal/oauth/errors"
	"oauth-server-go/internal/oauth/token"
)

// ErrorResponse OAuth2 에러 응답
//
// OAuth2 처리 도중 처리할 수 없거나 에러가 발생하였을 경우 사용자에게 보여줄 HTTP 응답 전문
type ErrorResponse struct {
	Code    string `json:"code"`
	Message string `json:"error_description"`
	State   string `json:"state,omitempty"`
	Uri     string `json:"error_uri,omitempty"`
}

// NewErrorResponse 인자로 받은 에러로 새 에러 응답 인스턴스를 생성한다.
func NewErrorResponse(err error) *ErrorResponse {
	var res *ErrorResponse

	var oauthError *OAuth2Error
	if errors.As(err, &oauthError) {
		res = &ErrorResponse{
			Code:    oautherr.ErrorCode(oauthError),
			Message: oauthError.Message,
		}

		if oauthError.AuthorizationRequest != nil {
			res.State = oauthError.AuthorizationRequest.State
		}
	} else {
		res = &ErrorResponse{
			Code:    oautherr.ErrCodeServerError,
			Message: "unknown error",
		}
	}
	return res
}

// QueryParamTo 주어진 주소의 쿼리 파라미터로 저장된 프로퍼티들을 설정한다.
func (m *ErrorResponse) QueryParamTo(u *url.URL) {
	q := u.Query()
	q.Set("code", m.Code)
	q.Set("error_description", m.Message)
	if m.State != "" {
		q.Set("state", m.State)
	}
	if m.Uri != "" {
		q.Set("error_uri", m.Uri)
	}
	u.RawQuery = q.Encode()
}

// OAuth2Error OAuth2 에러 객체
//
// 발생한 에러와 OAuth2 요청 정보 등에 대한 데이터를 함께 랩핑하는 구조체
type OAuth2Error struct {
	// Err 원본 에러
	Err error

	// Message 사용자에게 보여줄 메시지
	Message string

	// AuthorizationRequest 인가 요청시 사용했던 요청 전문
	AuthorizationRequest *authorization.Request

	// TokenRequest 토큰 발행 요청시 사용했던 요청 전문
	TokenRequest *token.Request

	// Redirect 요청 처리 후 호출할 콜백 URL
	Redirect *url.URL
}

func (e *OAuth2Error) Error() string {
	if e.Err != nil {
		return e.Err.Error()
	}
	return e.Message
}

func (e *OAuth2Error) Unwrap() error {
	return e.Err
}

// SetMessage 에러 메시지를 변경한다.
func (e *OAuth2Error) SetMessage(message string) {
	e.Message = message
}

// NewOAuth2Error 새 OAuth2 에러 인스턴스를 생성한다.
func NewOAuth2Error(err error, message string) *OAuth2Error {
	return &OAuth2Error{
		Err:     err,
		Message: message,
	}
}

// WrapAuthRequest 인가 처리 도중 발생한 에러를 랩핑하여 새로운 OAuth2 에러 인스턴스를 생성한다.
func WrapAuthRequest(err error, message string, request *authorization.Request, redirect *url.URL) *OAuth2Error {
	return &OAuth2Error{
		Err:                  err,
		Message:              message,
		AuthorizationRequest: request,
		Redirect:             redirect,
	}
}

// WrapTokenRequest 토큰 발급 도중 발행한 에러를 랩핑하여 새로운 OAuth2 에러 인스턴스를 생성한다.
func WrapTokenRequest(err error, message string, request *token.Request) *OAuth2Error {
	return &OAuth2Error{
		Err:          err,
		Message:      message,
		TokenRequest: request,
	}
}

// OAuth2ErrorWrappingHandler Gin 컨텍스트의 마지막 에러를 OAuth2Error 타입으로 변환한다.
func OAuth2ErrorWrappingHandler(c *gin.Context) {
	c.Next()
	if needErrorWrite(c) {
		err := c.Errors.Last()
		var oauth2Error *OAuth2Error
		if !errors.As(err, &oauth2Error) {
			oauth2Error = NewOAuth2Error(err, err.Error())
			_ = c.Error(oauth2Error)
		}
	}
}

// OAuth2ErrorHandler OAuth2 Gin 에러 헨들링 미들웨어 함수
//
// 이 함수는 Gin 컨텍스트의 마지막 에러를 확인하고 그 에러를 적절한 메시지로 변환한다.
// 만약 마지막 에러의 타입이 OAuth2Error 이고 리다이렉트할 곳이 있다면, 에러 메시지와 관련된 프로퍼티들을
// 쿼리 파라미터로 하여 지정된 콜백 주소로 리다이렉트한다.
func OAuth2ErrorHandler(c *gin.Context) {
	c.Next()
	if needErrorWrite(c) {
		err := c.Errors.Last()
		response := NewErrorResponse(err)

		var oauth2Error *OAuth2Error
		if errors.As(err, &oauth2Error) {
			if oauth2Error.Redirect != nil {
				redirect := oauth2Error.Redirect
				response.QueryParamTo(redirect)
				c.Redirect(http.StatusFound, redirect.String())
				return
			}
		}
		c.JSON(http.StatusBadRequest, response)
	}
}

// needErrorWrite 에러에 대한 응답을 응답 바디에 써야(write) 하는지 여부를 확인한다.
//
// 아래의 조건을 모두 만족할 때 true를 반환한다.
//  1. 컨텍스트에 등록된 에러가 존재한다.
//  2. 컨텍스트 응답 바디에 아직 아무런 응답도 적혀 있지 않다.
//  3. 현재 응답의 상태 코드가 200(StatusOK)이다.
func needErrorWrite(c *gin.Context) bool {
	return len(c.Errors) > 0 && !c.Writer.Written() && c.Writer.Status() == http.StatusOK
}
