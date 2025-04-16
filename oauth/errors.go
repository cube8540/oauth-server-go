package oauth

import (
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http"
	"net/url"
	"oauth-server-go/oauth/pkg"
)

// [RFC 6749] 에서 정의하는 에러 코드 리스트
//
// [RFC 6749]: https://datatracker.ietf.org/doc/html/rfc6749
const (
	// ErrInvalidRequest 필수 입력 파라미터를 입력 받지 못하였거나 지원하지 않는 파라미터가 입력됨
	ErrInvalidRequest = "invalid_request"

	// ErrUnauthorizedClient 인증된 클라이언트에는 요청한 인가 플로우를 사용할 수 없음
	ErrUnauthorizedClient = "unauthorized_client"

	// ErrAccessDenied 자원 소유자 혹은 서버가 접근을 거부함
	ErrAccessDenied = "access_denied"

	// ErrUnsupportedResponseType 지원 하지 않는 응답 타입
	ErrUnsupportedResponseType = "unsupported_response_type"

	// ErrInvalidScope 요청 받은 스코프를 알 수 없거나 잘못되었거나 유효하지 않음
	ErrInvalidScope = "invalid_scope"

	// ErrServerError 서버에서 에러가 발생함
	ErrServerError = "server_error"

	// ErrTemporaryUnavailable 요청을 처리 할 수 없음
	ErrTemporaryUnavailable = "temporarily_unavailable"

	// ErrInvalidClient 클라이언트 인증에 실패함
	ErrInvalidClient = "invalid_client"

	// ErrInvalidGrant 인증이 잘못 되었거나 리플레시 토큰등이 유효 하지 않음
	ErrInvalidGrant = "invalid_grant"

	// ErrUnsupportedGrantType 지원하지 않은 인가 타입
	ErrUnsupportedGrantType = "unsupported_grant_type"
)

var (
	ErrUnauthorized = errors.New("unauthorized")
)

type Error struct {
	Code    string
	Message string
}

func (e Error) Error() string {
	return e.Message
}

func NewErr(code, message string) error {
	return &Error{
		Code:    code,
		Message: message,
	}
}

func HttpStatus(c string) int {
	switch c {
	case ErrInvalidRequest, ErrInvalidGrant, ErrInvalidScope, ErrInvalidClient:
		return http.StatusBadRequest
	case ErrAccessDenied, ErrUnauthorizedClient:
		return http.StatusUnauthorized
	case ErrTemporaryUnavailable:
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

type requestFailed struct {
	err     error
	request *pkg.AuthorizationRequest
}

func (r *requestFailed) Error() string {
	return r.err.Error()
}

func (r *requestFailed) Unwrap() error {
	return r.err
}

func wrap(err error, r *pkg.AuthorizationRequest) error {
	return &requestFailed{
		err:     err,
		request: r,
	}
}

type routeErr struct {
	err error
	to  *url.URL
}

func (e *routeErr) Error() string {
	return e.err.Error()
}

func (e *routeErr) Unwrap() error {
	return e.err
}

func route(err error, to *url.URL) error {
	return &routeErr{
		err: err,
		to:  to,
	}
}

func routeWrap(err error, r *pkg.AuthorizationRequest, to *url.URL) error {
	return route(wrap(err, r), to)
}

func parse(err error) pkg.ErrResponse {
	var er pkg.ErrResponse

	var oauthErr *Error
	if errors.As(err, &oauthErr) {
		er = pkg.NewErrResponse(oauthErr.Code, oauthErr.Message)
	} else {
		fmt.Printf("%v", err)
		er = pkg.NewErrResponse(ErrServerError, "unknown error")
	}

	var requestErr *requestFailed
	if errors.As(err, &requestErr) {
		er.State = requestErr.request.State
	}
	return er
}

func ErrorHandleMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
		if len(c.Errors) > 0 && !c.Writer.Written() && c.Writer.Status() == http.StatusOK {
			err := c.Errors.Last()
			m := parse(err)

			var routeError *routeErr
			if errors.As(err, &routeError) {
				c.Redirect(http.StatusMovedPermanently, m.QueryParam(routeError.to).String())
			} else {
				c.JSON(HttpStatus(m.Code), m)
			}
		}
	}
}
