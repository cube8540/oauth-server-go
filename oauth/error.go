package oauth

import (
	"errors"
	"net/http"
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

// 어플리케이션 API에서 사용할 에러 리스트
var (
	// ErrTokenNotFound 요청한 토큰을 찾을 수 없음
	ErrTokenNotFound = errors.New("token not found")

	// ErrClientNotFound 요청한 클라이언트를 찾을 수 없음
	ErrClientNotFound = errors.New("client not found")

	// ErrAuthorizationCodeNotFound 요청한 인가 코드를 찾을 수 없음
	ErrAuthorizationCodeNotFound = errors.New("authorization code is not found")
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
