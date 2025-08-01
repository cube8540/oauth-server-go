package errors

import (
	"errors"
)

// OAuth2 어플리케이션에서 발생하는 에러 리스트
var (

	// ErrInvalidRequest 처리할 수 없는 요청 정보
	//
	// 주로 정의 되지 않은 파라미터나 승인 되지 않은 정보를 요구 할 떄 사용된다.
	ErrInvalidRequest = errors.New("invalid request")

	// ErrMissingParameter 필수 파리미터 누락
	ErrMissingParameter = errors.New("missing required parameter")

	// ErrUnauthorized 인가 되지 않은 요청
	//
	// 주로 잘못된 클라이언트 접근이나, 승인되지 않은 사용자 접근일때 사용한다.
	ErrUnauthorized = errors.New("unauthorized")

	// ErrUnauthorizedClient 인증되지 않은 클라이언트
	//
	// 주로 클라이언트의 인증이 필수인 API에서 인증되지 않은 클라이언트가 요청을 실행한 경우 사용한다.
	ErrUnauthorizedClient = errors.New("unauthorized client")

	// ErrInvalidScope 잘못된 스코프
	//
	// 주로 요청한 스코프를 부여할 수 없을때 사용된다.
	ErrInvalidScope = errors.New("invalid scope")

	// ErrExpiredResource 만료된 자원
	//
	// 요청한 데이터가 만료되어 사용할 수 없을때 사용한다.
	ErrExpiredResource = errors.New("expired resource")

	// ErrInvalidClient 잘못된 클라이언트
	//
	// 다음과 같은 경우 사용한다:
	//	 1. 토큰이나 인가 코드의 발행 클라이언트와 요청 클라이언트가 서로 다를 경우
	//	 2. 토큰을 발급 할 수 없는 클라이언트인 경우
	ErrInvalidClient = errors.New("invalid client")

	// ErrUnknown 알 수 없는 에러
	ErrUnknown = errors.New("unknown error")
)

// [RFC 6749] 에서 정의하는 에러 코드 리스트
//
// [RFC 6749]: https://datatracker.ietf.org/doc/html/rfc6749
const (
	// ErrCodeInvalidRequest 필수 입력 파라미터를 입력 받지 못하였거나 지원하지 않는 파라미터가 입력됨
	ErrCodeInvalidRequest = "invalid_request"

	// ErrCodeUnauthorizedClient 인증된 클라이언트에는 요청한 인가 플로우를 사용할 수 없음
	ErrCodeUnauthorizedClient = "unauthorized_client"

	// ErrCodeAccessDenied 자원 소유자 혹은 서버가 접근을 거부함
	ErrCodeAccessDenied = "access_denied"

	// ErrCodeUnsupportedResponseType 지원 하지 않는 응답 타입
	ErrCodeUnsupportedResponseType = "unsupported_response_type"

	// ErrCodeInvalidScope 요청 받은 스코프를 알 수 없거나 잘못되었거나 유효하지 않음
	ErrCodeInvalidScope = "invalid_scope"

	// ErrCodeServerError 서버에서 에러가 발생함
	ErrCodeServerError = "server_error"

	// ErrCodeTemporaryUnavailable 요청을 처리 할 수 없음
	ErrCodeTemporaryUnavailable = "temporarily_unavailable"

	// ErrCodeInvalidClient 클라이언트 인증에 실패함
	ErrCodeInvalidClient = "invalid_client"

	// ErrCodeInvalidGrant 인증이 잘못 되었거나 리플레시 토큰등이 유효 하지 않음
	ErrCodeInvalidGrant = "invalid_grant"

	// ErrCodeUnsupportedGrantType 지원하지 않은 인가 타입
	ErrCodeUnsupportedGrantType = "unsupported_grant_type"
)

// ErrorCode 인자로 받은 에러를 정의된 에러 코드로 변환한다.
func ErrorCode(err error) string {
	switch {
	case errors.Is(err, ErrInvalidRequest),
		errors.Is(err, ErrMissingParameter):
		return ErrCodeInvalidRequest
	case errors.Is(err, ErrUnauthorized),
		errors.Is(err, ErrExpiredResource):
		return ErrCodeInvalidGrant
	case errors.Is(err, ErrInvalidClient):
		return ErrCodeInvalidClient
	case errors.Is(err, ErrInvalidScope):
		return ErrCodeInvalidScope
	case errors.Is(err, ErrUnauthorizedClient):
		return ErrCodeUnauthorizedClient
	default:
		return ErrCodeServerError
	}
}
