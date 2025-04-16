package token

import "errors"

var (
	// ErrAccessTokenNotFound 엑세스 토큰을 찾을 수 없음
	ErrAccessTokenNotFound = errors.New("access token not found")

	// ErrRefreshTokenNotFound 리플레시 토큰을 찾을 수 없음
	ErrRefreshTokenNotFound = errors.New("refresh token not found")

	// ErrInvalidRequest 요청이 잘못됨
	ErrInvalidRequest = errors.New("invalid request")

	// ErrUnauthorized 토큰을 사용하거나 접근 할 수 없음
	// 토큰의 소유자가 다르거나, 토큰을 발급한 클라이언트가 아닐 경우 발생한다.
	ErrUnauthorized = errors.New("unauthorized")

	// ErrTokenCannotGrant 토큰을 부여할 수 없음
	// 특정 흐름에서 토큰을 발급 할 수 없는 문제가 발생 했을때(인가 토큰 만료, 리플레시 토큰 만료 등) 발생한다.
	ErrTokenCannotGrant = errors.New("token cannot grant")
)
