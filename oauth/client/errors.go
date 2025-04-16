package client

import "errors"

var (
	// ErrInvalidRequest 잘못된 요청
	ErrInvalidRequest = errors.New("invalid request")

	// ErrAuthentication 클라이언트 인증 실패
	ErrAuthentication = errors.New("authentication")

	// ErrInvalidScope 스코프를 승인 할 수 없거나 찾을 수 없음
	ErrInvalidScope = errors.New("invalid scope")

	// ErrInvalidRedirectURI 리다이렉트 URI을 승인 할 수 없거나 잘못됨
	ErrInvalidRedirectURI = errors.New("invalid redirect uri")

	// ErrNotFound 클라이언트를 찾을 수 없음
	ErrNotFound = errors.New("client not found")
)
