package code

import "errors"

var (
	// ErrParameterMissing 요구되는 파라미터가 없거나 찾을 수 없음
	ErrParameterMissing = errors.New("required parameter is missing")

	// ErrNotFound 인가 토큰을 찾을 수 없음
	ErrNotFound = errors.New("authorization code not found")
)
