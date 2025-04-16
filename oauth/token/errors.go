package token

import "errors"

var (
	ErrAccessTokenNotFound  = errors.New("access token not found")
	ErrRefreshTokenNotFound = errors.New("refresh token not found")
	ErrInvalidRequest       = errors.New("invalid request")
	ErrUnauthorized         = errors.New("unauthorized")
	ErrTokenCannotGrant     = errors.New("token cannot grant")
)
