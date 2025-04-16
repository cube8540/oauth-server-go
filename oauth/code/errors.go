package code

import "errors"

var (
	ErrParameterMissing = errors.New("required parameter is missing")
	ErrNotFound         = errors.New("authorization code not found")
)
