package user

import "errors"

var (
	ErrRequireParamsMissing = errors.New("required parameters are missing")
	ErrAccountNotFound      = errors.New("account cannot found")
	ErrPasswordNotMatch     = errors.New("password does not match")
	ErrAccountLocked        = errors.New("account is locked")
)
