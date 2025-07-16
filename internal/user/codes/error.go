package codes

import "errors"

var (
	// ErrRequireParamsMissing 필수 파라미터 누락
	ErrRequireParamsMissing = errors.New("required parameters are missing")

	// ErrAccountNotFound 계정을 찾을 수 없음
	ErrAccountNotFound = errors.New("account cannot found")

	// ErrPasswordNotMatched 패스워드가 일치하지 않음
	ErrPasswordNotMatched = errors.New("password does not match")

	// ErrAccountLocked 계정이 잠김 상태임
	ErrAccountLocked = errors.New("account is locked")
)
