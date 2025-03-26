package user

import (
	"errors"
	"fmt"
)

var (
	ErrAccountNotFound  = errors.New("account cannot found")
	ErrPasswordNotMatch = errors.New("password does not match")
	ErrAccountLocked    = errors.New("account is locked")
)

type (
	LoginModel struct {
		Username string
	}

	LoginRequest struct {
		Username string
		Password string
	}
)

func Login(req LoginRequest, hasher Hasher) (*LoginModel, error) {
	account, err := FindAccountByUsername(req.Username)
	if err != nil {
		return nil, fmt.Errorf("error by repository %w", err)
	}
	if account == nil {
		return nil, ErrAccountNotFound
	}

	cmp, err := account.PasswordCompare(hasher, req.Password)
	if err != nil {
		return nil, err
	}
	if !cmp {
		return nil, ErrPasswordNotMatch
	}

	if !account.active {
		return nil, ErrAccountLocked
	}

	login := LoginModel{Username: account.Username}
	return &login, nil
}
