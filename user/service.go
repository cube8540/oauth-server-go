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
		Username string `json:"username"`
		Password string `json:"password"`
	}
)

func Login(req *LoginRequest, hasher Hasher) (*LoginModel, error) {
	account, err := FindAccountByUsername(req.Username)
	if err != nil {
		return nil, fmt.Errorf("error by repository %w", err)
	} else if account == nil {
		return nil, ErrAccountNotFound
	}

	if cmp, err := account.PasswordCompare(hasher, req.Password); err != nil {
		return nil, err
	} else if !cmp {
		return nil, ErrPasswordNotMatch
	} else if !account.active {
		return nil, ErrAccountLocked
	}

	login := LoginModel{Username: account.Username}
	return &login, nil
}
