package service

import (
	"oauth-server-go/crypto"
	"oauth-server-go/user"
	"oauth-server-go/user/repository"
)

var hasher crypto.Hasher

func init() {
	hasher = crypto.NewBcryptHasher()
}

type (
	LoginDetail struct {
		Username string `json:"username"`
	}

	LoginRequest struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
)

func Login(req *LoginRequest) (*LoginDetail, error) {
	if req.Username == "" || req.Password == "" {
		return nil, user.ErrRequireParamsMissing
	}

	account := repository.FindAccountByUsername(req.Username)
	if account == nil {
		return nil, user.ErrAccountNotFound
	}

	if cmp, err := hasher.Compare(account.Password, req.Password); err != nil {
		return nil, err
	} else if !cmp {
		return nil, user.ErrPasswordNotMatch
	} else if !account.Active {
		return nil, user.ErrAccountLocked
	}

	login := LoginDetail{Username: account.Username}
	return &login, nil
}
