package service

import (
	"oauth-server-go/crypto"
	"oauth-server-go/user"
	"oauth-server-go/user/repository"
)

var accountRepo *repository.AccountRepository
var hasher crypto.Hasher

func init() {
	accountRepo = repository.NewAccountRepository()
	hasher = crypto.NewBcryptHasher()
}

type AuthService struct {
	Login func(r *LoginRequest) (*LoginDetail, error)
}

func NewAuthService() *AuthService {
	return &AuthService{Login: login}
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

func login(r *LoginRequest) (*LoginDetail, error) {
	if r.Username == "" || r.Password == "" {
		return nil, user.ErrRequireParamsMissing
	}

	account := accountRepo.FindByUsername(r.Username)
	if account == nil {
		return nil, user.ErrAccountNotFound
	}

	if cmp, err := hasher.Compare(account.Password, r.Password); err != nil {
		return nil, err
	} else if !cmp {
		return nil, user.ErrPasswordNotMatch
	} else if !account.Active {
		return nil, user.ErrAccountLocked
	}

	login := LoginDetail{Username: account.Username}
	return &login, nil
}
